// Temporarily deactivated warnings, remove after implementation is complete.
#![allow(warnings)]

use bytes::ToPretty;
//use hbbft::honey_badger::{self, MessageContent};
use hbbft::honey_badger::{self};
use parking_lot::RwLock;
use stats::PrometheusMetrics;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

// use threshold_crypto::{SignatureShare};
use crate::engines::hbbft::{NodeId, sealing};
// use hbbft::honey_badger::Message;
// use serde::{Deserialize, Serialize};
// use serde_json::{json, Result, Value};

use std::{
    fs::{self, File, create_dir_all},
    io::Write,
    path::PathBuf,
};

pub type HbMessage = honey_badger::Message<NodeId>;

/**
Hbbft Message Process
// Broadcast - Echo
// Broadcast - Value
// Agreement
// Decryption Share
// Broadcast - CanDecode
// Subset - Message (proposer)
// Broadcast - Ready
// SignatureShare
//
//
*/

pub(crate) enum SealMessageState {
    Good,
    Late(u64),
    Error(Box<sealing::Message>),
}
/// holds up the history of a node for a staking epoch history.
#[derive(Debug)]
pub(crate) struct NodeStakingEpochHistory {
    node_id: NodeId,
    last_good_sealing_message: u64,
    last_good_sealing_message_time: Instant,
    last_late_sealing_message: u64,
    last_late_sealing_message_time: Instant,
    last_error_sealing_message: u64,
    last_error_sealing_message_time: Instant,
    // summed up lateness of all seals, including bad seals.
    cumulative_lateness: u64,

    sealing_blocks_good: Vec<u64>,
    sealing_blocks_late: Vec<u64>,
    sealing_blocks_bad: Vec<u64>,
    // messages.
    last_message_faulty: u64,
    last_message_good: u64,
    last_message_good_time: Instant,

    num_faulty_messages: u64,
    num_good_messages: u64, // total_contributions_good: u64,
                            // total_contributions_bad: u64,
}

impl NodeStakingEpochHistory {
    pub fn new(node_id: NodeId) -> Self {
        let now = Instant::now();
        NodeStakingEpochHistory {
            node_id,
            last_good_sealing_message: 0,
            last_good_sealing_message_time: now,
            last_late_sealing_message: 0,
            last_late_sealing_message_time: now,
            last_error_sealing_message: 0,
            last_error_sealing_message_time: now,
            cumulative_lateness: 0,
            sealing_blocks_good: Vec::new(),
            sealing_blocks_late: Vec::new(),
            sealing_blocks_bad: Vec::new(),
            last_message_faulty: 0,
            last_message_good: 0,
            last_message_good_time: now,
            num_faulty_messages: 0,
            num_good_messages: 0,
        }
    }

    /// calculates the cumulative lateness for that communication partner,
    /// based on existing data, detecting blocks with missing late or good seals
    fn calc_cumulative_lateness_gap(
        &self,
        block_num: u64,
        staking_epoch_start_block_num: u64,
    ) -> u64 {
        if block_num <= 1 {
            return 0;
        }

        // add cumulative lateness, for all blocks between the last tracked block
        // and the current block.
        if self.last_late_sealing_message + 1 < block_num
            || self.last_good_sealing_message + 1 < block_num
            || self.last_error_sealing_message + 1 < block_num
        {
            let latest_message = u64::max(
                u64::max(
                    u64::max(
                        self.last_late_sealing_message,
                        staking_epoch_start_block_num,
                    ),
                    self.last_good_sealing_message,
                ),
                self.last_error_sealing_message,
            );

            if (latest_message + 1) > block_num {
                return 0;
            }

            let difference = block_num - 1 - latest_message;

            return (difference * (difference + 1)) / 2;
        }
        return 0;
    }

    /// protocols a good seal event.
    pub fn add_good_seal_event(
        &mut self,
        event: &SealEventGood,
        staking_epoch_start_block_num: u64,
    ) {
        // by definition a "good sealing" is always on the latest block.
        let block_num = event.block_num;
        let last_good_sealing_message = self.last_good_sealing_message;

        if block_num < last_good_sealing_message {
            warn!(target: "hbbft_message_memorium", "add_good_seal_event: event.block_num {block_num} <= self.last_good_sealing_message {last_good_sealing_message}");
            return;
        }

        self.cumulative_lateness +=
            self.calc_cumulative_lateness_gap(event.block_num, staking_epoch_start_block_num);
        self.last_good_sealing_message = event.block_num;
        self.last_good_sealing_message_time = Instant::now();
        self.sealing_blocks_good.push(event.block_num);
    }

    /// protocols a good seal event.
    pub fn add_seal_event_late(&mut self, event: &SealEventLate, staking_epoch_start_block: u64) {
        // by definition a "good sealing" is always on the latest block.
        let block_num = event.block_num;

        if block_num < self.last_late_sealing_message {
            warn!(target: "hbbft_message_memorium", "out of order seal events: add_late_seal_event: event.block_num {block_num} <= self.last_late_sealing_message {}", self.last_late_sealing_message);
            return;
        }

        self.cumulative_lateness +=
            self.calc_cumulative_lateness_gap(event.block_num, staking_epoch_start_block);

        self.last_late_sealing_message = event.block_num;
        self.last_late_sealing_message_time = Instant::now();
        self.cumulative_lateness += event.get_lateness();
        self.sealing_blocks_late.push(event.block_num);
    }

    pub(crate) fn add_bad_seal_event(
        &mut self,
        event: &SealEventBad,
        staking_epoch_start_block_num: u64,
    ) {
        // by definition a "good sealing" is always on the latest block.

        let block_num = event.block_num;
        let last_bad_sealing_message = self.last_error_sealing_message;

        if block_num < last_bad_sealing_message {
            warn!(target: "hbbft_message_memorium", "add_bad_seal_event: event.block_num {block_num} <= self.last_bad_sealing_message {last_bad_sealing_message}");
            return;
        }

        self.cumulative_lateness +=
            self.calc_cumulative_lateness_gap(block_num, staking_epoch_start_block_num);
        self.cumulative_lateness += 1;
        self.last_error_sealing_message = event.block_num;
        self.last_error_sealing_message_time = Instant::now();
        self.sealing_blocks_good.push(event.block_num);
    }

    pub(crate) fn add_message_event_faulty(&mut self, event: &MessageEventFaulty) {
        // todo: add to faulty message history
        let block_num = event.block_num;
        let last_message_faulty = self.last_message_faulty;

        if block_num > last_message_faulty {
            self.last_message_faulty = block_num;
        } // else {
        // this log entry is trigering often, probably there are more than 1 good messages able per block.// this log entry is trigering often, probably there are more than 1 good messages able per block.
        // warn!(target: "hbbft_message_memorium", "add_message_event_faulty: event.block_num {block_num} <= last_message_faulty {last_message_faulty}");
        // }
        self.num_faulty_messages += 1;
    }

    pub(crate) fn add_message_event_good(&mut self, event: &MessageEventGood) {
        // todo: add to faulty message history
        let block_num = event.block_num;
        let last_message_good = self.last_message_good;

        if block_num > last_message_good {
            self.last_message_good = block_num;
        } // else {
        // this log entry is trigering often, probably there are more than 1 good messages able per block.
        // warn!(target: "hbbft_message_memorium", "add_message_event_good: ! event.block_num {block_num} > last_message_good {last_message_good}");
        // }
        self.num_good_messages += 1;
        self.last_message_good_time = Instant::now();
    }

    /// GETTERS

    pub fn get_total_good_sealing_messages(&self) -> usize {
        self.sealing_blocks_good.len()
    }

    pub fn get_total_late_sealing_messages(&self) -> usize {
        self.sealing_blocks_late.len()
    }

    pub fn get_total_error_sealing_messages(&self) -> usize {
        self.sealing_blocks_bad.len()
    }

    pub fn get_total_sealing_messages(&self) -> usize {
        self.get_total_good_sealing_messages()
            + self.get_total_late_sealing_messages()
            + self.get_total_error_sealing_messages()
    }

    pub fn get_last_sealing_message(&self) -> u64 {
        u64::max(
            self.last_late_sealing_message,
            self.last_good_sealing_message,
        )
    }

    pub fn get_last_sealing_message_time(&self) -> Instant {
        Instant::max(
            self.last_late_sealing_message_time,
            self.last_good_sealing_message_time,
        )
    }

    pub fn get_last_good_message_time(&self) -> Instant {
        self.last_message_good_time
    }

    pub fn get_last_late_sealing_message(&self) -> u64 {
        self.last_late_sealing_message
    }

    pub fn get_last_good_sealing_message(&self) -> u64 {
        self.last_good_sealing_message
    }

    pub fn get_node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn get_epoch_stats_csv_header() -> String {
        return "\"staking_epoch\",\"node_id\",\"total_sealing_messages\",\"total_good_sealing_messages\",\"total_late_sealing_messages\",\"total_error_sealing_messages\",\"last_good_sealing_message\",\"last_late_sealing_message\",\"last_error_sealing_message\",\"cumulative_lateness\",\"total_good_messages\",\"total_faulty_messages\",\"last_message_good\",\"last_message_faulty\"".to_string();
    }

    pub fn as_csv_lines(&self, staking_epoch: u64) -> String {
        let node_id = self.node_id.0;
        let total_good_sealing_messages = self.get_total_good_sealing_messages();
        let total_late_sealing_messages = self.get_total_late_sealing_messages();
        let total_error_sealing_messages = self.get_total_error_sealing_messages();
        let total_sealing_messages = self.get_total_sealing_messages();

        let last_good_sealing_message = self.get_last_good_sealing_message();

        let last_error_sealing_message = self.last_late_sealing_message;
        let last_late_sealing_message = self.last_error_sealing_message;
        let cumulative_lateness = self.cumulative_lateness;
        // totals messages
        let total_good_messages = self.num_good_messages;
        let total_faulty_messages = self.num_faulty_messages;
        let last_message_good = self.last_message_good;
        // faulty messages
        let last_message_faulty = self.last_message_faulty;

        return format!(
            "{staking_epoch},{node_id},{total_sealing_messages},{total_good_sealing_messages},{total_late_sealing_messages},{total_error_sealing_messages},{last_good_sealing_message},{last_late_sealing_message},{last_error_sealing_message},{cumulative_lateness},{total_good_messages},{total_faulty_messages},{last_message_good},{last_message_faulty}\n"
        );
    }

    // prometheus metrics

    fn prometheus_metrics(
        &self,
        r: &mut stats::PrometheusRegistry,
        known_highest_block: u64,
        epoch_start_block: u64,
    ) {
        // one problem that occurs here is that we have a dynamic name of the gauges.
        // that could lead to troubles later in the UI, because we would have to adapt the UI to the dynamic names.
        // a solution could be to give every node a number from 0 to n (n=25 for DMD), and supply the name as a text value,
        // so we still can figure out the node id, but the name of the gauge keeps static.

        //let metric: Metric = Metric::new();
        //r.registry().register(c)

        //let node_id = self.get_node_id().0 .0;

        let other_node = self.get_node_id().as_8_byte_string();

        //r.register_gauge_with_label(name, help, label, value)
        r.register_gauge_with_other_node_label(
            "cumulative_lateness_raw",
            "cumulative lateness, raw value without lateness from missing seals",
            other_node.as_str(),
            self.cumulative_lateness as i64,
        );

        // if the node has not send an sealing message,
        // it's cumulative lateness is not tracked.

        // we begin counting from the first block of the epoch.
        let last_good_sealing_message = u64::max(self.last_good_sealing_message, epoch_start_block);

        let non_tracked_cumulative_lateness =
            self.calc_cumulative_lateness_gap(known_highest_block, epoch_start_block);

        r.register_gauge_with_other_node_label(
            "cumulative_lateness",
            "cumulative lateness, including missing seals from that node.",
            other_node.as_str(),
            (self.cumulative_lateness + non_tracked_cumulative_lateness) as i64,
        );

        r.register_gauge_with_other_node_label(
            "sealing_blocks_good",
            "good sealed block messages",
            other_node.as_str(),
            self.sealing_blocks_good.len() as i64,
        );

        r.register_gauge_with_other_node_label(
            "sealing_blocks_late",
            "late sealed blocks",
            other_node.as_str(),
            self.sealing_blocks_late.len() as i64,
        );

        r.register_gauge_with_other_node_label(
            "sealing_blocks_bad",
            "bad block seals",
            other_node.as_str(),
            self.sealing_blocks_bad.len() as i64,
        );

        // last_good_sealing_message: u64,
        // last_late_sealing_message: u64,
        // last_error_sealing_message: u64,

        if self.last_good_sealing_message > 0 {
            r.register_gauge_with_other_node_label(
                "last_good_sealing_message",
                "block number",
                other_node.as_str(),
                self.last_good_sealing_message as i64,
            );
        }

        if self.last_late_sealing_message > 0 {
            r.register_gauge_with_other_node_label(
                "last_late_sealing_message",
                "block number",
                other_node.as_str(),
                self.last_late_sealing_message as i64,
            );
        }

        if self.last_error_sealing_message > 0 {
            r.register_gauge_with_other_node_label(
                "last_error_sealing_message",
                "block number",
                other_node.as_str(),
                self.last_error_sealing_message as i64,
            );
        }

        // last_message_faulty: u64,
        // last_message_good: u64,

        // num_faulty_messages: u64,
        // num_good_messages: u64,

        if self.last_message_good > 0 {
            r.register_gauge_with_other_node_label(
                "last_message_good",
                "block number",
                other_node.as_str(),
                self.last_message_good as i64,
            );
        }

        if self.last_message_faulty > 0 {
            r.register_gauge_with_other_node_label(
                "last_message_faulty",
                "block number",
                other_node.as_str(),
                self.last_message_faulty as i64,
            );
        }
    }
}

/// holds up the history of all nodes for a staking epoch history.
#[derive(Debug)]
pub(crate) struct StakingEpochHistory {
    staking_epoch: u64,
    staking_epoch_start_block: u64,
    staking_epoch_end_block: u64,

    /// highest block number that was processed for this epoch.
    /// used to calculate the real lateness of Nodes.
    highest_block_num: u64,

    // stored the node staking epoch history.
    // since 25 is the exected maximum, a Vec has about the same perforamnce than a HashMap.
    node_staking_epoch_histories: Vec<NodeStakingEpochHistory>,
    // does this epoch have been exported already with this data ?
    exported: bool,
}

impl StakingEpochHistory {
    fn new(
        staking_epoch: u64,
        staking_epoch_start_block: u64,
        staking_epoch_end_block: u64,
    ) -> Self {
        StakingEpochHistory {
            staking_epoch,
            staking_epoch_start_block,
            staking_epoch_end_block,
            highest_block_num: staking_epoch_start_block,
            node_staking_epoch_histories: Vec::new(),
            exported: false,
        }
    }

    pub fn get_history_for_node(&self, node_id: &NodeId) -> Option<&NodeStakingEpochHistory> {
        let index_result = self
            .node_staking_epoch_histories
            .iter()
            .position(|x| &x.get_node_id() == node_id);

        match index_result {
            Some(index) => {
                return Some(&self.node_staking_epoch_histories[index]);
            }
            None => {
                return None;
            }
        };
    }

    pub fn ensure_history_for_node(&mut self, node_id: &NodeId) -> &mut NodeStakingEpochHistory {
        let index_result = self
            .node_staking_epoch_histories
            .iter_mut()
            .position(|x| &x.get_node_id() == node_id);

        match index_result {
            Some(index) => {
                return &mut self.node_staking_epoch_histories[index];
            }
            None => {
                self.node_staking_epoch_histories
                    .push(NodeStakingEpochHistory::new(node_id.clone()));
                return self.node_staking_epoch_histories.last_mut().unwrap();
            }
        };
    }

    pub fn on_seal_good(&mut self, event: &SealEventGood) {
        let staking_epoch_start_block = self.staking_epoch_start_block;
        if event.block_num > self.highest_block_num {
            self.highest_block_num = event.block_num;
        }
        let node_staking_epoch_history = self.ensure_history_for_node(&event.node_id);
        node_staking_epoch_history.add_good_seal_event(event, staking_epoch_start_block);
        self.exported = false;
    }

    pub fn on_seal_late(&mut self, event: &SealEventLate) {
        let staking_epoch_start_block = self.staking_epoch_start_block;
        let node_staking_epoch_history = self.ensure_history_for_node(&event.node_id);
        node_staking_epoch_history.add_seal_event_late(event, staking_epoch_start_block);
        self.exported = false;
    }

    pub fn on_seal_bad(&mut self, event: &SealEventBad) {
        let staking_epoch_start_block = self.staking_epoch_start_block;
        let node_staking_epoch_history = self.ensure_history_for_node(&event.node_id);
        node_staking_epoch_history.add_bad_seal_event(event, staking_epoch_start_block);
        self.exported = false;
    }

    pub fn on_message_faulty(&mut self, event: &MessageEventFaulty) {
        let node_staking_epoch_history = self.ensure_history_for_node(&event.node_id);
        node_staking_epoch_history.add_message_event_faulty(event);
        self.exported = false;
    }

    pub fn on_message_good(&mut self, event: &MessageEventGood) {
        let node_staking_epoch_history = self.ensure_history_for_node(&event.node_id);
        node_staking_epoch_history.add_message_event_good(event);
        self.exported = false;
    }

    pub fn get_epoch_stats_as_csv(&self) -> String {
        let mut result = String::with_capacity(1024);
        result.push_str(NodeStakingEpochHistory::get_epoch_stats_csv_header().as_str());
        result.push_str("\n");
        for history in self.node_staking_epoch_histories.iter() {
            result.push_str(history.as_csv_lines(self.staking_epoch).as_str());
        }

        return result;
    }
}

pub(crate) struct HbbftMessageDispatcher {
    num_blocks_to_keep_on_disk: u64,
    thread: Option<std::thread::JoinHandle<Self>>,
    memorial: std::sync::Arc<RwLock<HbbftMessageMemorium>>,
}

#[derive(Debug, Clone)]
pub struct SealEventGood {
    node_id: NodeId,
    block_num: u64,
}

#[derive(Debug, Clone)]
pub struct SealEventBad {
    node_id: NodeId,
    block_num: u64,
    reason: BadSealReason,
}

#[derive(Debug, Clone)]
pub struct SealEventLate {
    node_id: NodeId,
    block_num: u64,
    received_block_num: u64,
}

impl SealEventLate {
    // get's the block lateness in blocks.
    pub fn get_lateness(&self) -> u64 {
        (self.received_block_num - self.block_num) + 1
    }
}

#[derive(Debug, Clone)]
pub struct MessageEventFaulty {
    node_id: NodeId,
    block_num: u64,
    fault_kind: Option<honey_badger::FaultKind>,
}

#[derive(Debug, Clone)]
pub struct MessageEventGood {
    node_id: NodeId,
    block_num: u64,
}

struct StakingEpochRange {
    staking_epoch: u64,
    start_block: u64,
    end_block: u64,
}

#[derive(Debug, Clone)]
pub enum BadSealReason {
    ErrorTresholdSignStep,
    MismatchedNetworkInfo,
}

impl HbbftMessageDispatcher {
    pub fn new(
        num_blocks_to_keep_on_disk: u64,
        block_to_keep_directory: String,
        validator_stats_directory: String,
    ) -> Self {
        let mut result = HbbftMessageDispatcher {
            num_blocks_to_keep_on_disk,
            thread: None,
            memorial: std::sync::Arc::new(RwLock::new(HbbftMessageMemorium::new(
                num_blocks_to_keep_on_disk,
                validator_stats_directory,
                block_to_keep_directory,
            ))),
        };

        result.ensure_worker_thread();
        return result;
    }

    pub fn on_sealing_message_received(&self, message: &sealing::Message, epoch: u64) {
        if self.num_blocks_to_keep_on_disk > 0 {
            self.memorial
                .write()
                .dispatched_seals
                .push_back((message.clone(), epoch));
        }
    }

    pub fn on_message_received(&self, message: &HbMessage) {
        if self.num_blocks_to_keep_on_disk > 0 {
            self.memorial
                .write()
                .dispatched_messages
                .push_back(message.clone());
        }
    }

    fn ensure_worker_thread(&mut self) {
        if self.thread.is_none() {
            // let mut memo = self;
            // let mut arc = std::sync::Arc::new(&self);
            let arc_clone = self.memorial.clone();

            let builder = std::thread::Builder::new().name("MessageMemorial".to_string());

            match builder.spawn(move || {
                loop {
                    // one loop cycle is very fast.
                    // so report_ function have their chance to aquire a write lock soon.
                    // and don't block the work thread for too long.
                    let work_result = arc_clone.write().work_message();
                    if !work_result {
                        std::thread::sleep(std::time::Duration::from_millis(5000));
                    }
                }
            }) {
                Ok(thread) => {
                    self.thread = Some(thread);
                }
                Err(err) => {
                    error!("Failed to start message memorial worker thread: {}", err);
                }
            }
        }
    }

    pub(super) fn report_seal_good(&self, node_id: &NodeId, block_num: u64) {
        let event = SealEventGood {
            node_id: node_id.clone(),
            block_num,
        };
        // self.seal_events_good.push(goodEvent);
        self.memorial
            .write()
            .dispatched_seal_event_good
            .push_back(event);
    }

    pub(super) fn report_seal_bad(&self, node_id: &NodeId, block_num: u64, reason: BadSealReason) {
        let event = SealEventBad {
            node_id: node_id.clone(),
            block_num,
            reason,
        };
        // self.seal_events_bad.push(badEvent);

        // self.seal_events_good.push(goodEvent);
        self.memorial
            .write()
            .dispatched_seal_event_bad
            .push_back(event);
    }

    pub(super) fn report_seal_late(&self, node_id: &NodeId, block_num: u64, current_block: u64) {
        let event = SealEventLate {
            node_id: node_id.clone(),
            block_num,
            received_block_num: current_block,
        };

        self.memorial
            .write()
            .dispatched_seal_event_late
            .push_back(event);
    }

    pub(crate) fn report_message_faulty(
        &self,
        node_id: &NodeId,
        block_num: u64,
        fault_kind: Option<honey_badger::FaultKind>,
    ) {
        let event = MessageEventFaulty {
            node_id: node_id.clone(),
            block_num,
            fault_kind,
        };

        self.memorial
            .write()
            .dispatched_message_event_faulty
            .push_back(event);
    }

    pub(crate) fn report_message_good(&self, node_id: &NodeId, block_num: u64) {
        let event = MessageEventGood {
            node_id: node_id.clone(),
            block_num,
        };

        self.memorial
            .write()
            .dispatched_message_event_good
            .push_back(event);
    }

    pub fn free_memory(&self, _current_block: u64) {
        // TODO: make memorium freeing memory of ancient block.
    }

    pub fn report_new_epoch(&self, staking_epoch: u64, staking_epoch_start_block: u64) {
        // we write this sync so it get's written as fast as possible.
        self.memorial
            .write()
            .report_new_epoch(staking_epoch, staking_epoch_start_block);
    }

    pub fn get_memorium(&self) -> &std::sync::Arc<RwLock<HbbftMessageMemorium>> {
        return &self.memorial;
    }
}

pub(crate) struct HbbftMessageMemorium {
    // future_messages_cache: BTreeMap<u64, Vec<(NodeId, HbMessage)>>,
    // signature_shares: BTreeMap<u64, Vec<(NodeId, HbMessage)>>,

    // decryption_shares: BTreeMap<u64, Vec<(NodeId, HbMessage)>>,
    //*
    // u64: epoch
    // NodeId: proposer
    // NodeId: node
    // HbMessage: message
    // */
    // agreements: BTreeMap<u64, Vec<(NodeId, NodeId, HbMessage)>>,
    message_tracking_id: u64,
    /// how many bad message should we keep on disk ?
    config_bad_message_evidence_reporting: u64,
    config_blocks_to_keep_on_disk: u64,
    config_block_to_keep_directory: String,
    config_validator_stats_write_interval: u32,
    config_validator_stats_directory: String,
    last_block_deleted_from_disk: u64,
    dispatched_messages: VecDeque<HbMessage>,
    dispatched_seals: VecDeque<(sealing::Message, u64)>,
    dispatched_seal_event_good: VecDeque<SealEventGood>,
    dispatched_seal_event_bad: VecDeque<SealEventBad>,
    dispatched_seal_event_late: VecDeque<SealEventLate>,
    dispatched_message_event_faulty: VecDeque<MessageEventFaulty>,
    dispatched_message_event_good: VecDeque<MessageEventGood>,
    // stores the history for staking epochs.
    // this should be only a hand full of epochs.
    // since old ones are not needed anymore.
    // they are stored as a VecDeque, in the assumption that
    // we never have to add an epoch in the middle.
    staking_epoch_history: VecDeque<StakingEpochHistory>,
    // timestamp when the last stat report for hbbft node health was written.
    timestamp_last_validator_stats_written: u64,
    // interval in seconds how often we write the hbbft node health report.
    /// latest known stacking epoch number
    latest_epoch: u64,

    /// start block of latest known epoch start.
    latest_epoch_start_block: u64,
}

impl HbbftMessageMemorium {
    pub fn new(
        config_blocks_to_keep_on_disk: u64,
        config_validator_stats_directory: String,
        block_to_keep_directory: String, /* seal_event_good_receiver: Receiver<SealEventGood>, seal_event_bad_receiver: Receiver<SealEventBad>,  */
    ) -> Self {
        HbbftMessageMemorium {
            // signature_shares: BTreeMap::new(),
            // decryption_shares: BTreeMap::new(),
            // agreements: BTreeMap::new(),
            message_tracking_id: 0,
            config_bad_message_evidence_reporting: 0,
            config_blocks_to_keep_on_disk: config_blocks_to_keep_on_disk,
            config_block_to_keep_directory: block_to_keep_directory,
            config_validator_stats_write_interval: 5,
            config_validator_stats_directory,
            last_block_deleted_from_disk: 0,
            dispatched_messages: VecDeque::new(),
            dispatched_seals: VecDeque::new(),
            dispatched_seal_event_good: VecDeque::new(),
            dispatched_seal_event_bad: VecDeque::new(),
            dispatched_seal_event_late: VecDeque::new(),
            dispatched_message_event_faulty: VecDeque::new(),
            dispatched_message_event_good: VecDeque::new(),
            staking_epoch_history: VecDeque::new(),
            timestamp_last_validator_stats_written: 0,
            latest_epoch: 0,
            latest_epoch_start_block: 0,
        }
    }

    fn get_path_to_write(&self, epoch: u64) -> PathBuf {
        return PathBuf::from(format!("{}{}", self.config_block_to_keep_directory, epoch));
    }

    fn on_message_string_received(&mut self, message_json: String, epoch: u64) {
        self.message_tracking_id += 1;

        //don't pick up messages if we do not keep any.
        // and don't pick up old delayed messages for blocks already
        // decided to not to keep.
        if self.config_blocks_to_keep_on_disk > 0 && epoch > self.last_block_deleted_from_disk {
            let mut path_buf = self.get_path_to_write(epoch);
            if let Err(e) = create_dir_all(path_buf.as_path()) {
                warn!(target: "hbbft_message_memorium", "Error creating key directory: {:?}", e);
                return;
            };

            path_buf.push(format!("{}.json", self.message_tracking_id));
            let path = path_buf.as_path();
            let mut file = match File::create(&path) {
                Ok(file) => file,
                Err(e) => {
                    warn!(target: "hbbft_message_memorium", "Error creating hbbft memorial file: {:?}", e);
                    return;
                }
            };

            if let Err(e) = file.write(message_json.as_bytes()) {
                warn!(target: "hbbft_message_memorium", "Error writing hbbft memorial file: {:?}", e);
            }

            //figure out if we have to delete a old block
            // 1. protect against integer underflow.
            // 2. block is so new, that we have to trigger a cleanup
            if epoch > self.config_blocks_to_keep_on_disk
                && epoch > self.last_block_deleted_from_disk + self.config_blocks_to_keep_on_disk
            {
                let paths = fs::read_dir("data/messages/").unwrap();

                for dir_entry_result in paths {
                    //println!("Name: {}", path.unwrap().path().display())

                    match dir_entry_result {
                        Ok(dir_entry) => {
                            let path_buf = dir_entry.path();

                            if path_buf.is_dir() {
                                let dir_name = path_buf.file_name().unwrap().to_str().unwrap();

                                match dir_name.parse::<u64>() {
                                    Ok(dir_epoch) => {
                                        if dir_epoch <= epoch - self.config_blocks_to_keep_on_disk {
                                            match fs::remove_dir_all(path_buf.clone()) {
                                                Ok(_) => {
                                                    debug!(target: "hbbft_message_memorium", "deleted old message directory: {:?}", path_buf);
                                                }
                                                Err(e) => {
                                                    warn!(target: "hbbft_message_memorium", "could not delete old directories reason: {:?}", e);
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                        Err(_) => {}
                    }
                    self.last_block_deleted_from_disk = epoch;
                }
            }
        }
    }

    // process a good seal message in to the history.
    fn on_seal_good(&mut self, seal: &SealEventGood) -> bool {
        debug!(target: "hbbft_message_memorium", "working on  good seal!: {:?}", seal);
        let block_num = seal.block_num;
        if let Some(epoch_history) = self.get_staking_epoch_history_mut(block_num) {
            epoch_history.on_seal_good(seal);
            return true;
        } else {
            return self.event_handle_history_not_set_up(seal.block_num);
        }
    }

    fn event_handle_history_not_set_up(&self, block_num: u64) -> bool {
        if block_num > self.latest_epoch_start_block {
            if self.latest_epoch_start_block == 0 {
                warn!(target: "hbbft_message_memorium", "latest_epoch_start_block not set up yet.");
            }
            // this can happen if a epoch switch is not processed yet, but messages are already incomming.
            info!(target: "hbbft_message_memorium", "Staking Epoch History not set up for block: {}", block_num);
            return false;
        } else {
            // return true to indicate that we do not want this message to get processed anymore.
            // this is just an old seal message from an epoch before.
            return true;
        }
    }

    // process a late seal message in to the history.
    fn on_seal_late(&mut self, seal: &SealEventLate) -> bool {
        debug!(target: "hbbft_message_memorium", "working on  good seal!: {:?}", seal);
        let block_num = seal.block_num;
        if let Some(epoch_history) = self.get_staking_epoch_history_mut(block_num) {
            epoch_history.on_seal_late(seal);
            return true;
        } else {
            return self.event_handle_history_not_set_up(seal.block_num);
        }
    }

    fn on_seal_bad(&mut self, seal: &SealEventBad) -> bool {
        debug!(target: "hbbft_message_memorium", "working on  good seal!: {:?}", seal);
        let block_num = seal.block_num;
        if let Some(epoch_history) = self.get_staking_epoch_history_mut(block_num) {
            epoch_history.on_seal_bad(seal);
            return true;
        } else {
            return self.event_handle_history_not_set_up(seal.block_num);
        }
    }

    fn on_message_faulty(&mut self, event: &MessageEventFaulty) -> bool {
        debug!(target: "hbbft_message_memorium", "working on faulty message event!: {:?}", event);
        let block_num = event.block_num;
        if let Some(epoch_history) = self.get_staking_epoch_history_mut(block_num) {
            epoch_history.on_message_faulty(event);
            return true;
        } else {
            return self.event_handle_history_not_set_up(event.block_num);
        }
    }

    fn on_message_good(&mut self, event: &MessageEventGood) -> bool {
        debug!(target: "hbbft_message_memorium", "working on good message event!: {:?}", event);
        if let Some(epoch_history) = self.get_staking_epoch_history_mut(event.block_num) {
            epoch_history.on_message_good(event);
            return true;
        } else {
            return self.event_handle_history_not_set_up(event.block_num);
        }
    }

    pub fn get_validator_data(
        &self,
        block_num: u64,
        node_id: &NodeId,
    ) -> Option<&Vec<NodeStakingEpochHistory>> {
        if let Some(epoch_history) = self.get_staking_epoch_history(block_num) {
            return Some(&epoch_history.node_staking_epoch_histories);
        }
        None
    }

    // report that hbbft has switched to a new staking epoch
    pub fn report_new_epoch(&mut self, staking_epoch: u64, staking_epoch_start_block: u64) {
        debug!(target: "hbbft_message_memorium", "report new epoch: {}", staking_epoch);
        self.latest_epoch = staking_epoch;
        self.latest_epoch_start_block = staking_epoch_start_block;
        if let Ok(epoch_history_index) = self
            .staking_epoch_history
            .binary_search_by_key(&staking_epoch, |x| x.staking_epoch)
        {
            self.staking_epoch_history[epoch_history_index].staking_epoch_start_block =
                staking_epoch_start_block;
        } else {
            debug!(target: "hbbft_message_memorium", "New staking epoch reported : {staking_epoch}");

            // it might be possible that some messages already arrived in the old staking epoch.
            // how to handle that ?
            // maybe hbbft_message_memorium should be paused until fully synced ?
            // and messages should always be handled with a large delay ?!
            // or
            // we do not process messages from the future,
            // "the future" is defined by the latest imported block + 1 (one) - so we always can get statistics on the current
            // block that is currently being imported.

            // if we have already a staking epoch stored, we can write the end block of the previous staking epoch.
            if let Some(previous) = self.staking_epoch_history.back_mut() {
                previous.staking_epoch_end_block = staking_epoch_start_block - 1;
            }

            self.staking_epoch_history
                .push_back(StakingEpochHistory::new(
                    staking_epoch,
                    staking_epoch_start_block,
                    0,
                ));
        }
    }

    pub fn get_staking_epoch_history(&self, block_num: u64) -> Option<&StakingEpochHistory> {
        //let histories = &mut self.staking_epoch_history;

        // self.staking_epoch_history.get_mut(index)
        for i in 0..self.staking_epoch_history.len() {
            let e = &self.staking_epoch_history[i];
            if block_num >= e.staking_epoch_start_block
                && (e.staking_epoch_end_block == 0 || block_num <= e.staking_epoch_end_block)
            {
                return Some(&self.staking_epoch_history[i]);
            }
        }

        None
    }

    fn get_staking_epoch_history_mut(
        &mut self,
        block_num: u64,
    ) -> Option<&mut StakingEpochHistory> {
        //let histories = &mut self.staking_epoch_history;

        // self.staking_epoch_history.get_mut(index)
        for i in 0..self.staking_epoch_history.len() {
            let e = &self.staking_epoch_history[i];
            if block_num >= e.staking_epoch_start_block
                && (e.staking_epoch_end_block == 0 || block_num <= e.staking_epoch_end_block)
            {
                return Some(&mut self.staking_epoch_history[i]);
            }
        }

        // if we have not found a staking epoch, we add it if possible.
        // this can happen during timings, where new messages get's process,
        // but a block import did not happen yet, and the report_new_epoch function was called.

        // this is the case for example after booting up the node.
        // per definition there must always be a staking epoch history, with an open staking_epoch_end_block.
        // but in this case, we can not know the epoch start block.

        // we know abolutly nothing about the history, not even the start block of the staking epoch, or even it's number.
        // we mark this StakingEpochHistory as incomplete.

        // i think this should only be possible if we have no staking epoch history at all.
        //debug_assert!(self.staking_epoch_history.len() == 0);

        //let new_staking_epoch_history = StakingEpochHistory::new(0, 0, 0);

        //self.staking_epoch_history.push_front(new_staking_epoch_history);
        // return self.staking_epoch_history.front_mut().unwrap();

        //lets print some debug infos so we can analyze this case in greater detail.

        // warn!(target: "hbbft_message_memorium", "No staking epoch history found for block: {}", block_num);

        // for staking_epoch_history_entry in self.staking_epoch_history.iter() {
        //     warn!(target: "hbbft_message_memorium", "Staking Epoch History: {:?}", staking_epoch_history_entry);
        // }

        None
    }

    fn work_message(&mut self) -> bool {
        let mut had_worked = false;

        if let Some(message) = self.dispatched_messages.pop_front() {
            let epoch = message.epoch();
            // match message.content() {
            //     honey_badger::MessageContent::Subset(subset) => todo!(),
            //     honey_badger::MessageContent::DecryptionShare { proposer_id, share } => todo!(),
            // }
            match serde_json::to_string(&message) {
                Ok(json_string) => {
                    self.on_message_string_received(json_string, epoch);
                }
                Err(e) => {
                    // being unable to interprete a message, could result in consequences
                    // not being able to report missbehavior,
                    // or reporting missbehavior, where there was not a missbehavior.
                    error!(target: "hbbft_message_memorium", "could not store hbbft message: {:?}", e);
                }
            }
            had_worked = true;
        }

        if let Some(seal) = self.dispatched_seals.pop_front() {
            match serde_json::to_string(&seal.0) {
                Ok(json_string) => {
                    self.on_message_string_received(json_string, seal.1);
                }
                Err(e) => {
                    // being unable to interprete a message, could result in consequences
                    // not being able to report missbehavior,
                    // or reporting missbehavior, where there was not a missbehavior.
                    error!(target: "hbbft_message_memorium", "could not store seal message: {:?}", e);
                }
            }
            had_worked = true;
        }

        // good seals
        if let Some(good_seal) = self.dispatched_seal_event_good.front() {
            // rust borrow system forced me into this useless clone...
            debug!(target: "hbbft_message_memorium", "work: good Seal!");
            if self.on_seal_good(&good_seal.clone()) {
                self.dispatched_seal_event_good.pop_front();
                debug!(target: "hbbft_message_memorium", "work: good Seal success! left: {}", self.dispatched_seal_event_good.len());

                had_worked = true;
            }
        }

        // late seals
        if let Some(late_seal) = self.dispatched_seal_event_late.front() {
            // rust borrow system forced me into this useless clone...
            if self.on_seal_late(&late_seal.clone()) {
                self.dispatched_seal_event_late.pop_front();
                debug!(target: "hbbft_message_memorium", "work: late Seal success! left: {}", self.dispatched_seal_event_late.len());

                had_worked = true;
            }
        }

        // faulty seals.
        if let Some(late_seal) = self.dispatched_seal_event_bad.front() {
            // rust borrow system forced me into this useless clone...
            if self.on_seal_bad(&late_seal.clone()) {
                self.dispatched_seal_event_bad.pop_front();
                debug!(target: "hbbft_message_memorium", "work: late Seal success! left: {}", self.dispatched_seal_event_late.len());

                had_worked = true;
            }
        }

        // faulty messages
        if let Some(message_faulty) = self.dispatched_message_event_faulty.front() {
            // rust borrow system forced me into this useless clone...
            if self.on_message_faulty(&message_faulty.clone()) {
                self.dispatched_message_event_faulty.pop_front();
                debug!(target: "hbbft_message_memorium", "work: faulty message! left: {}", self.dispatched_message_event_faulty.len());

                had_worked = true;
            }
        }

        // good messages
        if let Some(message_good) = self.dispatched_message_event_good.front() {
            if self.on_message_good(&message_good.clone()) {
                self.dispatched_message_event_good.pop_front();
                debug!(target: "hbbft_message_memorium", "work: good message! left: {}", self.dispatched_message_event_good.len());
                had_worked = true;
            }
        }

        // this does a disc write - probably we should do this on a separate thread.
        had_worked = had_worked | self.do_validator_stats_work();

        return had_worked;
    }

    pub fn free_memory(&mut self, _current_block: u64) {
        // self.signature_shares.remove(&epoch);
    }

    fn do_validator_stats_work(&mut self) -> bool {
        // this function does only the write out to hdd,
        // so we can safely return here, if no directory is configured.
        if self.config_validator_stats_directory.len() == 0 {
            return false;
        }

        // write the validator stats output report to disk if data is available and enough time has passed.
        //  self.timestamp_last_validator_stats_written
        // get current time.
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if self.staking_epoch_history.len() > 0
            && self.timestamp_last_validator_stats_written
                + (self.config_validator_stats_write_interval as u64)
                < current_time
        {
            for epoch_history in self.staking_epoch_history.iter_mut() {
                if epoch_history.exported {
                    continue;
                }
                let filename = format!(
                    "{}/epoch_{}.csv",
                    self.config_validator_stats_directory, epoch_history.staking_epoch
                );
                // get current executable path.
                let mut path: PathBuf;

                if let Ok(path_) = std::env::current_dir() {
                    path = path_;
                } else {
                    return false;
                }
                path.push(PathBuf::from(filename));

                let output_path: &std::path::Path = path.as_path();

                match std::fs::File::create(output_path) {
                    Ok(mut file) => {
                        let csv = epoch_history.get_epoch_stats_as_csv();
                        if let Err(err) = file.write_all(csv.as_bytes()) {
                            error!(target: "hbbft_message_memorium", "could not write validator stats to disk:{:?} {:?}",output_path, err);
                        } else {
                            epoch_history.exported = true;
                            self.timestamp_last_validator_stats_written = current_time;
                            return true;
                        }
                    }
                    Err(error) => {
                        error!(target: "hbbft_message_memorium", "could not create validator stats file on disk:{:?} {:?}", output_path, error);
                    }
                }
            }
        }
        return false;
    }
}

impl PrometheusMetrics for HbbftMessageDispatcher {
    fn prometheus_metrics(&self, registry: &mut stats::PrometheusRegistry) {
        if let Some(memorium) = self.memorial.try_read_for(Duration::from_millis(100)) {
            memorium.prometheus_metrics(registry);
        } else {
            error!(target: "hbbft_message_memorium", "could not get read lock on memorium for prometheus metrics");
        }
    }
}

impl PrometheusMetrics for StakingEpochHistory {
    fn prometheus_metrics(&self, r: &mut stats::PrometheusRegistry) {
        r.register_gauge(
            "staking_epoch",
            "Staking Epoch Number",
            self.staking_epoch as i64,
        );
        r.register_gauge(
            "staking_epoch_start_block",
            "Staking Epoch Start Block",
            self.staking_epoch_start_block as i64,
        );

        for epoch_history in self.node_staking_epoch_histories.iter() {
            epoch_history.prometheus_metrics(
                r,
                self.highest_block_num,
                self.staking_epoch_start_block,
            );
        }
    }
}

impl PrometheusMetrics for HbbftMessageMemorium {
    fn prometheus_metrics(&self, r: &mut stats::PrometheusRegistry) {
        //let epoch_history_len = self.staking_epoch_history.len() as i64;

        // r.register_gauge(
        //     "HbbftMessageMemorium_dispatched_message_event_faulty",
        //     "dispatched_message_event_faulty",
        //     self.dispatched_message_event_faulty.len() as i64,
        // );
        // r.register_gauge(
        //     "HbbftMessageMemorium_dispatched_message_event_good",
        //     "dispatched_message_event_good",
        //     self.dispatched_message_event_good.len() as i64,
        // );

        if let Some(history) = self.staking_epoch_history.iter().last() {
            history.prometheus_metrics(r);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::engines::hbbft::{NodeId, hbbft_message_memorium::BadSealReason};

    use super::{HbbftMessageMemorium, MessageEventGood, SealEventBad};

    use crypto::publickey::{Generator, Random};
    use ethereum_types::Public;

    #[test]
    fn test_message_memorium() {
        use super::SealEventGood;
        let mut memorium = HbbftMessageMemorium::new(0, "".to_string(), "".to_string());
        memorium.report_new_epoch(1, 100);

        let node1 = NodeId(Public::random());

        // we need a second node, that sends good seals every block.
        let node2 = NodeId(Public::random());

        //memorium.on_seal_good(SealEventGood { });

        memorium.on_seal_good(&SealEventGood {
            node_id: node1.clone(),
            block_num: 101,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 101,
        });

        assert_eq!(
            memorium.staking_epoch_history[0].node_staking_epoch_histories[0]
                .last_good_sealing_message,
            101
        );
        assert_eq!(
            memorium.staking_epoch_history[0].node_staking_epoch_histories[0].cumulative_lateness,
            0
        );

        // if we do skip block 101 with node1, and do not send a message at all - a late block should be tracked.
        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 102,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 103,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node1.clone(),
            block_num: 103,
        });

        assert_eq!(
            memorium.staking_epoch_history[0].node_staking_epoch_histories[0].cumulative_lateness,
            1
        );

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 104,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node1.clone(),
            block_num: 104,
        });

        // node was on time, so cumulative_lateness should be still one.
        assert_eq!(
            memorium.staking_epoch_history[0].node_staking_epoch_histories[0].cumulative_lateness,
            1
        );

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 105,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 106,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 107,
        });

        // node 1 was missing 3 blocks now.
        // the cumulative lateness should sum up as follows:
        // 1 - base value
        // 1 - block 107
        // 2 - block 106
        // 3 - block 105
        // ------
        // 7 - total

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 108,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node1.clone(),
            block_num: 108,
        });

        // node was on time, so cumulative_lateness should be still one.
        assert_eq!(
            memorium.staking_epoch_history[0].node_staking_epoch_histories[0].cumulative_lateness,
            7
        );

        // test the bad message seals.

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 109,
        });

        memorium.on_seal_bad(&SealEventBad {
            node_id: node1.clone(),
            block_num: 109,
            reason: BadSealReason::MismatchedNetworkInfo,
        });

        assert_eq!(
            memorium.staking_epoch_history[0].node_staking_epoch_histories[0].cumulative_lateness,
            8
        );

        // check if sealing message gaps are calculated the correct way with Bad Sealing Messages as well.
        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 110,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 111,
        });

        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 112,
        });

        // we will receive a bad Seal for block 113
        memorium.on_seal_good(&SealEventGood {
            node_id: node2.clone(),
            block_num: 113,
        });

        memorium.on_seal_bad(&SealEventBad {
            node_id: node1.clone(),
            block_num: 113,
            reason: BadSealReason::MismatchedNetworkInfo,
        });

        // node 1 was missing 3 blocks now, and has written 1 bad block.
        // the cumulative lateness should sum up as follows:
        // 8 - base value
        // 1 - block 113 (bad)
        // 1 - block 112 (missed)
        // 2 - block 111 (missed)
        // 3 - block 110 (missed)
        // 0 - block 109 (bad - already counted.)
        // ------
        // 15 - total

        assert_eq!(
            memorium.staking_epoch_history[0].node_staking_epoch_histories[0].cumulative_lateness,
            15
        );

        // since node2 was our reference node, that always created blocks, it's cumulative lateness should be 0

        assert_eq!(
            memorium.staking_epoch_history[0].node_staking_epoch_histories[1].cumulative_lateness,
            0
        );
    }
}
