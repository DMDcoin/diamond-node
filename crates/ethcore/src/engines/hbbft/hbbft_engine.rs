use super::{
    block_reward_hbbft::BlockRewardContract,
    hbbft_early_epoch_end_manager::HbbftEarlyEpochEndManager,
    hbbft_engine_cache::HbbftEngineCache,
    hbbft_peers_handler::{HbbftConnectToPeersMessage, HbbftPeersHandler},
};
use crate::{
    block::ExecutedBlock,
    client::{
        BlockChainClient,
        traits::{EngineClient, ForceUpdateSealing},
    },
    engines::{
        Engine, EngineError, ForkChoice, Seal, SealingState, default_system_or_code_call,
        hbbft::{
            contracts::random_hbbft::set_current_seed_tx_raw, hbbft_message_memorium::BadSealReason,
        },
        signer::EngineSigner,
    },
    error::{BlockError, Error},
    io::{IoContext, IoHandler, IoService, TimerToken},
    machine::EthereumMachine,
    types::{
        BlockNumber,
        header::{ExtendedHeader, Header},
        ids::BlockId,
        transaction::{SignedTransaction, TypedTransaction},
    },
};
use crypto::publickey::Signature;
use ethereum_types::{Address, H256, H512, Public, U256};
use ethjson::spec::HbbftParams;
use hbbft::{NetworkInfo, Target};
use itertools::Itertools;
use parking_lot::{Mutex, RwLock};
use rlp;
use rmp_serde;
use serde::Deserialize;
use stats::PrometheusMetrics;
use std::{
    cmp::{max, min},
    collections::BTreeMap,
    convert::TryFrom,
    ops::BitXor,
    sync::{Arc, Weak, atomic::AtomicBool},
    time::{Duration, Instant},
};

use super::{
    NodeId,
    contracts::{
        keygen_history::{all_parts_acks_available, initialize_synckeygen},
        staking::start_time_of_next_phase_transition,
        validator_set::{ValidatorType, get_pending_validators, is_pending_validator},
    },
    contribution::{unix_now_millis, unix_now_secs},
    hbbft_state::{Batch, HbMessage, HbbftState, HoneyBadgerStep},
    keygen_transactions::KeygenTransactionSender,
    sealing::{self, RlpSig, Sealing},
};
use crate::engines::hbbft::hbbft_message_memorium::HbbftMessageDispatcher;
use std::{ops::Deref, sync::atomic::Ordering};

type TargetedMessage = hbbft::TargetedMessage<Message, NodeId>;

/// A message sent between validators that is part of Honey Badger BFT or the block sealing process.
#[derive(Debug, Deserialize, Serialize)]
enum Message {
    /// A Honey Badger BFT message.
    HoneyBadger(usize, HbMessage),
    /// A threshold signature share. The combined signature is used as the block seal.
    Sealing(BlockNumber, sealing::Message),
}

/// The Honey Badger BFT Engine.
pub struct HoneyBadgerBFT {
    transition_service: IoService<()>,
    hbbft_peers_service: IoService<HbbftConnectToPeersMessage>,
    client: Arc<RwLock<Option<Weak<dyn EngineClient>>>>,
    signer: Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
    machine: EthereumMachine,
    hbbft_state: RwLock<HbbftState>,
    hbbft_message_dispatcher: HbbftMessageDispatcher,
    sealing: RwLock<BTreeMap<BlockNumber, Sealing>>,
    params: HbbftParams,
    message_counter: Mutex<usize>,
    random_numbers: RwLock<BTreeMap<BlockNumber, U256>>,
    keygen_transaction_sender: RwLock<KeygenTransactionSender>,

    has_connected_to_validator_set: AtomicBool,
    //peers_management: Mutex<HbbftPeersManagement>,
    current_minimum_gas_price: Mutex<Option<U256>>,
    early_epoch_manager: Mutex<Option<HbbftEarlyEpochEndManager>>,
    hbbft_engine_cache: Mutex<HbbftEngineCache>,
}

struct TransitionHandler {
    client: Arc<RwLock<Option<Weak<dyn EngineClient>>>>,
    engine: Arc<HoneyBadgerBFT>,
    /// the last known block for the auto shutdown on stuck node feature.
    /// https://github.com/DMDcoin/diamond-node/issues/78
    auto_shutdown_last_known_block_number: Mutex<u64>,
    auto_shutdown_last_known_block_import: Mutex<Instant>,
}

const DEFAULT_DURATION: Duration = Duration::from_secs(1);

impl TransitionHandler {
    /// Returns the approximate time duration between the latest block and the given offset
    /// (is 0 if the offset was passed) or the default time duration of 1s.
    fn block_time_until(&self, client: Arc<dyn EngineClient>, offset: u64) -> Duration {
        if let Some(block_header) = client.block_header(BlockId::Latest) {
            // The block timestamp and minimum block time are specified in seconds.
            let next_block_time = (block_header.timestamp() + offset) as u128 * 1000;

            // We get the current time in milliseconds to calculate the exact timer duration.
            let now = unix_now_millis();

            if now >= next_block_time {
                // If the current time is already past the minimum time for the next block
                // return 0 to signal readiness to create the next block.
                Duration::from_secs(0)
            } else {
                // Otherwise wait the exact number of milliseconds needed for the
                // now >= next_block_time condition to be true.
                // Since we know that "now" is smaller than "next_block_time" at this point
                // we also know that "next_block_time - now" will always be a positive number.
                match u64::try_from(next_block_time - now) {
                    Ok(value) => Duration::from_millis(value),
                    _ => {
                        error!(target: "consensus", "Could not convert duration to next block to u64");
                        DEFAULT_DURATION
                    }
                }
            }
        } else {
            error!(target: "consensus", "Latest Block Header could not be obtained!");
            DEFAULT_DURATION
        }
    }

    // Returns the time remaining until minimum block time is passed or the default time duration of 1s.
    fn min_block_time_remaining(&self, client: Arc<dyn EngineClient>) -> Duration {
        self.block_time_until(client, self.engine.params.minimum_block_time)
    }

    // Returns the time remaining until maximum block time is passed or the default time duration of 1s.
    fn max_block_time_remaining(&self, client: Arc<dyn EngineClient>) -> Duration {
        self.block_time_until(client, self.engine.params.maximum_block_time)
    }

    /// executes all operations that have to be delayed after the chain has synced to the current tail.
    /// returns: true if all delayed operation have been done now.
    fn execute_delayed_unitl_synced_operations(&self) -> bool {
        warn!(target: "consensus", "execute_delayed_unitl_synced_operations has been called");
        true
    }
}

// Arbitrary identifier for the timer we register with the event handler.
const ENGINE_TIMEOUT_TOKEN: TimerToken = 1;
const ENGINE_SHUTDOWN: TimerToken = 2;
// Some Operations should be executed if the chain is synced to the current tail.
const ENGINE_DELAYED_UNITL_SYNCED_TOKEN: TimerToken = 3;
// Some Operations have no urge on the timing, but are rather expensive.
// those are handeled by this slow ticking timer.
const ENGINE_VALIDATOR_CANDIDATE_ACTIONS: TimerToken = 4;

impl TransitionHandler {
    fn handle_shutdown_on_missing_block_import(
        &self,
        shutdown_on_missing_block_import_config_option: Option<u64>,
    ) {
        let shutdown_on_missing_block_import_config: u64;

        if let Some(c) = shutdown_on_missing_block_import_config_option {
            if c == 0 {
                // if shutdown_on_missing_block_import is configured to 0, we do not have to do anything.
                return;
            }
            shutdown_on_missing_block_import_config = c;
        } else {
            // if shutdown_on_missing_block_import is not configured at all, we do not have to do anything.
            return;
        }

        // ... we need to check if enough time has passed since the last block was imported.
        let current_block_number_option = if let Some(ref weak) = *self.client.read() {
            if let Some(c) = weak.upgrade() {
                c.block_number(BlockId::Latest)
            } else {
                warn!(target: "consensus", "shutdown-on-missing-block-import: Could not upgrade weak reference to client.");
                return;
            }
        } else {
            warn!(target: "consensus", "shutdown-on-missing-block-import: Could not read client.");
            return;
        };

        let now = std::time::Instant::now();

        if let Some(current_block_number) = current_block_number_option {
            if current_block_number <= 1 {
                // we do not do an auto shutdown for the first block.
                // it is normal for a network to have no blocks at the beginning, until everything is settled.
                return;
            }

            let last_known_block_number: u64 =
                self.auto_shutdown_last_known_block_number.lock().clone();

            if current_block_number == last_known_block_number {
                // if the last known block number is the same as the current block number,
                // we have not imported a new block since the last check.
                // we need to check if enough time has passed since the last check.

                let last_known_block_import =
                    self.auto_shutdown_last_known_block_import.lock().clone();
                let duration_since_last_block_import =
                    now.duration_since(last_known_block_import).as_secs();

                if duration_since_last_block_import < shutdown_on_missing_block_import_config {
                    // if the time since the last block import is less than the configured interval,
                    // we do not have to do anything.
                    return;
                }

                // lock the client and signal shutdown.
                warn!(
                    "shutdown-on-missing-block-import: Detected stalled block import. no import for {duration_since_last_block_import}. last known import: {:?} now: {:?} Demanding shut down of hbbft engine.",
                    last_known_block_import, now
                );

                // if auto shutdown at missing block production (or import) is configured.
                // ... we need to check if enough time has passed since the last block was imported.
                if let Some(ref weak) = *self.client.read() {
                    if let Some(c) = weak.upgrade() {
                        c.demand_shutdown();
                    } else {
                        error!(
                            "shutdown-on-missing-block-import: Error during Shutdown: could not upgrade weak reference."
                        );
                    }
                } else {
                    error!(
                        "shutdown-on-missing-block-import: Error during Shutdown: No client found."
                    );
                }
            } else {
                *self.auto_shutdown_last_known_block_import.lock() = now;
                *self.auto_shutdown_last_known_block_number.lock() = current_block_number;
            }
        } else {
            warn!(target: "consensus", "shutdown-on-missing-block-import: Could not read current block number.");
        }
    }

    fn handle_engine(&self, io: &IoContext<()>) -> Result<(), Error> {
        let client = self
            .client
            .read()
            .as_ref()
            .ok_or(EngineError::RequiresClient)?
            .upgrade()
            .ok_or(EngineError::RequiresClient)?;

        // trace!(target: "consensus", "Honey Badger IoHandler timeout called");
        // The block may be complete, but not have been ready to seal - trigger a new seal attempt.
        // TODO: In theory, that should not happen. The seal is ready exactly when the sealing entry is `Complete`.
        // if let Some(ref weak) = *self.client.read() {
        //     if let Some(c) = weak.upgrade() {
        //         c.update_sealing(ForceUpdateSealing::No);
        //         shutdown_on_missing_block_import_config =
        //             c.config_shutdown_on_missing_block_import();
        //     }
        // }

        client.update_sealing(ForceUpdateSealing::No);
        let shutdown_on_missing_block_import_config =
            client.config_shutdown_on_missing_block_import();

        // Periodically allow messages received for future epochs to be processed.
        self.engine.replay_cached_messages();

        self.handle_shutdown_on_missing_block_import(shutdown_on_missing_block_import_config);

        let mut timer_duration = self.min_block_time_remaining(client.clone());

        // If the minimum block time has passed we are ready to trigger new blocks.
        if timer_duration == Duration::from_secs(0) {
            // Always create blocks if we are in the keygen phase.
            self.engine.start_hbbft_epoch_if_next_phase();

            // If the maximum block time has been reached we trigger a new block in any case.
            if self.max_block_time_remaining(client.clone()) == Duration::from_secs(0) {
                self.engine.start_hbbft_epoch(client);
            }

            // Transactions may have been submitted during creation of the last block, trigger the
            // creation of a new block if the transaction threshold has been reached.
            self.engine.start_hbbft_epoch_if_ready();

            // Set timer duration to the default period (1s)
            timer_duration = DEFAULT_DURATION;
        }

        // The duration should be at least 1ms and at most self.engine.params.minimum_block_time
        timer_duration = max(timer_duration, Duration::from_millis(1));
        timer_duration = min(
            timer_duration,
            Duration::from_secs(self.engine.params.minimum_block_time),
        );

        io.register_timer_once(ENGINE_TIMEOUT_TOKEN, timer_duration)
            .unwrap_or_else(
                |e| warn!(target: "consensus", "Failed to restart consensus step timer: {}.", e),
            );

        Ok(())
    }
}

impl IoHandler<()> for TransitionHandler {
    fn initialize(&self, io: &IoContext<()>) {
        // Start the event loop with an arbitrary timer
        io.register_timer_once(ENGINE_TIMEOUT_TOKEN, DEFAULT_DURATION)
            .unwrap_or_else(
                |e| warn!(target: "consensus", "Failed to start consensus timer: {}.", e),
            );

        io.register_timer(ENGINE_SHUTDOWN, Duration::from_secs(1200))
            .unwrap_or_else(|e| warn!(target: "consensus", "HBBFT Shutdown Timer failed: {}.", e));

        // io.register_timer_once(ENGINE_DELAYED_UNITL_SYNCED_TOKEN, Duration::from_secs(10))
        //     .unwrap_or_else(|e| warn!(target: "consensus", "ENGINE_DELAYED_UNITL_SYNCED_TOKEN Timer failed: {}.", e));

        io.register_timer(ENGINE_VALIDATOR_CANDIDATE_ACTIONS, Duration::from_secs(30))
            .unwrap_or_else(|e| warn!(target: "consensus", "ENGINE_VALIDATOR_CANDIDATE_ACTIONS Timer failed: {}.", e));

        // io.channel()
        //     io.register_stream()
    }

    fn timeout(&self, io: &IoContext<()>, timer: TimerToken) {
        if timer == ENGINE_TIMEOUT_TOKEN {
            if let Err(err) = self.handle_engine(io) {
                trace!(target: "consensus", "Error in Honey Badger Engine timeout handler: {:?}", err);

                // in error cases we try again soon.
                io.register_timer_once(ENGINE_TIMEOUT_TOKEN, DEFAULT_DURATION)
                .unwrap_or_else(
                    |e| warn!(target: "consensus", "Failed to restart consensus step timer: {}.", e),
                );
            }
        } else if timer == ENGINE_SHUTDOWN {
            // we do not run this on the first occurence,
            // the first occurence could mean that the client is not fully set up
            // (e.g. it should sync, but it does not know it yet.)
            // we bypass the first try

            // we are using local static variable here, because
            // this function does not have a mut&.

            static IS_FIRST_RUN: AtomicBool = AtomicBool::new(true);

            if IS_FIRST_RUN.load(Ordering::SeqCst) {
                IS_FIRST_RUN.store(false, Ordering::SeqCst);
                return;
            }

            // 0: just return if we are syncing.
            // 1: check if we are a validator candidate
            // 2: ... and not a current validator
            // 3: ... and we are flagged as unavailable
            // 4: ... and we have staked enough funds on our pool
            // then order a shutdown!!

            if let Some(ref weak) = *self.client.read() {
                if let Some(c) = weak.upgrade() {
                    if self.engine.is_syncing(&c) {
                        return;
                    }
                }
            }
            // the engine knows already if it is acting as validator or as regular node.

            debug!(target: "consensus", "Honey Badger check for unavailability shutdown.");

            let is_staked = self.engine.is_staked();
            if is_staked {
                trace!(target: "consensus", "We are staked!");
                let is_available = self.engine.is_available();
                if !is_available {
                    warn!(target: "consensus", "Initiating Shutdown: Honey Badger Consensus detected that this Node has been flagged as unavailable, while it should be available.");

                    if let Some(ref weak) = *self.client.read() {
                        if let Some(c) = weak.upgrade() {
                            if let Some(id) = c.block_number(BlockId::Latest) {
                                warn!(target: "consensus", "BlockID: {id}");
                            }
                        }
                    }

                    let id: usize = std::process::id() as usize;
                    let thread_id = std::thread::current().id();
                    info!(target: "engine", "Waiting for Signaling shutdown to process ID: {id} thread: {:?}", thread_id);

                    if let Some(ref weak) = *self.client.read() {
                        if let Some(client) = weak.upgrade() {
                            info!(target: "engine", "demanding shutdown from hbbft engine.");
                            client.demand_shutdown();
                        }
                    }
                }
            }
        } else if timer == ENGINE_DELAYED_UNITL_SYNCED_TOKEN {
            if !self.execute_delayed_unitl_synced_operations() {
                io.register_timer_once(ENGINE_DELAYED_UNITL_SYNCED_TOKEN, Duration::from_secs(10))
                .unwrap_or_else(
                    |e| warn!(target: "consensus", "Failed to restart Engine is syncedconsensus step timer: {}.", e),
                );
            } else {
                trace!(target: "consensus", "All Operation that had to be done after syncing have been done now.");
            }
        } else if timer == ENGINE_VALIDATOR_CANDIDATE_ACTIONS {
            if let Err(err) = self.engine.do_validator_engine_actions() {
                error!(target: "consensus", "do_validator_engine_actions failed: {:?}", err);
            }
        }
    }
}

impl HoneyBadgerBFT {
    /// Creates an instance of the Honey Badger BFT Engine.
    pub fn new(params: HbbftParams, machine: EthereumMachine) -> Result<Arc<Self>, Error> {
        let is_unit_test = params.is_unit_test.unwrap_or(false);

        let engine = Arc::new(HoneyBadgerBFT {
            transition_service: IoService::<()>::start("Hbbft", 4)?,
            hbbft_peers_service: IoService::<HbbftConnectToPeersMessage>::start(
                "peers_management",
                1,
            )?,
            client: Arc::new(RwLock::new(None)),
            signer: Arc::new(RwLock::new(None)),
            machine,
            hbbft_state: RwLock::new(HbbftState::new()),
            hbbft_message_dispatcher: HbbftMessageDispatcher::new(
                params.blocks_to_keep_on_disk.unwrap_or(0),
                params
                    .blocks_to_keep_directory
                    .clone()
                    .unwrap_or("data/messages/".to_string()),
                if is_unit_test {
                    "".to_string()
                } else {
                    "data".to_string()
                },
            ),
            sealing: RwLock::new(BTreeMap::new()),
            params,
            message_counter: Mutex::new(0),
            random_numbers: RwLock::new(BTreeMap::new()),
            keygen_transaction_sender: RwLock::new(KeygenTransactionSender::new()),

            has_connected_to_validator_set: AtomicBool::new(false),
            current_minimum_gas_price: Mutex::new(None),
            early_epoch_manager: Mutex::new(None),
            hbbft_engine_cache: Mutex::new(HbbftEngineCache::new()),
        });

        if !engine.params.is_unit_test.unwrap_or(false) {
            let handler = TransitionHandler {
                client: engine.client.clone(),
                engine: engine.clone(),
                auto_shutdown_last_known_block_number: Mutex::new(0),
                auto_shutdown_last_known_block_import: Mutex::new(Instant::now()),
            };
            engine
                .transition_service
                .register_handler(Arc::new(handler))?;
        }

        let peers_handler = HbbftPeersHandler::new(engine.client.clone());
        engine
            .hbbft_peers_service
            .register_handler(Arc::new(peers_handler))?;

        Ok(engine)
    }

    fn process_output(
        &self,
        client: Arc<dyn EngineClient>,
        output: Vec<Batch>,
        network_info: &NetworkInfo<NodeId>,
    ) {
        // TODO: Multiple outputs are possible,
        //       process all outputs, respecting their epoch context.
        if output.len() > 1 {
            error!(target: "consensus", "UNHANDLED EPOCH OUTPUTS!");
            panic!("UNHANDLED EPOCH OUTPUTS!");
        }
        let batch = match output.first() {
            None => return,
            Some(batch) => batch,
        };

        trace!(target: "consensus", "Batch received for epoch {}, creating new Block.", batch.epoch);

        // Decode and de-duplicate transactions
        let batch_txns: Vec<_> = batch
            .contributions
            .iter()
            .flat_map(|(_, c)| &c.transactions)
            .filter_map(|ser_txn| {
                // TODO: Report proposers of malformed transactions.
                TypedTransaction::decode(ser_txn).ok()
            })
            .unique()
            .filter_map(|txn| {
                // TODO: Report proposers of invalidly signed transactions.
                SignedTransaction::new(txn).ok()
            })
            .collect();

        debug!(target: "consensus", "Block creation: Batch received for epoch {}, total {} contributions, with {} unique transactions.", batch.epoch, batch
            .contributions.iter().fold(0, |i, c| i + c.1.transactions.len()), batch_txns.len());

        trace!(target: "consensus", "Block creation: transactions {}", batch_txns.iter().map(|x| x.hash.to_string()).join(", "));

        // Make sure the resulting transactions do not contain nonces out of order.
        // Not necessary any more - we select contribution transactions by sender, contributing all transactions by that sender or none.
        // The transaction queue's "pending" transactions already guarantee there are no nonce gaps for a selected sender.
        // Even if different validators contribute a different number of transactions for the same sender the transactions stay sorted
        // by nonce after de-duplication.
        // Note: The following sorting would also allow front-running of addresses with higher nonces. If sorting became necessary in
        // the future for some reason replace this simplistic sort with one which preserves the relative order of senders.
        //batch_txns.sort_by(|left, right| left.tx().nonce.cmp(&right.tx().nonce));

        // We use the median of all contributions' timestamps
        let timestamps = batch
            .contributions
            .iter()
            .map(|(_, c)| c.timestamp)
            .sorted();

        let timestamp = match timestamps.iter().nth(timestamps.len() / 2) {
            Some(t) => t.clone(),
            None => {
                error!(target: "consensus", "Error calculating the block timestamp");
                return;
            }
        };

        let random_number = batch
            .contributions
            .iter()
            .fold(U256::zero(), |acc, (n, c)| {
                if c.random_data.len() >= 32 {
                    U256::from(&c.random_data[0..32]).bitxor(acc)
                } else {
                    // TODO: Report malicious behavior by node!
                    error!(target: "consensus", "Insufficient random data from node {}", n);
                    acc
                }
            });

        self.random_numbers
            .write()
            .insert(batch.epoch, random_number);

        if let Some(header) = client.create_pending_block_at(batch_txns, timestamp, batch.epoch) {
            let block_num = header.number();
            let hash = header.bare_hash();
            // TODO: trace is missleading here: we already got the signature shares, we can already
            trace!(target: "consensus", "Sending signature share of {} for block {}", hash, block_num);
            let step = match self
                .sealing
                .write()
                .entry(block_num)
                .or_insert_with(|| self.new_sealing(network_info))
                .sign(hash)
            {
                Ok(step) => step,
                Err(err) => {
                    // TODO: Error handling
                    error!(target: "consensus", "Error creating signature share for block {}: {:?}", block_num, err);
                    return;
                }
            };
            self.process_seal_step(client, step, block_num, network_info);
        } else {
            error!(target: "consensus", "Could not create pending block for hbbft epoch {}: ", batch.epoch);
        }
    }

    fn process_hb_message(
        &self,
        msg_idx: usize,
        message: HbMessage,
        sender_id: NodeId,
    ) -> Result<(), EngineError> {
        let client = self.client_arc().ok_or(EngineError::RequiresClient)?;
        trace!(target: "consensus", "Received message of idx {}  {:?} from {}", msg_idx, message, sender_id);

        // store received messages here.
        self.hbbft_message_dispatcher.on_message_received(&message);

        let message_block = message.epoch();

        let mut lock = self.hbbft_state.write();
        match lock.process_message(client.clone(), &self.signer, sender_id, message) {
            Ok(Some((step, network_info))) => {
                std::mem::drop(lock);
                if step.fault_log.0.is_empty() {
                    //TODO:  report good message here.
                    self.hbbft_message_dispatcher
                        .report_message_good(&sender_id, message_block);
                } else {
                    for f in step.fault_log.0.iter() {
                        warn!(target: "consensus", "Block {} Node {} reported fault: {:?}", message_block, f.node_id, f.kind);
                        self.hbbft_message_dispatcher.report_message_faulty(
                            &f.node_id,
                            message_block,
                            Some(f.kind.clone()),
                        );
                    }
                }
                self.process_step(client, step, &network_info);
                self.join_hbbft_epoch()?;
            }
            Ok(None) => {}
            Err(err) => {
                std::mem::drop(lock);
                // this error is thrown on a step error.
                warn!(target: "consensus", "Block {} Node {} reported fault: {:?}", message_block, &sender_id, err);
                self.hbbft_message_dispatcher.report_message_faulty(
                    &sender_id,
                    message_block,
                    None,
                );
            }
        }

        Ok(())
    }

    fn process_sealing_message(
        &self,
        message: sealing::Message,
        sender_id: NodeId,
        block_num: BlockNumber,
    ) -> Result<(), EngineError> {
        // store received messages here.
        // self.hbbft_message_dispatcher
        //     .write()
        //     .on_sealing_message_received(&message, block_num, &sender_id);

        let client = self.client_arc().ok_or(EngineError::RequiresClient)?;
        trace!(target: "consensus", "Received sealing message for block {} from {}",block_num, sender_id);
        if let Some(latest) = client.block_number(BlockId::Latest) {
            if latest >= block_num {
                self.hbbft_message_dispatcher
                    .report_seal_late(&sender_id, block_num, latest);
                return Ok(()); // Message is obsolete.
            }
        }

        // client.staking

        let network_info = match self.hbbft_state.write().network_info_for(
            client.clone(),
            &self.signer,
            block_num,
        ) {
            Some(n) => n,
            None => {
                error!(target: "consensus", "Sealing message for block #{} could not be processed due to missing/mismatching network info.", block_num);
                self.hbbft_message_dispatcher.report_seal_bad(
                    &sender_id,
                    block_num,
                    BadSealReason::MismatchedNetworkInfo,
                );
                return Err(EngineError::UnexpectedMessage);
            }
        };

        trace!(target: "consensus", "Received signature share for block {} from {}", block_num, sender_id);
        let step_result = self
            .sealing
            .write()
            .entry(block_num)
            .or_insert_with(|| self.new_sealing(&network_info))
            .handle_message(&sender_id, message);
        match step_result {
            Ok(step) => {
                self.hbbft_message_dispatcher
                    .report_seal_good(&sender_id, block_num);
                self.process_seal_step(client, step, block_num, &network_info);
            }
            Err(err) => {
                error!(target: "consensus", "Error on ThresholdSign step: {:?}", err);
                self.hbbft_message_dispatcher.report_seal_bad(
                    &sender_id,
                    block_num,
                    BadSealReason::ErrorTresholdSignStep,
                );
            }
        }
        Ok(())
    }

    fn dispatch_messages<I>(
        &self,
        client: &Arc<dyn EngineClient>,
        messages: I,
        net_info: &NetworkInfo<NodeId>,
    ) where
        I: IntoIterator<Item = TargetedMessage>,
    {
        for m in messages {
            let ser =
                rmp_serde::to_vec(&m.message).expect("Serialization of consensus message failed");
            match m.target {
                Target::Nodes(set) => {
                    trace!(target: "consensus", "Dispatching message {:?} to {:?}", m.message, set);
                    for node_id in set.into_iter().filter(|p| p != net_info.our_id()) {
                        trace!(target: "consensus", "Sending message to {}", node_id.0);
                        client.send_consensus_message(ser.clone(), Some(node_id.0));
                    }
                }
                Target::AllExcept(set) => {
                    trace!(target: "consensus", "Dispatching exclusive message {:?} to all except {:?}", m.message, set);
                    for node_id in net_info
                        .all_ids()
                        .filter(|p| (p != &net_info.our_id() && !set.contains(p)))
                    {
                        trace!(target: "consensus", "Sending exclusive message to {}", node_id.0);
                        client.send_consensus_message(ser.clone(), Some(node_id.0));
                    }
                }
            }
        }
    }

    fn process_seal_step(
        &self,
        client: Arc<dyn EngineClient>,
        step: sealing::Step,
        block_num: BlockNumber,
        network_info: &NetworkInfo<NodeId>,
    ) {
        let messages = step
            .messages
            .into_iter()
            .map(|msg| msg.map(|m| Message::Sealing(block_num, m)));
        self.dispatch_messages(&client, messages, network_info);
        if let Some(sig) = step.output.into_iter().next() {
            trace!(target: "consensus", "Signature for block {} is ready", block_num);
            let state = Sealing::Complete(sig);
            self.sealing.write().insert(block_num, state);

            client.update_sealing(ForceUpdateSealing::No);
        }
    }

    fn process_step(
        &self,
        client: Arc<dyn EngineClient>,
        step: HoneyBadgerStep,
        network_info: &NetworkInfo<NodeId>,
    ) {
        let mut message_counter = self.message_counter.lock();

        let messages = step.messages.into_iter().map(|msg| {
            *message_counter += 1;
            TargetedMessage {
                target: msg.target,
                message: Message::HoneyBadger(*message_counter, msg.message),
            }
        });
        self.dispatch_messages(&client, messages, network_info);
        std::mem::drop(message_counter);
        self.process_output(client, step.output, network_info);
    }

    /// Conditionally joins the current hbbft epoch if the number of received
    /// contributions exceeds the maximum number of tolerated faulty nodes.
    fn join_hbbft_epoch(&self) -> Result<(), EngineError> {
        let client = self.client_arc().ok_or(EngineError::RequiresClient)?;
        if self.is_syncing(&client) {
            trace!(target: "consensus", "tried to join HBBFT Epoch, but still syncing.");
            return Ok(());
        }

        let step = self
            .hbbft_state
            .write()
            .contribute_if_contribution_threshold_reached(client.clone(), &self.signer);
        if let Some((step, network_info)) = step {
            self.process_step(client, step, &network_info)
        } else {
            // trace!(target: "consensus", "tried to join HBBFT Epoch, but contribution threshold not reached.");
        }
        Ok(())
    }

    fn start_hbbft_epoch(&self, client: Arc<dyn EngineClient>) {
        if self.is_syncing(&client) {
            return;
        }

        let step = match self
            .hbbft_state
            .try_write_for(std::time::Duration::from_millis(10))
        {
            Some(mut state_lock) => state_lock.try_send_contribution(client.clone(), &self.signer),
            None => {
                return;
            }
        };

        if let Some((step, network_info)) = step {
            self.process_step(client, step, &network_info)
        }
    }

    fn transaction_queue_and_time_thresholds_reached(
        &self,
        client: &Arc<dyn EngineClient>,
    ) -> bool {
        if let Some(block_header) = client.block_header(BlockId::Latest) {
            let target_min_timestamp = block_header.timestamp() + self.params.minimum_block_time;
            let now = unix_now_secs();
            // we could implement a cheaper way to get the number of queued transaction, that does not require this intensive locking.
            // see: https://github.com/DMDcoin/diamond-node/issues/237
            let queue_length = client.queued_transactions().len();
            (self.params.minimum_block_time == 0 || target_min_timestamp <= now)
                && queue_length >= self.params.transaction_queue_size_trigger
        } else {
            false
        }
    }

    fn new_sealing(&self, network_info: &NetworkInfo<NodeId>) -> Sealing {
        Sealing::new(network_info.clone())
    }

    fn client_arc(&self) -> Option<Arc<dyn EngineClient>> {
        self.client.read().as_ref().and_then(Weak::upgrade)
    }

    fn start_hbbft_epoch_if_next_phase(&self) {
        match self.client_arc() {
            None => return,
            Some(client) => {
                // Get the next phase start time
                let genesis_transition_time = match start_time_of_next_phase_transition(&*client) {
                    Ok(time) => time,
                    Err(_) => return,
                };

                // If current time larger than phase start time, start a new block.
                if genesis_transition_time.as_u64() < unix_now_secs() {
                    self.start_hbbft_epoch(client);
                }
            }
        }
    }

    fn replay_cached_messages(&self) -> Option<()> {
        let client = self.client_arc()?;

        // replaying cached messages is not so important that it cause deadlocks
        // instead we gently try to get a lock for 10 ms, and if we do not get a lock,
        // we will just try again in the next tick.
        // we could try to do some optimizations here to improve performance.

        let steps = match self.hbbft_state.try_write_for(Duration::from_millis(10)) {
            Some(mut hbbft_state_lock) => hbbft_state_lock.replay_cached_messages(client.clone()),
            None => {
                trace!(target: "engine", "could not acquire write lock for replaying cached messages, stepping back..",);
                return None;
            }
        };

        let mut processed_step = false;
        if let Some((steps, network_info)) = steps {
            for step in steps {
                match step {
                    Ok(step) => {
                        trace!(target: "engine", "Processing cached message step");
                        processed_step = true;
                        self.process_step(client.clone(), step, &network_info)
                    }
                    Err(e) => error!(target: "engine", "Error handling replayed message: {}", e),
                }
            }
        }

        if processed_step {
            if let Err(e) = self.join_hbbft_epoch() {
                error!(target: "engine", "Error trying to join epoch: {}", e);
            }
        }

        Some(())
    }

    fn should_connect_to_validator_set(&self) -> bool {
        !self.has_connected_to_validator_set.load(Ordering::SeqCst)
    }

    /// early epoch ends
    /// https://github.com/DMDcoin/diamond-node/issues/87
    fn handle_early_epoch_end(
        &self,
        block_chain_client: &dyn BlockChainClient,
        engine_client: &dyn EngineClient,
        mining_address: &Address,
        epoch_start_block: u64,
        epoch_num: u64,
        validator_set: &Vec<NodeId>,
    ) {
        // todo: acquire allowed devp2p warmup time from contracts ?!
        let allowed_devp2p_warmup_time = Duration::from_secs(1200);

        debug!(target: "engine", "early-epoch-end: handle_early_epoch_end.");

        // we got everything we need from hbbft_state - drop lock ASAP.

        if let Some(memorium) = self
            .hbbft_message_dispatcher
            .get_memorium()
            .try_read_for(Duration::from_millis(300))
        {
            // this is currently the only location where we lock early epoch manager -
            // so this should never cause a deadlock, and we do not have to try_lock_for
            let mut lock_guard = self.early_epoch_manager.lock();

            match lock_guard.as_mut() {
                Some(early_epoch_end_manager) => {
                    // should we check here if the epoch number has changed ?
                    early_epoch_end_manager.decide(&memorium, block_chain_client, engine_client);
                }
                None => {
                    *lock_guard = HbbftEarlyEpochEndManager::create_early_epoch_end_manager(
                        allowed_devp2p_warmup_time,
                        block_chain_client,
                        engine_client,
                        epoch_num,
                        epoch_start_block,
                        validator_set.clone(),
                        mining_address,
                    );

                    if let Some(manager) = lock_guard.as_mut() {
                        manager.decide(&memorium, block_chain_client, engine_client);
                    }
                }
            }
        } else {
            warn!(target: "engine", "early-epoch-end: could not acquire read lock for memorium to decide on ealry_epoch_end_manager in do_validator_engine_actions.");
        }
    }

    // some actions are required for hbbft nodes.
    // this functions figures out what kind of actions are required and executes them.
    // this will lock the client and some deeper layers.
    fn do_validator_engine_actions(&self) -> Result<(), Error> {
        // here we need to differentiate the different engine functions,
        // that requre different levels of access to the client.
        trace!(target: "engine", "do_validator_engine_actions.");
        match self.client_arc() {
            Some(client_arc) => {
                if self.is_syncing(&client_arc) {
                    // we are syncing - do not do anything.
                    trace!(target: "engine", "do_validator_engine_actions: skipping because we are syncing.");
                    return Ok(());
                }

                // If we have no signer there is nothing for us to send.
                let mining_address = match self.signer.read().as_ref() {
                    Some(signer) => signer.address(),
                    None => {
                        // we do not have a signer on Full and RPC nodes.
                        // here is a possible performance improvement:
                        // this won't change during the lifetime of the application ?!
                        return Ok(());
                    }
                };

                let engine_client = client_arc.as_ref();
                if let Err(err) = self
                    .hbbft_engine_cache
                    .lock()
                    .refresh_cache(mining_address, engine_client)
                {
                    trace!(target: "engine", "do_validator_engine_actions: data could not get updated, follow up tasks might fail: {:?}", err);
                }

                let engine_client = client_arc.deref();

                let block_chain_client = match engine_client.as_full_client() {
                    Some(block_chain_client) => block_chain_client,
                    None => {
                        return Err("Unable to retrieve client.as_full_client()".into());
                    }
                };

                let should_connect_to_validator_set = self.should_connect_to_validator_set();
                let mut should_handle_early_epoch_end = false;

                // we just keep those variables here, because we need them in the early_epoch_end_manager.
                // this is just an optimization, so we do not acquire the lock for that much time.
                let mut validator_set: Vec<NodeId> = Vec::new();
                let mut epoch_start_block: u64 = 0;
                let mut epoch_num: u64 = 0;

                {
                    let hbbft_state_option =
                        self.hbbft_state.try_read_for(Duration::from_millis(250));
                    match hbbft_state_option {
                        Some(hbbft_state) => {
                            should_handle_early_epoch_end = hbbft_state.is_validator();

                            // if we are a pending validator, we will also do the reserved peers management.
                            if should_handle_early_epoch_end {
                                // we already remember here stuff the early epoch manager needs,
                                // so we do not have to acquire the lock for that long.
                                epoch_num = hbbft_state.get_current_posdao_epoch();
                                epoch_start_block =
                                    hbbft_state.get_current_posdao_epoch_start_block();
                                validator_set = hbbft_state.get_validator_set();
                            }
                        }
                        None => {
                            // maybe improve here, to return with a result, that triggers a retry soon.
                            debug!(target: "engine", "Unable to do_validator_engine_actions: Could not acquire read lock for hbbft state. Unable to decide about early epoch end. retrying soon.");
                        }
                    };
                } // drop lock for hbbft_state

                self.hbbft_peers_service
                    .send_message(HbbftConnectToPeersMessage::AnnounceOwnInternetAddress)?;

                // if we do not have to do anything, we can return early.
                if !(should_connect_to_validator_set || should_handle_early_epoch_end) {
                    return Ok(());
                }

                self.hbbft_peers_service
                    .channel()
                    .send(HbbftConnectToPeersMessage::AnnounceAvailability)?;

                if should_connect_to_validator_set {
                    self.hbbft_peers_service.send_message(
                        HbbftConnectToPeersMessage::ConnectToCurrentPeers(validator_set.clone()),
                    )?;
                }

                if should_handle_early_epoch_end {
                    self.handle_early_epoch_end(
                        block_chain_client,
                        engine_client,
                        &mining_address,
                        epoch_start_block,
                        epoch_num,
                        &validator_set,
                    );
                }

                return Ok(());
            }

            None => {
                // client arc not ready yet,
                // can happen during initialization and shutdown.
                return Ok(());
            }
        }
    }

    /// Returns true if we are in the keygen phase and a new key has been generated.
    fn do_keygen(&self, block_timestamp: u64) -> bool {
        match self.client_arc() {
            None => false,
            Some(client) => {
                // If we are not in key generation phase, return false.
                let validators = match get_pending_validators(&*client) {
                    Err(_) => return false,
                    Ok(validators) => {
                        // If the validator set is empty then we are not in the key generation phase.
                        if validators.is_empty() {
                            return false;
                        }
                        validators
                    }
                };

                // Check if a new key is ready to be generated, return true to switch to the new epoch in that case.
                // The execution needs to be *identical* on all nodes, which means it should *not* use the local signer
                // when attempting to initialize the synckeygen.
                if let Ok(all_available) =
                    all_parts_acks_available(&*client, block_timestamp, validators.len())
                {
                    if all_available {
                        let null_signer = Arc::new(RwLock::new(None));
                        match initialize_synckeygen(
                            &*client,
                            &null_signer,
                            BlockId::Latest,
                            ValidatorType::Pending,
                        ) {
                            Ok(synckeygen) => {
                                if synckeygen.is_ready() {
                                    return true;
                                }
                            }
                            Err(e) => {
                                error!(target: "consensus", "Error initializing synckeygen: {:?}", e);
                            }
                        }
                    }
                }

                // Otherwise check if we are in the pending validator set and send Parts and Acks transactions.
                // @todo send_keygen_transactions initializes another synckeygen structure, a potentially
                //       time consuming process. Move sending of keygen transactions into a separate function
                //       and call it periodically using timer events instead of on close block.
                if let Some(signer) = self.signer.read().as_ref() {
                    if let Ok(is_pending) = is_pending_validator(&*client, &signer.address()) {
                        trace!(target: "engine", "is_pending_validator: {}", is_pending);
                        if is_pending {
                            if let Err(err) = self.hbbft_peers_service.send_message(
                                HbbftConnectToPeersMessage::ConnectToPendingPeers(validators),
                            ) {
                                error!(target: "engine", "Error connecting to pending peers: {:?}", err);
                            }

                            let _err = self
                                .keygen_transaction_sender
                                .write()
                                .send_keygen_transactions(&*client, &self.signer);
                            match _err {
                                Ok(()) => {}
                                Err(e) => {
                                    error!(target: "engine", "Error sending keygen transactions {:?}", e);
                                }
                            }
                        }
                    }
                }
                false
            }
        }
    }

    fn is_syncing(&self, client: &Arc<dyn EngineClient>) -> bool {
        match client.as_full_client() {
            Some(full_client) => full_client.is_syncing(),
            // We only support full clients at this point.
            None => true,
        }
    }

    /** returns if the signer of hbbft is tracked as available in the hbbft contracts..*/
    pub fn is_available(&self) -> bool {
        self.hbbft_engine_cache.lock().is_available()
    }

    /** returns if the signer of hbbft is stacked. */
    pub fn is_staked(&self) -> bool {
        self.hbbft_engine_cache.lock().is_staked()
    }

    fn start_hbbft_epoch_if_ready(&self) {
        if let Some(client) = self.client_arc() {
            if self.transaction_queue_and_time_thresholds_reached(&client) {
                self.start_hbbft_epoch(client);
            }
        }
    }
}

impl Engine<EthereumMachine> for HoneyBadgerBFT {
    fn name(&self) -> &str {
        "HoneyBadgerBFT"
    }

    fn machine(&self) -> &EthereumMachine {
        &self.machine
    }

    fn minimum_gas_price(&self) -> Option<U256> {
        self.current_minimum_gas_price.lock().clone()
    }

    fn fork_choice(&self, new: &ExtendedHeader, current: &ExtendedHeader) -> ForkChoice {
        crate::engines::total_difficulty_fork_choice(new, current)
    }

    fn verify_local_seal(&self, _header: &Header) -> Result<(), Error> {
        Ok(())
    }

    /// Phase 1 Checks
    fn verify_block_basic(&self, _header: &Header) -> Result<(), Error> {
        Ok(())
    }

    /// Pase 2 Checks
    fn verify_block_unordered(&self, _header: &Header) -> Result<(), Error> {
        Ok(())
    }

    /// Phase 3 Checks
    /// We check the signature here since at this point the blocks are imported in-order.
    /// To verify the signature we need the parent block already imported on the chain.
    fn verify_block_family(&self, header: &Header, _parent: &Header) -> Result<(), Error> {
        let client = self.client_arc().ok_or(EngineError::RequiresClient)?;

        let latest_block_nr = client.block_number(BlockId::Latest).expect("must succeed");

        if header.number() > (latest_block_nr + 1) {
            error!(target: "engine", "Phase 3 block verification out of order!");
            return Err(BlockError::InvalidSeal.into());
        }

        if header.seal().len() != 1 {
            return Err(BlockError::InvalidSeal.into());
        }

        let RlpSig(sig) = rlp::decode(header.seal().first().ok_or(BlockError::InvalidSeal)?)?;
        if self
            .hbbft_state
            .write()
            .verify_seal(client, &self.signer, &sig, header)
        {
            Ok(())
        } else {
            error!(target: "engine", "Invalid seal (Stage 3) for block #{}!", header.number());
            let trace = std::backtrace::Backtrace::capture();
            error!(target: "engine", "Invalid Seal Trace: #{trace:?}!");
            Err(BlockError::InvalidSeal.into())
        }
    }

    // Phase 4
    fn verify_block_external(&self, _header: &Header) -> Result<(), Error> {
        Ok(())
    }

    fn register_client(&self, client: Weak<dyn EngineClient>) {
        *self.client.write() = Some(client.clone());

        if let Some(client) = self.client_arc() {
            let mut state = self.hbbft_state.write();

            // todo: better get the own ID from devP2P communication ?!
            let own_public_key = match self.signer.read().as_ref() {
                Some(signer) => signer
                    .public()
                    .expect("Signer's public key must be available!"),
                None => Public::from(H512::from_low_u64_be(0)),
            };

            if let Some(latest_block) = client.block_number(BlockId::Latest) {
                state.init_fork_manager(
                    NodeId(own_public_key),
                    latest_block,
                    self.params.forks.clone(),
                );
            } else {
                error!(target: "engine", "hbbft-hardfork : could not initialialize hardfork manager, no latest block found.");
            }

            match state.update_honeybadger(
                client,
                &self.signer,
                &self.hbbft_peers_service,
                &self.early_epoch_manager,
                &self.current_minimum_gas_price,
                BlockId::Latest,
                true,
            ) {
                Some(_) => {
                    let posdao_epoch = state.get_current_posdao_epoch();
                    let epoch_start_block = state.get_current_posdao_epoch_start_block();
                    // we got all infos from the state, we can drop the lock.
                    std::mem::drop(state);
                    info!(target: "engine", "report new epoch: {} at block: {}", posdao_epoch, epoch_start_block);
                    self.hbbft_message_dispatcher
                        .report_new_epoch(posdao_epoch, epoch_start_block);
                }
                None => error!(target: "engine", "Error during HoneyBadger initialization!"),
            }
        }
    }

    fn set_signer(&self, signer: Option<Box<dyn EngineSigner>>) {
        if let Some(engine_signer) = signer.as_ref() {
            let signer_address = engine_signer.address();
            info!(target: "engine", "set_signer: {:?}", signer_address);
            if let Err(err) = self
                .hbbft_peers_service
                .send_message(HbbftConnectToPeersMessage::SetSignerAddress(signer_address))
            {
                error!(target: "engine", "Error setting signer address in hbbft peers service: {:?}", err);
            }
        } else {
            info!(target: "engine", "set_signer: signer is None, not setting signer address in hbbft peers service.");
        }

        *self.signer.write() = signer;

        if let Some(client) = self.client_arc() {
            // client.as_full_client().and_then(|c| {
            //     self.peers_management.lock().set_peers_management(self.peers_management.clone());
            //     None
            //     }
            // );
            // setting peers management here.

            warn!(target: "engine", "set_signer - update_honeybadger...");
            if let None = self.hbbft_state.write().update_honeybadger(
                client,
                &self.signer,
                &self.hbbft_peers_service,
                &self.early_epoch_manager,
                &self.current_minimum_gas_price,
                BlockId::Latest,
                true,
            ) {
                info!(target: "engine", "HoneyBadger Algorithm could not be created, Client possibly not set yet.");
            }
        }
    }

    fn sign(&self, hash: H256) -> Result<Signature, Error> {
        match self.signer.read().as_ref() {
            Some(signer) => signer
                .sign(hash)
                .map_err(|_| EngineError::RequiresSigner.into()),
            None => Err(EngineError::RequiresSigner.into()),
        }
    }

    fn sealing_state(&self) -> SealingState {
        // Purge obsolete sealing processes.
        let client = match self.client_arc() {
            None => return SealingState::NotReady,
            Some(client) => client,
        };
        let next_block = match client.block_number(BlockId::Latest) {
            None => return SealingState::NotReady,
            Some(block_num) => block_num + 1,
        };
        let mut sealing = self.sealing.write();
        *sealing = sealing.split_off(&next_block);

        // We are ready to seal if we have a valid signature for the next block.
        if let Some(next_seal) = sealing.get(&next_block) {
            if next_seal.signature().is_some() {
                return SealingState::Ready;
            }
        }
        SealingState::NotReady
    }

    fn on_transactions_imported(&self) {
        if self.params.is_unit_test.unwrap_or(false) {
            self.start_hbbft_epoch_if_ready();
        }
    }

    fn handle_message(&self, message: &[u8], node_id: Option<H512>) -> Result<(), EngineError> {
        let node_id = NodeId(node_id.ok_or(EngineError::UnexpectedMessage)?);
        match rmp_serde::from_slice(message) {
            Ok(Message::HoneyBadger(msg_idx, hb_msg)) => {
                self.process_hb_message(msg_idx, hb_msg, node_id)
            }
            Ok(Message::Sealing(block_num, seal_msg)) => {
                self.process_sealing_message(seal_msg, node_id, block_num)
            }
            Err(_) => Err(EngineError::MalformedMessage(
                "Serde message decoding failed.".into(),
            )),
        }
    }

    fn seal_fields(&self, _header: &Header) -> usize {
        1
    }

    fn generate_seal(&self, block: &ExecutedBlock, _parent: &Header) -> Seal {
        let client = match self.client_arc() {
            None => return Seal::None,
            Some(client) => client,
        };

        let block_num = block.header.number();
        let sealing = self.sealing.read();
        let sig = match sealing.get(&block_num).and_then(Sealing::signature) {
            None => return Seal::None,
            Some(sig) => sig,
        };
        if !self
            .hbbft_state
            .write()
            .verify_seal(client, &self.signer, &sig, &block.header)
        {
            error!(target: "consensus", "generate_seal: Threshold signature does not match new block.");
            return Seal::None;
        }
        trace!(target: "consensus", "Returning generated seal for block {}.", block_num);
        Seal::Regular(vec![rlp::encode(&RlpSig(sig))])
    }

    fn should_miner_prepare_blocks(&self) -> bool {
        false
    }

    fn use_block_author(&self) -> bool {
        false
    }

    fn on_before_transactions(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
        // trace!(target: "consensus", "on_before_transactions: {:?} extra data: {:?}", block.header.number(), block.header.extra_data());
        let random_numbers = self.random_numbers.read();
        let random_number: U256 = match random_numbers.get(&block.header.number()) {
            None => {
                // if we do not have random data for this block,
                // because we are performant vaidator, the block is comming over the block import.
                // the RNG is stored in the extra data field.
                let extra_data = block.header.extra_data();

                // extra data 0 and the value "Parity" is not considered as random number.
                // so we only accept data with the correct length.
                let r_ = if extra_data.len() == 32 {
                    let r = U256::from_big_endian(extra_data);
                    debug!(
                        "restored random number from header for block {} random number: {:?}",
                        block.header.number(),
                        r
                    );
                    r
                } else if extra_data.len() == 6 && extra_data == &[80, 97, 114, 105, 116, 121] {
                    warn!("detected Parity as random number, ignoring.",);
                    return Ok(());
                } else {
                    // if there is no header data,
                    // than it is because the old node software created blocks without random data in the header.
                    // this backward compatibility can be removed once no testnetwork with old behavior is running."

                    return Ok(());
                    // return Err(EngineError::Custom(
                    //     "No value available for calling randomness contract.".into(),
                    // )
                    // .into());
                };
                r_
            }
            Some(r) => {
                // we also need to write this extra data into the header.
                let mut bytes: [u8; 32] = [0; 32];
                r.to_big_endian(&mut bytes);
                block.header.set_extra_data(bytes.to_vec());
                r.clone()
            }
        };

        let tx = set_current_seed_tx_raw(&random_number);

        //  let mut call = engines::default_system_or_code_call(&self.machine, block);
        let result = self
            .machine
            .execute_as_system(block, tx.0, U256::max_value(), Some(tx.1));

        match result {
            Ok(_) => {
                return Ok(());
            }
            Err(e) => {
                //return Err(EngineError::Custom(format!("Error calling randomness contract: {:?}", e)).into());
                return Err(e);
            }
        }
    }

    /// Allow mutating the header during seal generation.
    fn on_seal_block(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
        let random_numbers = self.random_numbers.read();
        match random_numbers.get(&block.header.number()) {
            None => {
                warn!("No rng value available for header.");
                return Ok(());
            }
            Some(r) => {
                let mut bytes: [u8; 32] = [0; 32];
                r.to_big_endian(&mut bytes);

                block.header.set_extra_data(bytes.to_vec());
            }
        };

        Ok(())
    }

    fn on_close_block(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
        if let Some(address) = self.params.block_reward_contract_address {
            // only if no block reward skips are defined for this block.
            let header_number = block.header.number();

            if self
                .params
                .should_do_block_reward_contract_call(header_number)
            {
                let mut call = default_system_or_code_call(&self.machine, block);
                let mut latest_block_number: BlockNumber = 0;
                let mut latest_block_timestamp: u64 = 0;
                if let Some(client) = self.client_arc() {
                    if let Some(header) = client.block_header(BlockId::Latest) {
                        latest_block_number = header.number();
                        latest_block_timestamp = header.timestamp()
                    }
                }

                // only do the key gen
                let is_epoch_end = self.do_keygen(latest_block_timestamp);

                trace!(target: "consensus", "calling reward function for block {} isEpochEnd? {} on address: {} (latest block: {}", header_number,  is_epoch_end, address, latest_block_number);
                let contract = BlockRewardContract::new_from_address(address);
                let _total_reward = contract.reward(&mut call, is_epoch_end)?;
            }
        }

        self.hbbft_message_dispatcher
            .free_memory(block.header.number());

        Ok(())
    }

    fn on_chain_commit(&self, block_hash: &H256) {
        if let Some(client) = self.client_arc() {
            let mut state = self.hbbft_state.write();
            let old_posdao_epoch = state.get_current_posdao_epoch();
            match state.update_honeybadger(
                client.clone(),
                &self.signer,
                &self.hbbft_peers_service,
                &self.early_epoch_manager,
                &self.current_minimum_gas_price,
                BlockId::Hash(block_hash.clone()),
                false,
            ) {
                Some(_) => {
                    let new_posdao_epoch = state.get_current_posdao_epoch();
                    std::mem::drop(state);
                    if new_posdao_epoch != old_posdao_epoch {
                        info!(target: "consensus", "POSDAO epoch changed from {old_posdao_epoch} to {new_posdao_epoch}.");
                        if let Some(block_number) = client.block_number(BlockId::Hash(*block_hash))
                        {
                            self.hbbft_message_dispatcher
                                .report_new_epoch(new_posdao_epoch, block_number);
                        } else {
                            error!(target: "engine", "could not retrieve Block on_chain_commit for updating message memoriumaupdate honey badger after importing block {block_hash}: update honeybadger failed")
                        }
                    }
                }
                None => {
                    error!(target: "engine", "could not update honey badger after importing block {block_hash}: update honeybadger failed")
                }
            }
        } else {
            error!(target: "engine", "could not update honey badger after importing the block {block_hash}: no client");
        }
    }

    /// hbbft protects the start of the current posdao epoch start from being pruned.
    fn pruning_protection_block_number(&self) -> Option<u64> {
        // we try to get a read lock for 500 ms.
        // that is a very long duration, but the information is important.
        if let Some(hbbft_state_lock) = self.hbbft_state.try_read_for(Duration::from_millis(500)) {
            if let Some(last_epoch_start_block) =
                hbbft_state_lock.get_last_posdao_epoch_start_block()
            {
                return Some(last_epoch_start_block);
            }
            return Some(hbbft_state_lock.get_current_posdao_epoch_start_block());
        } else {
            // better a potential stage 3 verification error instead of a deadlock ?!
            // https://github.com/DMDcoin/diamond-node/issues/68
            warn!(target: "engine", "could not aquire read lock for retrieving the pruning_protection_block_number. Stage 3 verification error might follow up.");
            return None;
        }
    }

    // note: this is by design not part of the PrometheusMetrics trait,
    // it is part of the Engine trait and does nothing by default.
    fn prometheus_metrics(&self, registry: &mut stats::PrometheusRegistry) {
        let is_staked = self.is_staked();

        registry.register_gauge(
            "hbbft_is_staked",
            "Is the signer of the hbbft engine staked.",
            is_staked as i64,
        );

        self.hbbft_message_dispatcher.prometheus_metrics(registry);
        if let Some(early_epoch_manager_option) = self
            .early_epoch_manager
            .try_lock_for(Duration::from_millis(250))
        {
            if let Some(early_epoch_manager) = early_epoch_manager_option.as_ref() {
                early_epoch_manager.prometheus_metrics(registry);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{contribution::Contribution, test::create_transactions::create_transaction};
    use crate::types::transaction::SignedTransaction;
    use crypto::publickey::{Generator, Random};
    use ethereum_types::U256;
    use hbbft::{
        NetworkInfo,
        honey_badger::{HoneyBadger, HoneyBadgerBuilder},
    };
    use rand;
    use std::sync::Arc;

    #[test]
    fn test_single_contribution() {
        let mut rng = rand::thread_rng();
        let net_infos = NetworkInfo::generate_map(0..1usize, &mut rng)
            .expect("NetworkInfo generation is expected to always succeed");

        let net_info = net_infos
            .get(&0)
            .expect("A NetworkInfo must exist for node 0");

        let mut builder: HoneyBadgerBuilder<Contribution, _> =
            HoneyBadger::builder(Arc::new(net_info.clone()));

        let mut honey_badger = builder.build();

        let mut pending: Vec<SignedTransaction> = Vec::new();
        let keypair = Random.generate();
        pending.push(create_transaction(&keypair, &U256::from(1)));
        let input_contribution = Contribution::new(&pending);

        let step = honey_badger
            .propose(&input_contribution, &mut rng)
            .expect("Since there is only one validator we expect an immediate result");

        // Assure the contribution returned by HoneyBadger matches the input
        assert_eq!(step.output.len(), 1);
        let out = step.output.first().unwrap();
        assert_eq!(out.epoch, 0);
        assert_eq!(out.contributions.len(), 1);
        assert_eq!(out.contributions.get(&0).unwrap(), &input_contribution);
    }
}
