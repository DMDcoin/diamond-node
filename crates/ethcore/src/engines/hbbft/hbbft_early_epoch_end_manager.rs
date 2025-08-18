use crate::types::ids::BlockId;
use ethereum_types::Address;
use stats::PrometheusMetrics;

use crate::{
    client::{BlockChainClient, EngineClient},
    engines::hbbft::contracts::connectivity_tracker_hbbft::report_missing_connectivity,
    ethereum::public_key_to_address::public_key_to_address,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use super::{
    NodeId,
    contracts::connectivity_tracker_hbbft::{is_connectivity_loss_reported, report_reconnect},
    hbbft_message_memorium::HbbftMessageMemorium,
};

pub(crate) struct HbbftEarlyEpochEndManager {
    /// The current epoch number.
    current_tracked_epoch_number: u64,

    /// epoch manager start up time.
    start_time: Instant,

    start_block: u64,

    /// allowed devp2p warmup time.
    allowed_devp2p_warmup_time: Duration,

    /// public keys of all validators for this epoch.
    validators: Vec<NodeId>,

    /// current flagged validators, unordered list - no performance issue, since this can
    /// only grow up to 7 elements for a usual set of 25 nodes.
    flagged_validators: Vec<NodeId>,

    node_id_to_address: BTreeMap<NodeId, Address>,

    // address_to_node_id: BTreeMap<Address, NodeId>,
    signing_address: Address,
}

impl HbbftEarlyEpochEndManager {
    /// creates a new EarlyEpochEndManager,
    /// if conditions are matching to create one.
    /// It is expected that this function is only called if the node is a validator.
    /// This prerequesite will be checked and if not met, panics.
    pub fn create_early_epoch_end_manager(
        allowed_devp2p_warmup_time: Duration,
        client: &dyn BlockChainClient,
        engine_client: &dyn EngineClient,
        epoch_number: u64,
        epoch_start_block: u64,
        validator_set: Vec<NodeId>,
        signing_address: &Address,
    ) -> Option<HbbftEarlyEpochEndManager> {
        if client.is_syncing() {
            // if we are syncing, we do not need to create an early epoch end manager yet.
            // if we are syncing as a validator, and it is really this epoch,
            // this way the creation of the early epoch end manager is created in a subsequent call,
            // when we are at the tip of the chain, and get the correct state for
            // - flagged validators
            // - start_time
            // The whole window for the devp2p warmup time is granted in this case,
            // therefore this node won't flag anyone in the near future.
            return None;
        }

        let mut node_id_to_address: BTreeMap<NodeId, Address> = BTreeMap::new();
        let mut address_to_node_id: BTreeMap<Address, NodeId> = BTreeMap::new();

        let mut validators: Vec<NodeId> = Vec::new();

        for validator in validator_set.iter() {
            let address = public_key_to_address(&validator.0);
            node_id_to_address.insert(validator.clone(), address);
            address_to_node_id.insert(address, validator.clone());

            if address == *signing_address {
                continue;
            }

            validators.push(validator.clone());
        }

        // figure out if we have to retrieve the data from the smart contracts.
        // if the epoch start did just happen,
        // we do not have to retrieve the data from the smart contracts.
        let now = Instant::now();

        let flagged_validators = Self::get_current_reported_validators_from_contracts(
            engine_client,
            BlockId::Latest,
            &node_id_to_address,
            &validators,
            signing_address,
            epoch_number,
        );

        let result = Self {
            current_tracked_epoch_number: epoch_number,
            start_time: now,
            start_block: epoch_start_block,
            allowed_devp2p_warmup_time,
            validators: validators,
            flagged_validators: flagged_validators,
            node_id_to_address,
            // address_to_node_id,
            signing_address: signing_address.clone(),
        };

        info!(target: "engine", "early-epoch-end: HbbftEarlyEpochEndManager created. start_time {now:?}, start_block: {epoch_start_block}");

        return Some(result);
    }

    /// retrieves the information from smart contracts which validators are currently flagged.
    fn get_current_reported_validators_from_contracts(
        client: &dyn EngineClient,
        block_id: BlockId,
        node_id_to_address: &BTreeMap<NodeId, Address>,
        validators: &Vec<NodeId>,
        signing_address: &Address,
        epoch: u64,
    ) -> Vec<NodeId> {
        let mut result = Vec::<NodeId>::new();

        for validator in validators.iter() {
            let validator_address = if let Some(a) = node_id_to_address.get(validator) {
                a
            } else {
                error!(target: "engine", "early-epoch-end: could not find address for validator in node_id_to_address cache.");
                continue;
            };

            match is_connectivity_loss_reported(
                client,
                block_id,
                signing_address,
                epoch,
                validator_address,
            ) {
                Ok(reported) => {
                    if reported {
                        result.push(validator.clone());
                    }
                }
                Err(e) => {
                    error!(target: "engine", "early-epoch-end: could not get reported status for validator {validator:?}. call error: {e:?}");
                }
            }
        }

        return result;
        // match is_connectivity_loss_reported(client, block_id, signing_address, ) {

        // }

        // match get_current_flagged_validators_from_contract(client, block_id) {
        //     Ok(v) => {
        //         let mut result: Vec<NodeId> = Vec::new();

        //         for a in v.iter() {
        //             if let Some(node_id) = address_to_node_id.get(a) {
        //                 result.push(node_id.clone());
        //             } else {
        //                 error!(target: "engine","early-epoch-end: could not find validator in address cache: {a:?}");
        //             }
        //         }

        //         return result;
        //         // address_to_node_id.get(key)
        //     }
        //     Err(e) => {
        //         error!(target: "engine","early-epoch-end: could not get_current_flagged_validators_from_contracts {e:?}" );
        //         Vec::new()
        //     }
        // }
    }

    fn notify_about_missing_validator(
        &mut self,
        validator: &NodeId,
        client: &dyn EngineClient,
        full_client: &dyn BlockChainClient,
    ) {
        if let Some(validator_address) = self.node_id_to_address.get(validator) {
            if report_missing_connectivity(
                client,
                full_client,
                validator_address,
                &self.signing_address,
            ) {
                if !self.flagged_validators.contains(&validator) {
                    // in this case, we already had this validator in the list,
                    // what means that the transaction previous send was not successful.
                    // we could here do some improvements to not spam to many disconnect reports into the system.
                    self.flagged_validators.push(validator.clone());
                }
            }
        } else {
            warn!("Could not find validator_address for node id in cache: {validator:?}");
            return;
        }
    }

    fn notify_about_validator_reconnect(
        &mut self,
        validator: &NodeId,
        full_client: &dyn BlockChainClient,
        engine_client: &dyn EngineClient,
    ) {
        let index = if let Some(index) = self.flagged_validators.iter().position(|x| x == validator)
        {
            index
        } else {
            error!(target: "engine", "early-epoch-end: notify_about_validator_reconnect Could not find reconnected validator in flagged validators.");
            return;
        };

        if let Some(validator_address) = self.node_id_to_address.get(validator) {
            if report_reconnect(
                engine_client,
                full_client,
                validator_address,
                &self.signing_address,
            ) {
                // Todo: we do not know if the transaction will get processed successful.
                // shall we track transactions ?
                self.flagged_validators.remove(index);
            }
        } else {
            warn!("Could not find validator_address for node id in cache: {validator:?}");
            return;
        }
    }

    pub fn is_reported(
        &self,
        client: &dyn EngineClient,
        other_validator_address: &Address,
    ) -> bool {
        // todo: for performance improvements, we could apply caching here,
        // once we are up to date with the contract information and track the inclusion of our own reports.
        let result = is_connectivity_loss_reported(
            client,
            BlockId::Latest,
            &self.signing_address,
            self.current_tracked_epoch_number,
            other_validator_address,
        );

        if let Ok(r) = result {
            return r;
        } else {
            error!(target: "engine", "early-epoch-end: could not get reported status for validator {other_validator_address:?}");
            return false;
        }
    }

    /// decides on the memorium data if we should update to contract data.
    /// end executes them.
    pub fn decide(
        &mut self,
        memorium: &HbbftMessageMemorium,
        full_client: &dyn BlockChainClient,
        client: &dyn EngineClient,
    ) {
        // if devp2p warmup time is not over yet, we do not have to do anything.
        if self.start_time.elapsed() < self.allowed_devp2p_warmup_time {
            debug!(target: "engine", "early-epoch-end: no decision: Devp2p warmup time");
            return;
        }

        if full_client.is_major_syncing() {
            // if we are syncing, we wont do any blaming.
            debug!(target: "engine", "early-epoch-end: no decision: syncing");
            return;
        }

        if full_client.is_syncing() {
            // if we are syncing, we wont do any blaming.
            debug!(target: "engine", "early-epoch-end: detected attempt to break because of is_major_syncing() instead of is_synincg()no decision: syncing");
        }

        let block_num = if let Some(block) = full_client.block(BlockId::Latest) {
            block.number()
        } else {
            error!(target:"engine", "early-epoch-end: could not retrieve latest block.");
            return;
        };

        let treshold: u64 = 2;
        // todo: read this out from contracts: ConnectivityTrackerHbbft -> reportDisallowPeriod
        // requires us to update the Contracts ABIs:
        // https://github.com/DMDcoin/diamond-node/issues/115
        let treshold_time = Duration::from_secs(12 * 60); // 12 Minutes = 1 times the heartbeat + 2 minutes as grace period.

        if self.start_time.elapsed() < treshold_time {
            debug!(target: "engine", "early-epoch-end: no decision: Treshold time not reached.");
            return;
        }

        if block_num < self.start_block + treshold {
            // not enought blocks have passed this epoch,
            // to judge other nodes.
            debug!(target: "engine", "early-epoch-end: no decision: not enough blocks.");
            return;
        }

        trace!(target: "engine", "checking epoch history for {}  validators", &self.validators.len());

        //full_client.best_block_header()
        // get current state of missing validators from hbbftMemorium.
        if let Some(epoch_history) = memorium.get_staking_epoch_history(block_num) {
            for validator in &self.validators.clone() {
                let validator_address = match self.node_id_to_address.get(validator) {
                    Some(a) => a,
                    None => {
                        error!(target: "engine", "early-epoch-end: could not find validator_address for node id in cache: {validator:?}");
                        continue;
                    }
                };

                if let Some(node_history) = epoch_history.get_history_for_node(validator) {
                    let last_message_time = node_history.get_last_good_message_time();
                    let last_message_time_lateness = last_message_time.elapsed();
                    if last_message_time_lateness > treshold_time {
                        // we do not have to send notification, if we already did so.
                        if !self.is_reported(client, validator_address) {
                            // this function will also add the validator to the list of flagged validators.
                            self.notify_about_missing_validator(&validator, client, full_client);
                        }
                    } else {
                        // this validator is OK.
                        // maybe it was flagged and we need to unflag it ?
                        if self.is_reported(client, validator_address) {
                            self.notify_about_validator_reconnect(&validator, full_client, client);
                        }
                    }
                } else {
                    debug!(target: "engine", "early-epoch-end: no history info for validator {validator}");

                    // we do not have any history for this node.
                    if !self.is_reported(client, validator_address) {
                        // this function will also add the validator to the list of flagged validators.
                        self.notify_about_missing_validator(&validator, client, full_client);
                    }
                }
                // todo: if the systems switched from block based measurement to time based measurement.
            }
        }
        // else: nothing to do: no history yet.

        // note: We do not take care if hbbft message memorium might not have processed some of the messages yet,
        // since it is not important to do the decision based on the latest data, since the decide method will be called
        // again.
    }
}

impl PrometheusMetrics for HbbftEarlyEpochEndManager {
    fn prometheus_metrics(&self, registry: &mut stats::PrometheusRegistry) {
        registry.register_gauge(
            "early_epoch_end_staking_epoch",
            "staking epoch information for early epoch end manager",
            self.current_tracked_epoch_number as i64,
        );

        registry.register_gauge(
            "early_epoch_end_num_flagged_validators",
            "number of validators flagged for missing communication",
            self.flagged_validators.len() as i64,
        );

        for v in self.validators.iter() {
            let is_flagged = self.flagged_validators.contains(v);
            let label_value = v.as_8_byte_string();
            registry.register_gauge_with_other_node_label(
                "early_epoch_end_flag",
                "node has flagged other_node [0-1]",
                label_value.as_str(),
                is_flagged as i64,
            );
        }
    }
}
/// testing early epoch stop manager.
#[cfg(test)]
mod tests {

    #[test]
    fn test_early_epoch_end() {

        // should
    }
}
