use crate::{
    client::traits::EngineClient,
    engines::signer::EngineSigner,
    types::{header::Header, ids::BlockId},
};
use ethcore_miner::pool::{PoolVerifiedTransaction, ScoredTransaction};
use ethereum_types::U256;
use ethjson::spec::hbbft::HbbftNetworkFork;
use hbbft::{
    Epoched, NetworkInfo,
    crypto::{PublicKey, Signature},
    honey_badger::{self, HoneyBadgerBuilder},
};
use parking_lot::{Mutex, RwLock};
use rand::seq::IteratorRandom;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

use crate::engines::hbbft::contracts::permission::get_minimum_gas_from_permission_contract;

use super::{
    NodeId,
    contracts::{
        keygen_history::{initialize_synckeygen, synckeygen_to_network_info},
        staking::{get_posdao_epoch, get_posdao_epoch_start},
        validator_set::ValidatorType,
    },
    contribution::Contribution,
    hbbft_early_epoch_end_manager::HbbftEarlyEpochEndManager,
    hbbft_network_fork_manager::HbbftNetworkForkManager,
    hbbft_peers_management::HbbftPeersManagement,
};

pub type HbMessage = honey_badger::Message<NodeId>;
pub(crate) type HoneyBadger = honey_badger::HoneyBadger<Contribution, NodeId>;
pub(crate) type Batch = honey_badger::Batch<Contribution, NodeId>;
pub(crate) type HoneyBadgerStep = honey_badger::Step<Contribution, NodeId>;
pub(crate) type HoneyBadgerResult = honey_badger::Result<HoneyBadgerStep>;

pub(crate) struct HbbftState {
    network_info: Option<NetworkInfo<NodeId>>,
    honey_badger: Option<HoneyBadger>,
    public_master_key: Option<PublicKey>,
    historic_public_keys: BTreeMap<u64, PublicKey>,
    current_posdao_epoch: u64,
    current_posdao_epoch_start_block: u64,
    last_fork_start_block: Option<u64>,
    last_posdao_epoch_start_block: Option<u64>,
    future_messages_cache: BTreeMap<u64, Vec<(NodeId, HbMessage)>>,
    fork_manager: HbbftNetworkForkManager,
}

impl HbbftState {
    pub fn new() -> Self {
        HbbftState {
            network_info: None,
            honey_badger: None,
            public_master_key: None,
            historic_public_keys: BTreeMap::new(),
            current_posdao_epoch: 0,
            current_posdao_epoch_start_block: 0,
            last_posdao_epoch_start_block: None,
            last_fork_start_block: None,
            future_messages_cache: BTreeMap::new(),
            fork_manager: HbbftNetworkForkManager::new(),
        }
    }

    fn new_honey_badger(&self, network_info: NetworkInfo<NodeId>) -> Option<HoneyBadger> {
        let mut builder: HoneyBadgerBuilder<Contribution, _> =
            HoneyBadger::builder(Arc::new(network_info));
        return Some(builder.build());
    }

    pub fn init_fork_manager(
        &mut self,
        own_id: NodeId,
        latest_block: u64,
        fork_definition: Vec<HbbftNetworkFork>,
    ) {
        self.fork_manager
            .initialize(own_id, latest_block, fork_definition);
    }

    /**
     * Updates the underlying honeybadger instance, possible switching into a new
     * honeybadger instance if according to contracts a new staking epoch has started.
     * true if a new epoch has started and a new honeybadger instance has been created
     */
    pub fn update_honeybadger(
        &mut self,
        client: Arc<dyn EngineClient>,
        signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
        peers_management_mutex: &Mutex<HbbftPeersManagement>,
        early_epoch_end_manager_mutex: &Mutex<Option<HbbftEarlyEpochEndManager>>,
        current_minimum_gas_price: &Mutex<Option<U256>>,
        block_id: BlockId,
        force: bool,
    ) -> Option<()> {
        let target_posdao_epoch: u64;
        match get_posdao_epoch(&*client, block_id) {
            Ok(value) => target_posdao_epoch = value.low_u64(),
            Err(error) => {
                error!(target: "engine", "error calling get_posdao_epoch for block {:?}: {:?}", block_id, error);
                return None;
            }
        }

        // https://github.com/DMDcoin/diamond-node/issues/98
        // check here if we are in a fork scenario.
        // in a fork scenario, the new honeybadger keys will come from the config,
        // and not from the contracts.
        // also the current block will trigger the epoch end,
        // this will start the loop for finding a new validator set,
        // probably it will fail multiple times,
        // because nodes that do not apply to the fork rule will drop out.
        // this might happen for a lot of key-gen rounds, until a set with responsive validators
        // can be found.

        if let Some(last_block_number) = client.block_number(block_id) {
            if let Some(network_info) = self.fork_manager.should_fork(
                last_block_number,
                self.current_posdao_epoch,
                signer.clone(),
            ) {
                info!(target: "engine", "Forking at block {last_block_number}, starting new honeybadger instance with new validator set.");

                for id in network_info.validator_set().all_ids() {
                    info!(target: "engine", "Fork Validator: {}", id);
                }

                self.public_master_key = Some(network_info.public_key_set().public_key());
                self.honey_badger = Some(self.new_honey_badger(network_info.clone())?);

                self.historic_public_keys
                    .insert(target_posdao_epoch, self.public_master_key.unwrap().clone());

                for x in network_info.validator_set().all_ids() {
                    info!(target: "engine", "Validator: {:?}", x);
                }

                self.network_info = Some(network_info);
                self.last_fork_start_block = Some(last_block_number);
                self.current_posdao_epoch_start_block = last_block_number;

                return Some(());
            }
        } else {
            error!(target: "engine", "fork: could not get block number for block_id: {:?}", block_id);
        }
        //

        if !force && self.current_posdao_epoch == target_posdao_epoch {
            // hbbft state is already up to date.
            // @todo Return proper error codes.
            return Some(());
        }

        let posdao_epoch_start = get_posdao_epoch_start(&*client, block_id).ok()?;
        let synckeygen = match initialize_synckeygen(
            &*client,
            signer,
            BlockId::Number(posdao_epoch_start.low_u64()),
            ValidatorType::Current,
        ) {
            Ok(synckey) => synckey,
            Err(e) => {
                error!(target: "engine", "error initializing synckeygen for block: {:?}: {:?}", block_id, e);
                return None;
            }
        };

        if !synckeygen.is_ready() {
            error!(target: "engine", "Synckeygen not ready when it should be!");
            return None;
        }

        let (pks, sks) = synckeygen.generate().ok()?;
        self.public_master_key = Some(pks.public_key());
        self.historic_public_keys
            .insert(target_posdao_epoch, pks.public_key());
        // Clear network info and honey badger instance, since we may not be in this POSDAO epoch any more.
        info!(target: "engine", "public master key: {:?}", pks.public_key());

        self.network_info = None;
        self.honey_badger = None;
        // Set the current POSDAO epoch #
        self.current_posdao_epoch = target_posdao_epoch;
        self.last_posdao_epoch_start_block = Some(self.current_posdao_epoch_start_block);
        self.current_posdao_epoch_start_block = posdao_epoch_start.as_u64();

        trace!(target: "engine", "Switched hbbft state to epoch {}.", self.current_posdao_epoch);

        // apply DAO updates here.
        // update the current minimum gas price.

        match get_minimum_gas_from_permission_contract(
            client.as_ref(),
            BlockId::Number(self.current_posdao_epoch_start_block),
        ) {
            Ok(min_gas) => {
                *current_minimum_gas_price.lock() = Some(min_gas);
            }
            Err(err) => {
                warn!(target: "engine", "Could not read min gas from hbbft permission contract.  {:?}.", err);
            }
        }

        if sks.is_none() {
            info!(target: "engine", "We are not part of the HoneyBadger validator set - running as regular node.");
            // we can disconnect the peers here.
            if let Some(mut peers_management) =
                peers_management_mutex.try_lock_for(std::time::Duration::from_millis(50))
            {
                peers_management.disconnect_all_validators(&client);
            }
            return Some(());
        }

        let network_info = synckeygen_to_network_info(&synckeygen, pks, sks)?;
        self.network_info = Some(network_info.clone());
        self.honey_badger = Some(self.new_honey_badger(network_info.clone())?);

        info!(target: "engine", "HoneyBadger Algorithm initialized! Running as validator node.");

        // this is importent, but we should not risk deadlocks...
        // maybe we should refactor this to a message Queue system, and pass a "connect_to_current_validators" message
        if let Some(mut peers_management) =
            peers_management_mutex.try_lock_for(std::time::Duration::from_millis(250))
        {
            peers_management.connect_to_current_validators(&self.get_validator_set(), &client);
        } else {
            // maybe we should work with signals that signals that connect_to_current_validators should happen
            // instead of trying to achieve a lock here.
            // in this case:
            // if Node A cannot acquire the lock, but Node B can, then Node B connects to Node A,
            // and we are find.
            // if both nodes cannot acquire the lock, then we are busted.
            warn!(target: "engine", "could not acquire to connect to current validators on switching to new validator set for staking epoch {}.", self.current_posdao_epoch);
        }

        let allowed_devp2p_warmup_time = Duration::from_secs(1200);

        if let Some(full_client) = client.as_full_client() {
            let signing_address = if let Some(s) = signer.read().as_ref() {
                s.address()
            } else {
                error!(target: "engine", "early epoch manager: signer is not set!");
                ethereum_types::Address::zero()
            };

            *early_epoch_end_manager_mutex.lock() =
                HbbftEarlyEpochEndManager::create_early_epoch_end_manager(
                    allowed_devp2p_warmup_time,
                    full_client,
                    client.as_ref(),
                    self.current_posdao_epoch,
                    self.current_posdao_epoch_start_block,
                    self.get_validator_set(),
                    &signing_address,
                );
        }

        Some(())
    }

    // Call periodically to assure cached messages will eventually be delivered.
    pub fn replay_cached_messages(
        &mut self,
        client: Arc<dyn EngineClient>,
    ) -> Option<(Vec<HoneyBadgerResult>, NetworkInfo<NodeId>)> {
        let honey_badger = self.honey_badger.as_mut()?;

        if honey_badger.epoch() == 0 {
            // honey_badger not initialized yet, wait to be called after initialization.
            return None;
        }

        // Caveat:
        // If all necessary honey badger processing for an hbbft epoch is done the HoneyBadger
        // implementation automatically jumps to the next hbbft epoch.
        // This means hbbft may already be on the next epoch while the current epoch/block is not
        // imported yet.
        // The Validator Set may actually change, so we do not know to whom to send these messages yet.
        // We have to attempt to switch to the newest block, and then check if the hbbft epoch's parent
        // block is already imported. If not we have to wait until that block is available.
        let parent_block = honey_badger.epoch() - 1;
        match get_posdao_epoch(&*client, BlockId::Number(parent_block)) {
            Ok(epoch) => {
                if epoch.low_u64() != self.current_posdao_epoch {
                    trace!(target: "engine", "replay_cached_messages: Parent block(#{}) imported, but hbbft state not updated yet, re-trying later.", parent_block);
                    return None;
                }
            }
            Err(e) => {
                trace!(target: "engine", "replay_cached_messages: Could not query posdao epoch at parent block#{}, re-trying later. Probably due to the block not being imported yet. {:?}", parent_block, e);
                return None;
            }
        }

        let messages = self.future_messages_cache.get(&honey_badger.epoch())?;
        if messages.is_empty() {
            return None;
        }

        let network_info = self.network_info.as_ref()?.clone();

        let all_steps: Vec<_> = messages
			.iter()
			.map(|m| {
				trace!(target: "engine", "Replaying cached consensus message {:?} from {}", m.1, m.0);
				honey_badger.handle_message(&m.0, m.1.clone())
			})
			.collect();

        // Delete current epoch and all previous messages
        self.future_messages_cache = self
            .future_messages_cache
            .split_off(&(honey_badger.epoch() + 1));

        Some((all_steps, network_info))
    }

    fn skip_to_current_epoch(
        &mut self,
        client: Arc<dyn EngineClient>,
        _signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
    ) -> Option<()> {
        // Ensure we evaluate at the same block # in the entire upward call graph to avoid inconsistent state.
        let latest_block_number = client.block_number(BlockId::Latest)?;

        // Update honey_badger *before* trying to use it to make sure we use the data
        // structures matching the current epoch.

        // we asume that honey badger instance is up to date here.
        // it has to be updated after closing each block.

        // If honey_badger is None we are not a validator, nothing to do.
        let honey_badger = self.honey_badger.as_mut()?;

        let next_block = latest_block_number + 1;
        // if next_block != honey_badger.epoch() {
        //trace!(target: "consensus", "Skipping honey_badger forward to epoch(block) {}, was at epoch(block) {}.", next_block, honey_badger.epoch());
        // }
        honey_badger.skip_to_epoch(next_block);

        Some(())
    }

    pub fn process_message(
        &mut self,
        client: Arc<dyn EngineClient>,
        signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
        sender_id: NodeId,
        message: HbMessage,
    ) -> Result<Option<(HoneyBadgerStep, NetworkInfo<NodeId>)>, honey_badger::Error> {
        match self.skip_to_current_epoch(client, signer) {
            Some(_) => (),
            None => return Ok(None),
        }

        // If honey_badger is None we are not a validator, nothing to do.
        let honey_badger = match self.honey_badger.as_mut() {
            Some(hb) => hb,
            None => return Ok(None),
        };

        let message_epoch = message.epoch();
        let hb_epoch = honey_badger.epoch();
        // Note that if the message is for a future epoch we do not know if the current honey_badger
        // instance is the correct one to use. Tt may change if the the POSDAO epoch changes, causing
        // consensus messages to get lost.
        if message_epoch > hb_epoch {
            trace!(target: "consensus", "Message from future epoch, caching it for handling it in when the epoch is current. Current hbbft epoch is: {}", honey_badger.epoch());
            self.future_messages_cache
                .entry(message.epoch())
                .or_default()
                .push((sender_id, message));
            return Ok(None);
        }

        match self.network_info.as_ref() {
            Some(network_info) => {
                match honey_badger.handle_message(&sender_id, message) {
                    Ok(step) => return Ok(Some((step, network_info.clone()))),
                    Err(err) => {
                        // the sender is possible not in the hbbft set anymore
                        // and can ignore this error and not process a step.
                        let epoch = message_epoch;
                        if epoch < self.current_posdao_epoch_start_block {
                            return Ok(None);
                        }

                        error!(target: "consensus", "Error on handling HoneyBadger message from {} in epoch {} error: {:?}", sender_id, message_epoch, err);
                        return Err(err);
                    }
                }
            }
            None => {
                // We are not a validator, but we still need to handle the message to keep the
                // network in sync.
                // honey_badger.handle_message(&sender_id, message);
                warn!(target: "consensus", "Message from node {} for block {} received - but no network info available.: current Block: {}", sender_id.0, message_epoch, hb_epoch);
                return Ok(None);
            }
        }
    }

    pub fn contribute_if_contribution_threshold_reached(
        &mut self,
        client: Arc<dyn EngineClient>,
        signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
    ) -> Option<(HoneyBadgerStep, NetworkInfo<NodeId>)> {
        // If honey_badger is None we are not a validator, nothing to do.
        let honey_badger = self.honey_badger.as_mut()?;
        let network_info = self.network_info.as_ref()?;

        if honey_badger.received_proposals() > network_info.num_faulty() {
            return self.try_send_contribution(client, signer);
        }
        None
    }

    pub fn try_send_contribution(
        &mut self,
        client: Arc<dyn EngineClient>,
        signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
    ) -> Option<(HoneyBadgerStep, NetworkInfo<NodeId>)> {
        // Make sure we are in the most current epoch.
        self.skip_to_current_epoch(client.clone(), signer)?;

        let honey_badger = self.honey_badger.as_mut()?;

        // If we already sent a contribution for this epoch, there is nothing to do.
        if honey_badger.has_input() {
            return None;
        }

        if let Some(latest_block) = client.block_number(BlockId::Latest) {
            if honey_badger.epoch() != latest_block + 1 {
                debug!(target: "consensus", "Detected an attempt to send a hbbft contribution for block {} before the previous block was imported to the chain.", honey_badger.epoch());
                return None;
            }
        }

        // If the parent block of the block we would contribute to is not in the hbbft state's
        // epoch we cannot start to contribute, since we would write into a hbbft instance
        // which will be destroyed.
        let posdao_epoch = get_posdao_epoch(&*client, BlockId::Number(honey_badger.epoch() - 1))
            .ok()?
            .low_u64();
        if self.current_posdao_epoch != posdao_epoch {
            trace!(target: "consensus", "hbbft_state epoch mismatch: hbbft_state epoch is {}, honey badger instance epoch is: {}.",
				   self.current_posdao_epoch, posdao_epoch);
            return None;
        }

        let network_info = self.network_info.as_ref()?.clone();

        // Choose a random subset of the maximum transactions, but at least 1.
        // Since not all nodes may contribute we do not use the full number of nodes
        // but the minimum number of nodes required to build a block.

        // We cannot be sure that all active validators contribute to the block, in the worst
        // case only 2/3 of the validators will contribute.
        // Therefore we need to divide the maximum size of the transactions available for the block
        // by 2/3 of the validators.
        // The "num_correct" function of the hbbft network info returns the minimum amount of
        // validators needed to create a block (which is 2/3 of the total active validators).
        let min_required_nodes = (network_info.num_correct() / 2) + 1;
        let max_transactions_for_block = client.queued_transactions();
        let transactions_subset_size = (max_transactions_for_block.len() / min_required_nodes) + 4;

        // Since every transaction sender can send multiple transactions we need to make sure
        // not to create nonce gaps. To avoid these gaps we randomly select senders instead of
        // transaction. For every chosen sender *all* transactions are added to our contribution
        // until the target contribution size is reached.

        // As a first step we create a map sorting the transactions by sender.
        let mut transactions_by_sender = HashMap::new();
        for t in &max_transactions_for_block {
            transactions_by_sender
                .entry(t.sender().clone())
                .or_insert_with(Vec::new)
                .push(t.clone());
        }

        // Randomly select a sender and add all their transactions
        // until we at least reached the target contribution size.
        let mut transactions_subset = Vec::new();
        let mut my_rng = rand::thread_rng();

        let full_client = if let Some(full_client) = client.as_full_client() {
            full_client
        } else {
            error!(target: "consensus", "Contribution creation: Full client could not be obtained.");
            return None;
        };

        while transactions_subset.len() < transactions_subset_size {
            let chosen_key = match transactions_by_sender.keys().choose(&mut my_rng) {
                None => break,
                Some(key) => key.clone(),
            };
            // add all transactions for that sender and delete the sender from the map.
            if let Some(ts) = transactions_by_sender.remove(&chosen_key) {
                // Even after block import there may still be transactions in the pending set which already
                // have been included on the chain. We filter out transactions where the nonce is too low.
                let min_nonce = full_client.latest_nonce(&chosen_key);
                for tx in ts {
                    if tx.nonce() >= min_nonce {
                        transactions_subset.push(tx);
                    } else {
                        debug!(target: "consensus", "Block creation: Pending transaction with nonce too low, got {}, expected at least {}", tx.nonce(), min_nonce);
                    }
                }
            }
        }

        trace!(target: "consensus", "Block creation: Honeybadger epoch {}, Transactions subset target size: {}, actual size: {}, from available {}.", honey_badger.epoch(), transactions_subset_size, transactions_subset.len(), max_transactions_for_block.len());

        let signed_transactions = transactions_subset
            .iter()
            .map(|txn| txn.signed().clone())
            .collect();

        // Now we can select the transactions to include in our contribution.
        let input_contribution = Contribution::new(&signed_transactions);

        let mut rng = rand::thread_rng();
        let step = honey_badger.propose(&input_contribution, &mut rng);
        match step {
            Ok(step) => Some((step, network_info)),
            _ => {
                // TODO: Report detailed consensus step errors
                error!(target: "consensus", "Error on proposing Contribution.");
                None
            }
        }
    }

    pub fn verify_seal(
        &mut self,
        client: Arc<dyn EngineClient>,
        signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
        signature: &Signature,
        header: &Header,
    ) -> bool {
        // maybe add the option: "not ready yet ?!"

        self.skip_to_current_epoch(client.clone(), signer);

        // Check if posdao epoch fits the parent block of the header seal to verify.
        let parent_block_nr = header.number() - 1;
        let target_posdao_epoch = match get_posdao_epoch(&*client, BlockId::Number(parent_block_nr))
        {
            Ok(number) => number.low_u64(),
            Err(e) => {
                error!(target: "consensus", "Failed to verify seal - reading POSDAO epoch from contract failed! Error: {:?}", e);
                return false;
            }
        };

        if self.current_posdao_epoch > target_posdao_epoch {
            trace!(target: "consensus", "verify_seal - hbbft state epoch does not match epoch at the header's parent, attempting to reconstruct the appropriate public key share from scratch.");

            match self.historic_public_keys.get(&target_posdao_epoch) {
                Some(key) => {
                    if key.verify(signature, header.bare_hash()) {
                        return true;
                    } else {
                        error!(target: "consensus", "Failed to verify seal - historic public key verification failed!");
                        return false;
                    }
                }
                None => {
                    warn!(target: "consensus", "unable to verifiy seal for historic block, public key not available.");
                    return false;
                }
            }
        } else {
            // not a historic block, we can use the current public key.
            match self.public_master_key {
                Some(key) => key.verify(signature, header.bare_hash()),
                None => {
                    error!(target: "consensus", "Failed to verify seal - public master key not available!");
                    false
                }
            }
        }
    }

    pub fn network_info_for(
        &mut self,
        client: Arc<dyn EngineClient>,
        signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
        block_nr: u64,
    ) -> Option<NetworkInfo<NodeId>> {
        self.skip_to_current_epoch(client.clone(), signer);

        let posdao_epoch = get_posdao_epoch(&*client, BlockId::Number(block_nr - 1))
            .ok()?
            .low_u64();

        if self.current_posdao_epoch != posdao_epoch {
            error!(target: "consensus", "Trying to get the network info from a different epoch. Current epoch: {}, Requested epoch: {}",
				   self.current_posdao_epoch, posdao_epoch);
            return None;
        }

        self.network_info.clone()
    }

    // pub fn get_current_network_info(&self) -> &Option<NetworkInfo<NodeId>> {
    //     return &self.network_info;
    // }

    pub fn is_validator(&self) -> bool {
        self.network_info.as_ref().is_some_and(|n| n.is_validator())
    }

    pub fn get_validator_set(&self) -> Vec<NodeId> {
        if let Some(network_info) = &self.network_info {
            let result: Vec<NodeId> = network_info
                .validator_set()
                .all_ids()
                .map(|n| n.clone())
                .collect();
            return result;
        }

        return Vec::new();
    }

    pub fn get_current_posdao_epoch(&self) -> u64 {
        self.current_posdao_epoch
    }

    pub fn get_current_posdao_epoch_start_block(&self) -> u64 {
        self.current_posdao_epoch_start_block
    }

    pub fn get_last_posdao_epoch_start_block(&self) -> Option<u64> {
        self.last_posdao_epoch_start_block
    }
}
