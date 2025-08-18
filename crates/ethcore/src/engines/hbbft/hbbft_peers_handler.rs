use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

use ethereum_types::Address;
use io::IoHandler;
use parking_lot::{Mutex, RwLock};

use crate::{
    client::EngineClient,
    engines::{EngineError, hbbft::contracts::validator_set::send_tx_announce_availability},
    error::Error,
};

use super::{
    NodeId,
    contracts::validator_set::{get_validator_available_since, staking_by_mining_address},
    hbbft_peers_management::HbbftPeersManagement,
};

#[derive(Debug)]
pub enum HbbftConnectToPeersMessage {
    SetSignerAddress(Address),
    ConnectToPendingPeers(Vec<Address>),
    ConnectToCurrentPeers(Vec<NodeId>),
    AnnounceOwnInternetAddress,
    AnnounceAvailability,
    DisconnectAllValidators,
}

/// IOChannel handler for doing hbbft peers management and hbbft service transactions async.
pub struct HbbftPeersHandler {
    peers_management: Mutex<HbbftPeersManagement>,
    client: Arc<RwLock<Option<Weak<dyn EngineClient>>>>,
    has_sent_availability_tx: AtomicBool,
    mining_address: Mutex<Address>,
}

impl HbbftPeersHandler {
    pub fn new(client: Arc<RwLock<Option<Weak<dyn EngineClient>>>>) -> Self {
        Self {
            peers_management: Mutex::new(HbbftPeersManagement::new()),
            client,
            has_sent_availability_tx: AtomicBool::new(false),
            mining_address: Mutex::new(Address::zero()), // Initialize with zero address, can be set later
        }
    }

    fn client_arc(&self) -> Result<Arc<dyn EngineClient>, Error> {
        return self
            .client
            .read()
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or(EngineError::RequiresClient.into());
    }

    fn get_mining_address(&self) -> Address {
        // Lock the mutex to safely access the mining address
        return self.mining_address.lock().clone();
    }

    fn announce_availability(&self) -> Result<(), Error> {
        if self.has_sent_availability_tx.load(Ordering::SeqCst) {
            return Ok(());
        }

        let mining_address = self.get_mining_address();

        if mining_address.is_zero() {
            error!(target: "engine", "Mining address is zero, cannot announce availability.");
            return Err(
                EngineError::SystemCallResultInvalid("Mining address is zero".to_string()).into(),
            );
        }

        let engine_client = self.client_arc()?;

        let block_chain_client = engine_client
            .as_full_client()
            .ok_or("BlockchainClient required")?;

        if block_chain_client.is_major_syncing() {
            return Ok(());
        }

        match get_validator_available_since(engine_client.as_ref(), &mining_address) {
            Ok(s) => {
                if s.is_zero() {
                    //debug!(target: "engine", "sending announce availability transaction");
                    info!(target: "engine", "sending announce availability transaction");
                    match send_tx_announce_availability(block_chain_client, &mining_address) {
                        Ok(()) => {}
                        Err(call_error) => {
                            error!(target: "engine", "CallError during announce availability. {:?}", call_error);
                            return Err(EngineError::SystemCallResultInvalid(
                                "CallError during announce availability".to_string(),
                            )
                            .into());
                        }
                    }
                }

                // we store "HAS_SENT" if we SEND,
                // or if we are already marked as available.
                self.has_sent_availability_tx.store(true, Ordering::SeqCst);
                //return Ok(());
                return Ok(());
            }
            Err(e) => {
                error!(target: "engine", "Error trying to send availability check: {:?}", e);
                return Err(EngineError::SystemCallResultInvalid(
                    "Error trying to send availability check".to_string(),
                )
                .into());
            }
        }
    }

    fn announce_own_internet_address(&self) -> Result<(), Error> {
        // todo:
        // if the network is unable to process this transaction,
        // we are keeping to announce out internet address.

        let mining_address = self.get_mining_address();

        if mining_address.is_zero() {
            error!(target: "engine", "Mining address is zero, will not announce own internet address.");
            return Err(
                EngineError::SystemCallResultInvalid("Mining address is zero".to_string()).into(),
            );
        }

        let engine_client = self.client_arc()?;

        // TODO:
        // staking by mining address could be cached.
        // but it COULD also get changed in the contracts, during the time the node is running.
        // most likely since a Node can get staked, and than it becomes a mining address.
        // a good solution for this is not to do this expensive operation that fequently.
        let staking_address = match staking_by_mining_address(
            engine_client.as_ref(),
            &mining_address,
        ) {
            Ok(staking_address) => {
                if staking_address.is_zero() {
                    //TODO: here some fine handling can improve performance.
                    //with this implementation every node (validator or not)
                    //needs to query this state every block.
                    //trace!(target: "engine", "availability handling not a validator");
                    return Ok(());
                }
                staking_address
            }
            Err(call_error) => {
                let message = format!(
                    "unable to ask for corresponding staking address for given mining address: {:?}",
                    call_error
                );
                error!(target: "engine", "{:?}", message);

                return Err(EngineError::SystemCallResultInvalid(message).into());
            }
        };

        let block_chain_client = engine_client
            .as_full_client()
            .ok_or("BlockchainClient required")?;

        if let Err(error) = self.peers_management.lock().announce_own_internet_address(
            block_chain_client,
            engine_client.as_ref(),
            &mining_address,
            &staking_address,
        ) {
            error!(target: "engine", "Error trying to announce own internet address: {:?}", error);
        }

        trace!(target: "engine", "Success: trying to announce own internet address for mining address: {:?}", mining_address);

        return Ok(());
    }

    fn handle_message(&self, message: &HbbftConnectToPeersMessage) -> Result<(), Error> {
        match message {
            HbbftConnectToPeersMessage::ConnectToPendingPeers(peers) => {
                match self
                    .peers_management
                    .lock()
                    .connect_to_pending_validators(&self.client_arc()?, peers)
                {
                    Ok(value) => {
                        if value > 0 {
                            debug!(target: "engine", "Added {:?} reserved peers because they are pending validators.", value);
                        }
                        return Ok(());
                    }
                    Err(err) => {
                        return Err(format!(
                            "Error connecting to other pending validators: {:?}",
                            err
                        )
                        .into());
                    }
                }
            }
            HbbftConnectToPeersMessage::ConnectToCurrentPeers(validator_set) => {
                // connecting to current validators.
                self.peers_management
                    .lock()
                    .connect_to_current_validators(validator_set, &self.client_arc()?);
                return Ok(());
            }

            HbbftConnectToPeersMessage::AnnounceOwnInternetAddress => {
                if let Err(error) = self.announce_own_internet_address() {
                    bail!("Error announcing own internet address: {:?}", error);
                }
                return Ok(());
            }

            HbbftConnectToPeersMessage::SetSignerAddress(signer_address) => {
                info!(target: "engine", "Setting signer address to: {:?}", signer_address);
                *self.mining_address.lock() = signer_address.clone();

                self.peers_management
                    .lock()
                    .set_validator_address(signer_address.clone());
                return Ok(());
            }

            HbbftConnectToPeersMessage::DisconnectAllValidators => {
                self.peers_management
                    .lock()
                    .disconnect_all_validators(&self.client_arc()?);
                return Ok(());
            }

            HbbftConnectToPeersMessage::AnnounceAvailability => {
                if let Err(error) = self.announce_availability() {
                    bail!("Error announcing availability: {:?}", error);
                }
                return Ok(());
            }
        }
    }
}

impl IoHandler<HbbftConnectToPeersMessage> for HbbftPeersHandler {
    fn message(
        &self,
        _io: &io::IoContext<HbbftConnectToPeersMessage>,
        message: &HbbftConnectToPeersMessage,
    ) {
        match self.handle_message(message) {
            Ok(_) => {
                trace!(target: "engine", "Hbbft Queue successfully worked message {:?}", message);
            }
            Err(e) => {
                error!(target: "engine", "Error handling HbbftConnectToPeersMessage: {:?} {:?}", message, e);
            }
        }
    }
}
