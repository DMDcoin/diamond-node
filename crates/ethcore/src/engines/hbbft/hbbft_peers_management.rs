use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    client::{BlockChainClient, EngineClient},
    engines::hbbft::contracts::{
        staking::get_validator_internet_address,
        validator_set::{set_validator_internet_address, staking_by_mining_address},
    },
    ethereum::public_key_to_address::public_key_to_address,
};

use super::{NodeId, contracts::staking::get_pool_public_key};
use bytes::ToPretty;
use ethereum_types::Address;

#[derive(Clone, Debug)]
struct ValidatorConnectionData {
    // mining_address: Address,
    // staking_address: Address,
    // socket_addr: SocketAddr,
    // public_key: NodeId,
    peer_string: String,
    mining_address: Address,
}

pub struct HbbftPeersManagement {
    own_validator_address: Address,
    last_written_internet_address: Option<SocketAddr>,
    connected_current_pending_validators: Vec<ValidatorConnectionData>,
    connected_current_validators: Vec<ValidatorConnectionData>,
}

impl HbbftPeersManagement {
    pub fn new() -> Self {
        HbbftPeersManagement {
            own_validator_address: Address::zero(),
            last_written_internet_address: None,
            connected_current_pending_validators: Vec::new(),
            connected_current_validators: Vec::new(),
        }
    }

    /// connections are not always required.
    /// - during syncing
    /// - if not validator address specified.
    fn should_not_connect(&self, client: &dyn BlockChainClient) -> bool {
        // don't do any connections while the network is syncing.
        // the connection is not required yet, and might be outdated.
        // if we don't have a signing key, then we also do not need connections.

        return self.own_validator_address.is_zero() || client.is_major_syncing();
    }

    // pub fn connect_to_validators_core()

    /// if we become a pending validator,
    /// we have to start to communicate with all other
    /// potential future validators.
    /// The transition phase for changing the validator
    /// gives us enough time, so we already can build
    /// up the connections to the potential validators.
    pub fn connect_to_pending_validators(
        &mut self,
        client_arc: &Arc<dyn EngineClient>,
        pending_validators: &Vec<Address>,
    ) -> Result<usize, String> {
        let block_chain_client = client_arc
            .as_full_client()
            .ok_or("reserverd peers: could not retrieve BlockChainClient for connect_to_pending_validators")?;
        if self.should_not_connect(block_chain_client) {
            // warn!(target: "Engine", "connect_to_pending_validators should_not_connect");
            return Ok(0);
        }
        let mut connected_current_pending_validators: Vec<ValidatorConnectionData> = Vec::new();

        // we need go get the nodeID from the smart contract
        for pending_validator_address in pending_validators.iter() {
            if pending_validator_address == &self.own_validator_address {
                continue; // skip ourself.
            }

            if let Some(connection) = self.is_miner_connected(pending_validator_address) {
                // if we are already connected to this pending validator,
                // than we just can keep the connection.
                connected_current_pending_validators.push(connection.clone());
            } else {
                if let Some(connected_validator) = self.connect_to_validator(
                    client_arc.as_ref(),
                    block_chain_client,
                    pending_validator_address,
                ) {
                    connected_current_pending_validators.push(connected_validator);
                } else {
                    warn!(target: "Engine", "could not add pending validator to reserved peers: {}", pending_validator_address);
                }
            }
        }

        let mut old_peers_to_disconnect: Vec<String> = Vec::new();
        // we disconnect from all validators that are not in the pending list anymore.
        for old_validator in self.connected_current_pending_validators.iter() {
            let newly_connected_count = connected_current_pending_validators
                .iter()
                .filter(|v| v.mining_address == old_validator.mining_address)
                .count();

            // should be 0 or 1.

            if newly_connected_count == 0 {
                // maybe this validator is a active validator, then we keep the connection.

                if self
                    .is_miner_connected_as_current_validator(&old_validator.mining_address)
                    .is_none()
                {
                    // we are neighter a pending validator, nor a current validator.
                    // we have to disconnect.
                    old_peers_to_disconnect.push(old_validator.peer_string.clone());
                }
            }
        }

        if old_peers_to_disconnect.len() > 0 {
            // we have to disconnect from some peers
            let mut peers_management_guard = block_chain_client.reserved_peers_management().lock();

            if let Some(peers_management) = peers_management_guard.as_deref_mut() {
                for peer_string in old_peers_to_disconnect.iter() {
                    match peers_management.remove_reserved_peer(&peer_string) {
                        Ok(_) => {
                            info!(target: "Engine", "removed reserved peer {}", peer_string);
                        }
                        Err(_) => {
                            warn!(target: "Engine", "could not remove reserved peer {}", peer_string);
                        }
                    }
                }
            }
        }

        // we overwrite here the data.
        // mahybe we should make sure that there are no connected_current_pending_validators
        self.connected_current_pending_validators = connected_current_pending_validators;

        return Ok(self.connected_current_pending_validators.len());
    }

    // if we boot up and figure out,
    // that we are a current valudator,
    // then we have to figure out the current devP2P endpoints
    // from the smart contract and connect to them.
    // we cannot for sure disconnect the current validator,
    // because the node could just get synced into the transition time frame as
    // a current validator.
    pub fn connect_to_current_validators(
        &mut self,
        validator_set: &Vec<NodeId>,
        client_arc: &Arc<dyn EngineClient>,
    ) {
        if validator_set.len() > 0 {
            debug!(target: "Engine", "adding current validators as reserved peers. potential {}", validator_set.len());
        }
        // todo: iterate over NodeIds, extract the address
        // we do not need to connect to ourself.
        // figure out the IP and port from the contracts

        let client = client_arc.as_ref();

        let block_chain_client = match client.as_full_client() {
            Some(full_client) => full_client,
            None => {
                error!(target: "Engine", "could not retrieve BlockChainClient for adding reserved peer.");
                return;
            }
        };

        if self.should_not_connect(block_chain_client) {
            // warn!("connect_to_current_validators should_not_connect" );
            return;
        }

        // let mut validators_to_remove: BTreeSet<String> =  BTreeSet::new();

        let mut validators_to_remove: BTreeSet<Address> = self
            .connected_current_validators
            .iter()
            .map(|v| v.mining_address.clone())
            .collect();

        // validators_to_remove
        let mut current_validator_connections: Vec<ValidatorConnectionData> = Vec::new();
        let mut validators_to_connect_count = 0;
        for node in validator_set.iter() {
            let address = public_key_to_address(&node.0);

            if address == self.own_validator_address {
                continue; // skip ourself.
            }

            if let Some(connection) = self.is_miner_connected(&address) {
                current_validator_connections.push(connection.clone());
                validators_to_remove.remove(&connection.mining_address);
            } else if let Some(connection) =
                self.connect_to_validator(client, block_chain_client, &address)
            {
                validators_to_remove.remove(&connection.mining_address);
                validators_to_connect_count += 1;
                current_validator_connections.push(connection);
            } else {
                warn!(target: "Engine", "could not add current validator to reserved peers: {}", address);
            }
        }

        if validators_to_remove.len() > 0 {
            info!(
                "removing {} reserved peers, because they are neither a pending validator nor a current validator.",
                validators_to_remove.len()
            );

            let mut peers_management_guard = block_chain_client.reserved_peers_management().lock();

            if let Some(peers_management) = peers_management_guard.as_deref_mut() {
                for current_validator in self.connected_current_validators.iter() {
                    if validators_to_remove.contains(&current_validator.mining_address) {
                        match peers_management.remove_reserved_peer(&current_validator.peer_string)
                        {
                            Ok(_) => {
                                info!(target: "Engine", "removed reserved peer {}", current_validator.peer_string);
                            }
                            Err(error) => {
                                warn!(target: "Engine", "could not remove reserved peer {}: reason: {}", current_validator.peer_string, error);
                            }
                        }
                    }
                }

                peers_management
                    .get_reserved_peers()
                    .iter()
                    .for_each(|peer| {
                        info!(target: "Engine", "reserved peer: {}", peer);
                    });
            }
        }
        // we have now connected all additional current validators, kept the connection for those that have already been connected,
        // and we have disconnected all previous validators that are not current validators anymore.
        // so we now can set the information of collected validators.

        if validators_to_connect_count > 0 {
            info!(target: "Engine", "added {} current validators as reserved peers.", validators_to_connect_count);
        }

        self.connected_current_validators = current_validator_connections;
    }

    /// if we drop out as a current validator,
    /// as well a pending validator, we should drop
    /// all reserved connections.
    /// in later addition, we will keep the Partner Node Connections here. (upcomming feature)
    pub fn disconnect_all_validators(&mut self, client_arc: &Arc<dyn EngineClient>) {
        // we safely can disconnect even in situation where we are syncing.

        // todo: maybe develop as signal message because of deadlock danger ?!

        let client: &dyn BlockChainClient = match client_arc.as_ref().as_full_client() {
            Some(block_chain_client) => block_chain_client,
            None => {
                return;
            }
        };

        let mut lock = client.reserved_peers_management().lock();
        if let Some(peers_management) = lock.as_deref_mut() {
            let mut removed: BTreeSet<String> = BTreeSet::new();

            for connected_validator in self.connected_current_validators.iter() {
                if let Err(err) =
                    peers_management.remove_reserved_peer(&connected_validator.peer_string)
                {
                    error!(target: "engine", "could not remove validator {}: {}", connected_validator.peer_string, err);
                } else {
                    removed.insert(connected_validator.peer_string.clone());
                }
            }

            for connected_validator in self.connected_current_pending_validators.iter() {
                if removed.contains(&connected_validator.peer_string) {
                    // if we have already disconnected this pending validator, we can skip it#
                    // because the reserved peers management only manages 1 instance per
                    continue;
                }
                if let Err(err) =
                    peers_management.remove_reserved_peer(&connected_validator.peer_string)
                {
                    error!(target: "engine", "could not remove pending validator {}: {}", connected_validator.peer_string, err);
                } else {
                    removed.insert(connected_validator.peer_string.clone());
                }
            }

            info!(target: "engine", "removed {} peers from reserved peers management.", removed.len());
        }

        // regardless of disconnect problems here, we clear all the data here.
        self.connected_current_validators.clear();
        self.connected_current_pending_validators.clear();
    }

    /// if a key gen round fails or succeeds,
    /// we can disconnect from the failing validators,
    /// and only keep the connection to the current ones.
    /// if it succeeds, we also can disconnect from the pending validators,
    /// because those should be current validators by now.
    /// Make sure to connect to the new current validators,
    /// before disconnecting from the pending validators.
    #[allow(dead_code)]
    pub fn disconnect_pending_validators(
        &mut self,
        client: &dyn BlockChainClient,
    ) -> Result<usize, String> {
        // disconnect's can be done in any case,
        // reguardless if we are syncing or not.
        //let mutex_clone = client.reserved_peers_management().clone();

        let mut guard = client
            .reserved_peers_management()
            .try_lock_for(Duration::from_millis(100))
            .ok_or("Could not acquire reserved peers management within 100ms".to_string())?;

        if let Some(reserved_peers_management) = guard.as_deref_mut() {
            let mut kept_peers = Vec::<ValidatorConnectionData>::new();

            for old_pending_validator in self.connected_current_pending_validators.iter() {
                // do not disconnect pending validators that are also active validators.

                if !self
                    .is_miner_connected_as_current_validator(&old_pending_validator.mining_address)
                    .is_none()
                {
                    // let full_client = client.as_full_client()
                    if reserved_peers_management
                        .remove_reserved_peer(&old_pending_validator.peer_string)
                        .is_err()
                    {
                        warn!(target: "engine", "could not remove reserved peer {}", old_pending_validator.peer_string);
                        kept_peers.push(old_pending_validator.clone());
                    }
                }
            }

            let total_peers_removed =
                self.connected_current_pending_validators.len() - kept_peers.len();

            self.connected_current_pending_validators = kept_peers;

            return Ok(total_peers_removed);
        } else {
            return Err("Reserved Peers Management not set".to_string());
        }
    }
    // self.connected_current_pending_validators.retain(f)

    pub fn should_announce_own_internet_address(&self, client: &dyn BlockChainClient) -> bool {
        return !client.is_major_syncing() && self.last_written_internet_address.is_none();
    }

    // handles the announcements of the internet address for other peers as blockchain transactions
    pub fn announce_own_internet_address(
        &mut self,
        block_chain_client: &dyn BlockChainClient,
        engine_client: &dyn EngineClient,
        mining_address: &Address,
        staking_address: &Address,
    ) -> Result<(), String> {
        if !self.should_announce_own_internet_address(block_chain_client) {
            return Ok(());
        }
        // updates the nodes internet address if the information on the blockchain is outdated.

        // check if the stored internet address differs from our.
        // we do not need to do a special handling for 0.0.0.0, because
        // our IP is always different to that.

        trace!(target: "engine", "checking if internet address needs to be updated.");

        let current_endpoint = if let Some(peers_management) = block_chain_client
            .reserved_peers_management()
            .lock()
            .as_ref()
        {
            if let Some(endpoint) = peers_management.get_devp2p_network_endpoint() {
                endpoint
            } else {
                warn!(target: "engine", "devp2p endpoint not available.");
                return Ok(());
            }
        } else {
            error!(target: "engine", "Unable to lock reserved_peers_management");
            return Err("Unable to lock reserved_peers_management".to_string());
        };
        //let peers_management =

        trace!(target: "engine", "current Endpoint: {:?}", current_endpoint);

        // todo: we can improve performance,
        // by assuming that we are the only one who writes the internet address.
        // so we have to query this data only once, and then we can cache it.
        match get_validator_internet_address(engine_client, &staking_address) {
            Ok(validator_internet_address) => {
                trace!(target: "engine", "stored validator address{:?}", validator_internet_address);
                if validator_internet_address.eq(&current_endpoint) {
                    // if the current stored endpoint is the same as the current endpoint,
                    // we don't need to do anything.
                    // but we cache the current endpoint, so we don't have to query the db again.
                    self.last_written_internet_address = Some(current_endpoint);
                    return Ok(());
                }

                match set_validator_internet_address(
                    block_chain_client,
                    &mining_address,
                    &current_endpoint,
                ) {
                    Ok(()) => {
                        self.last_written_internet_address = Some(current_endpoint);
                        return Ok(());
                    }
                    Err(err) => {
                        error!(target: "engine", "unable to set validator internet address: {:?}", err);
                        return Err(format!(
                            "unable to set validator internet address: {:?}",
                            err
                        ));
                    }
                }
            }
            Err(err) => {
                error!(target: "engine", "unable to retrieve validator internet address: {:?}", err);
                return Err(format!(
                    "unable to retrieve validator internet address: {:?}",
                    err
                ));
            }
        }
    }

    pub fn set_validator_address(&mut self, value: Address) {
        self.own_validator_address = value;
    }

    // fn disconnect_validator(
    //     &mut self,
    //     block_chain_client: &dyn BlockChainClient,
    //     mining_address: &Address,
    // ) {
    // }

    fn connect_to_validator(
        &self,
        client: &dyn EngineClient,
        block_chain_client: &dyn BlockChainClient,
        mining_address: &Address,
    ) -> Option<ValidatorConnectionData> {
        // we do not connect to ourself.
        if mining_address == &self.own_validator_address {
            return None;
        }
        // self.own_validator_address
        match staking_by_mining_address(client, &mining_address) {
            Ok(staking_address) => {
                let node_id = match get_pool_public_key(client, &staking_address) {
                    Ok(pk) => NodeId(pk),
                    Err(e) => {
                        error!("error calling get_pool_public_key: {:?}", e);
                        return None;
                    }
                };

                let result = connect_to_validator_core(
                    client,
                    block_chain_client,
                    staking_address,
                    &node_id,
                );
                if let Some(mut data) = result {
                    data.mining_address = *mining_address;
                    info!("added reserved peer: {:?}", data);
                    return Some(data);
                }
            }
            Err(call_error) => {
                error!(target: "engine", "unable to ask for corresponding staking address for given mining address: {:?}", call_error);
            }
        };

        return None;
    }

    fn is_miner_connected(&self, mining_address: &Address) -> Option<&ValidatorConnectionData> {
        let result = self.is_miner_connected_as_current_validator(mining_address);
        if result.is_some() {
            return result;
        }

        return self.is_miner_connected_pending_validator(mining_address);
    }

    fn is_miner_connected_as_current_validator(
        &self,
        mining_address: &Address,
    ) -> Option<&ValidatorConnectionData> {
        return self
            .connected_current_validators
            .iter()
            .find(|x| x.mining_address == *mining_address);
    }

    fn is_miner_connected_pending_validator(
        &self,
        mining_address: &Address,
    ) -> Option<&ValidatorConnectionData> {
        return self
            .connected_current_pending_validators
            .iter()
            .find(|x| x.mining_address == *mining_address);
    }
}

fn connect_to_validator_core(
    client: &dyn EngineClient,
    block_chain_client: &dyn BlockChainClient,
    staking_address: Address,
    node_id: &NodeId,
) -> Option<ValidatorConnectionData> {
    if staking_address.is_zero() {
        // error!(target: "engine", "no IP Address found unable to ask for corresponding staking address for given mining address: {:?}", address);
        return None;
    }

    let socket_addr = match get_validator_internet_address(client, &staking_address) {
        Ok(socket_addr) => socket_addr,
        Err(error) => {
            error!(target: "engine", "unable to retrieve internet address for Node ( Public (NodeId): {:?} , staking address: {}, call Error: {:?}", node_id, staking_address, error);
            return None;
        }
    };

    if socket_addr.port() == 0 {
        error!(target: "engine", "connect_to_validator_core: no port specified for Node ( Public (NodeId): {:?} , staking address: {}, socket_addr: {:?}", node_id, staking_address, socket_addr);
        // we interprate port 0 as NULL.
        return None;
    }
    let ip = socket_addr.to_string();

    let mut guard = block_chain_client.reserved_peers_management().lock();

    if let Some(peers_management) = guard.as_deref_mut() {
        let public_key = node_id.0.to_hex();
        let peer_string = format!("enode://{}@{}", public_key, ip);
        info!(target: "engine", "adding reserved peer: {}", peer_string);
        if let Err(err) = peers_management.add_reserved_peer(&peer_string) {
            warn!(target: "engine", "failed to adding reserved: {} : {}", peer_string, err);
            return None;
        }

        return Some(ValidatorConnectionData {
            //staking_address: staking_address,
            //mining_address: *address,
            //socket_addr: socket_addr,
            peer_string,
            //public_key: node_id.clone(),
            mining_address: Address::zero(), // all caller of this function will set this value.
        });
    } else {
        warn!(target: "engine", "no peers management");
        None
    }
}
