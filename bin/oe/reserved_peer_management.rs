use std::{collections::BTreeSet, net::SocketAddr, sync::Weak};

use ethcore::client::ReservedPeersManagement;

pub(crate) struct ReservedPeersWrapper {
    manage_network: Weak<dyn sync::ManageNetwork>,
    current_reserved_peers: BTreeSet<String>,
}

impl ReservedPeersWrapper {
    pub fn new(manage_network: Weak<dyn sync::ManageNetwork>) -> Self {
        ReservedPeersWrapper {
            manage_network,
            current_reserved_peers: BTreeSet::new(),
        }
    }
}

impl ReservedPeersManagement for ReservedPeersWrapper {
    fn add_reserved_peer(&mut self, peer: &String) -> Result<(), String> {
        if self.current_reserved_peers.contains(peer) {
            return Ok(());
        }

        match self.manage_network.upgrade() {
            Some(sync_arc) => {
                sync_arc.add_reserved_peer(peer.clone())?;
                // this insert should never fail, because we check just before
                self.current_reserved_peers.insert(peer.clone());
                Ok(())
            }
            None => Err("ManageNetwork instance not available.".to_string()),
        }
    }

    /// remove reserved peer
    fn remove_reserved_peer(&mut self, peer: &String) -> Result<(), String> {
        if self.current_reserved_peers.contains(peer) {
            match self.manage_network.upgrade() {
                Some(sync_arc) => {
                    let remove_result = sync_arc.remove_reserved_peer(peer.clone());
                    if remove_result.is_ok() {
                        // this remove should never fail, because we check just before
                        self.current_reserved_peers.remove(peer);
                    }
                    remove_result
                        .map_err(|_e| format!("remove_reserved_peer failed for peer: {peer}"))
                }
                None => {
                    warn!("ManageNetwork instance not available.");
                    Err("ManageNetwork instance not available.".to_string())
                }
            }
        } else {
            Err(format!(
                "Cannot remove reserved Peer: Peer not reserved: {peer}"
            ))
        }
    }

    fn get_reserved_peers(&self) -> &BTreeSet<String> {
        &self.current_reserved_peers
    }

    fn disconnect_others_than(&mut self, keep_list: BTreeSet<String>) -> usize {
        let reserved_peers_to_disconnect: Vec<String> = self
            .current_reserved_peers
            .iter()
            .filter_map(|p| {
                if keep_list.contains(p) {
                    None
                } else {
                    Some(p.clone())
                }
            })
            .collect();

        let mut disconnected = 0;
        for reserved_peer in reserved_peers_to_disconnect {
            if self.remove_reserved_peer(&reserved_peer).is_ok() {
                disconnected += 1;
            }
        }

        disconnected
    }

    /// Returns the devp2p network endpoint IP and Port information that is used to communicate with other peers.
    fn get_devp2p_network_endpoint(&self) -> Option<SocketAddr> {
        match self.manage_network.upgrade() {
            Some(sync_arc) => sync_arc.get_devp2p_network_endpoint(),
            None => {
                warn!("ManageNetwork instance not available.");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        network::{NetworkContext, ProtocolId},
        sync::ManageNetwork,
    };
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        ops::RangeInclusive,
        sync::Arc,
    };

    pub struct TestManageNetwork;

    impl ManageNetwork for TestManageNetwork {
        fn accept_unreserved_peers(&self) {}
        fn deny_unreserved_peers(&self) {}
        fn remove_reserved_peer(&self, _peer: String) -> Result<(), String> {
            Ok(())
        }
        fn add_reserved_peer(&self, _peer: String) -> Result<(), String> {
            Ok(())
        }
        fn start_network(&self) {}
        fn stop_network(&self) {}
        fn num_peers_range(&self) -> RangeInclusive<u32> {
            25..=50
        }
        fn with_proto_context(&self, _: ProtocolId, _: &mut dyn FnMut(&dyn NetworkContext)) {}

        fn get_devp2p_network_endpoint(&self) -> Option<SocketAddr> {
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                30303,
            )))
        }
    }

    #[test]
    fn test_add_reserved_peer() {
        let manage_network: Arc<dyn ManageNetwork> = Arc::new(TestManageNetwork);
        let mut wrapper = ReservedPeersWrapper::new(Arc::downgrade(&manage_network));
        let peer = "127.0.0.1:30303".to_string();
        assert_eq!(wrapper.add_reserved_peer(&peer), Ok(()));
        assert_eq!(wrapper.add_reserved_peer(&peer), Ok(()));
    }

    #[test]
    fn test_remove_reserved_peer() {
        let manage_network: Arc<dyn ManageNetwork> = Arc::new(TestManageNetwork);
        let mut wrapper = ReservedPeersWrapper::new(Arc::downgrade(&manage_network));
        let peer = "127.0.0.1:30303".to_string();
        assert!(wrapper.remove_reserved_peer(&peer).is_err());
        assert_eq!(wrapper.add_reserved_peer(&peer), Ok(()));
        assert_eq!(wrapper.remove_reserved_peer(&peer), Ok(()));
    }

    #[test]
    fn test_get_reserved_peers() {
        let manage_network: Arc<dyn ManageNetwork> = Arc::new(TestManageNetwork);
        let mut wrapper = ReservedPeersWrapper::new(Arc::downgrade(&manage_network));
        assert_eq!(wrapper.get_reserved_peers().len(), 0);
        let peer = "127.0.0.1:30303".to_string();
        assert_eq!(wrapper.add_reserved_peer(&peer), Ok(()));
        assert_eq!(wrapper.get_reserved_peers().len(), 1);
    }

    #[test]
    fn test_disconnect_others_than() {
        let manage_network: Arc<dyn ManageNetwork> = Arc::new(TestManageNetwork);

        let mut wrapper = ReservedPeersWrapper::new(Arc::downgrade(&manage_network));
        let peer1 = "127.0.0.1:30303".to_string();
        let peer2 = "127.0.0.1:30304".to_string();
        let peer3 = "127.0.0.1:30305".to_string();
        assert_eq!(wrapper.add_reserved_peer(&peer1), Ok(()));
        assert_eq!(wrapper.add_reserved_peer(&peer2), Ok(()));
        assert_eq!(wrapper.add_reserved_peer(&peer3), Ok(()));
        let keep_list = ["127.0.0.1:30303", "127.0.0.1:30304"]
            .iter()
            .cloned()
            .map(String::from)
            .collect();
        assert_eq!(wrapper.disconnect_others_than(keep_list), 1);
        assert_eq!(wrapper.get_reserved_peers().len(), 2);
    }
}
