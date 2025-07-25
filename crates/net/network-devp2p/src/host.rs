// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

use crate::{
    mio::{deprecated::EventLoop, tcp::*, udp::*, *},
    session_container::{SessionContainer, SharedSession},
};
use crypto::publickey::{Generator, KeyPair, Random, Secret};
use ethereum_types::H256;
use hash::keccak;
use rlp::{Encodable, RlpStream};
use std::{
    cmp::{max, min},
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::*,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    time::Duration,
};

use crate::{
    PROTOCOL_VERSION,
    discovery::{Discovery, MAX_DATAGRAM_SIZE, NodeEntry, TableUpdates},
    io::*,
    ip_utils::{map_external_address, select_public_address},
    node_table::*,
    session::SessionData,
};
use network::{
    ConnectionDirection, ConnectionFilter, DisconnectReason, Error, ErrorKind,
    NetworkConfiguration, NetworkContext as NetworkContextTrait, NetworkIoMessage,
    NetworkProtocolHandler, NonReservedPeerMode, PacketId, PeerId, ProtocolId, SessionInfo,
    client_version::ClientVersion,
};
use parity_path::restrict_permissions_owner;
use parking_lot::{Mutex, RwLock};
use stats::{PrometheusMetrics, PrometheusRegistry};

const MAX_SESSIONS: usize = 2048;
const MAX_HANDSHAKES: usize = 99;

const DEFAULT_PORT: u16 = 30303;

//const SYS_TIMER: TimerToken = 0;
// StreamToken/TimerToken
const TCP_ACCEPT: StreamToken = 1;
const IDLE: TimerToken = 2;
const DISCOVERY: StreamToken = 3;
const DISCOVERY_REFRESH: TimerToken = 4;
const FAST_DISCOVERY_REFRESH: TimerToken = 5;
const DISCOVERY_ROUND: TimerToken = 6;
const NODE_TABLE: TimerToken = 7;

// Maximum count of peer mappings we remember.  each node ID takes 64 bytes for nodeID, 8 bytes for peer id, and probabyl 3 * 8 bytes for internals. = about 100 bytes per entry.)
// 10000 elements should take about 1 MB of memory.
const MAX_NODE_TO_PEER_MAPPINGS: usize = 10000;

// the user timers are a collection of timers that are registered by the protocol handlers.
// therefore comming from other modules.
// to be not in conflict with the token ID system, we choose a very
// high number for the user timers,
// that is realisticly unreachable by the peer stream tokens,
// but still have enough number space for user timers.
const FIRST_USER_TIMER: TimerToken = 8;
const MAX_USER_TIMERS: TimerToken = 91;
const LAST_USER_TIMER: TimerToken = FIRST_USER_TIMER + MAX_USER_TIMERS;

const FIRST_HANDSHAKE: StreamToken = LAST_USER_TIMER + 1;
const LAST_HANDSHAKE: StreamToken = FIRST_HANDSHAKE + MAX_HANDSHAKES;
const FIRST_SESSION: StreamToken = FIRST_HANDSHAKE + MAX_HANDSHAKES + 1;
const LAST_SESSION: StreamToken = StreamToken::MAX;

// Timeouts
// for IDLE TimerToken
const MAINTENANCE_TIMEOUT: Duration = Duration::from_secs(1);
// for DISCOVERY_REFRESH TimerToken
const DISCOVERY_REFRESH_TIMEOUT: Duration = Duration::from_secs(60);
// for FAST_DISCOVERY_REFRESH TimerToken
const FAST_DISCOVERY_REFRESH_TIMEOUT: Duration = Duration::from_secs(10);
// for DISCOVERY_ROUND TimerToken
const DISCOVERY_ROUND_TIMEOUT: Duration = Duration::from_millis(300);
// for NODE_TABLE TimerToken
const NODE_TABLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, PartialEq, Eq)]
/// Protocol info
pub struct CapabilityInfo {
    /// Protocol ID
    pub protocol: ProtocolId,
    /// Protocol version
    pub version: u8,
    /// Total number of packet IDs this protocol support.
    pub packet_count: u8,
}

impl Encodable for CapabilityInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.protocol.as_u64());
        s.append(&self.version);
    }
}

/// IO access point. This is passed to all IO handlers and provides an interface to the IO subsystem.
pub struct NetworkContext<'s> {
    io: &'s IoContext<NetworkIoMessage>,
    protocol: ProtocolId,
    sessions: &'s SessionContainer,
    session: Option<SharedSession>,
    session_id: Option<StreamToken>,
    reserved_peers: &'s HashSet<NodeId>,
    statistics: &'s NetworkingStatistics,
}

pub struct NetworkingStatistics {
    logging_enabled: bool,

    bytes_sent: AtomicU64,
    peer_losses: AtomicU64,
    packages_send: AtomicU64,
}

impl NetworkingStatistics {
    pub fn new(logging_enabled: bool) -> NetworkingStatistics {
        NetworkingStatistics {
            logging_enabled: logging_enabled,
            bytes_sent: AtomicU64::new(0),
            peer_losses: AtomicU64::new(0),
            packages_send: AtomicU64::new(0),
        }
    }
}

impl PrometheusMetrics for NetworkingStatistics {
    fn prometheus_metrics(&self, registry: &mut PrometheusRegistry) {
        registry.register_counter(
            "p2p_bytes_sent",
            "total",
            self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed) as i64,
        );
        registry.register_counter(
            "p2p_packages_sent",
            "count",
            self.packages_send
                .load(std::sync::atomic::Ordering::Relaxed) as i64,
        );
        registry.register_counter(
            "p2p_peer_losses",
            "count",
            self.peer_losses.load(std::sync::atomic::Ordering::Relaxed) as i64,
        );
    }
}

impl<'s> NetworkContext<'s> {
    /// Create a new network IO access point. Takes references to all the data that can be updated within the IO handler.
    fn new(
        io: &'s IoContext<NetworkIoMessage>,
        protocol: ProtocolId,
        session: Option<SharedSession>,
        sessions: &'s SessionContainer,
        reserved_peers: &'s HashSet<NodeId>,
        statistics: &'s NetworkingStatistics,
    ) -> NetworkContext<'s> {
        let id = session.as_ref().map(|s| s.lock().token());
        NetworkContext {
            io,
            protocol,
            session_id: id,
            session,
            sessions,
            reserved_peers,
            statistics,
        }
    }

    fn resolve_session(&self, peer: PeerId) -> Option<SharedSession> {
        match self.session_id {
            Some(id) if id == peer => self.session.clone(),
            _ => {
                if peer >= FIRST_SESSION {
                    self.sessions.get_session(peer)
                } else {
                    self.sessions.get_handshake(peer)
                }
            }
        }
    }
}

impl<'s> NetworkContextTrait for NetworkContext<'s> {
    fn send(
        &self,
        peer: PeerId,
        packet_id: PacketId,
        data: Vec<u8>,
    ) -> std::result::Result<(), network::Error> {
        self.send_protocol(self.protocol, peer, packet_id, data)
    }

    fn send_protocol(
        &self,
        protocol: ProtocolId,
        peer: PeerId,
        packet_id: PacketId,
        data: Vec<u8>,
    ) -> std::result::Result<(), Error> {
        let session = self.resolve_session(peer);
        if let Some(session) = session {
            session
                .lock()
                .send_packet(self.io, Some(protocol), packet_id as u8, &data)?;

            if self.statistics.logging_enabled {
                self.statistics
                    .bytes_sent
                    .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                self.statistics
                    .packages_send
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        } else {
            trace!(target: "network", "Send: Peer no longer exist");
            if self.statistics.logging_enabled {
                self.statistics
                    .peer_losses
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn respond(
        &self,
        packet_id: PacketId,
        data: Vec<u8>,
    ) -> std::result::Result<(), network::Error> {
        assert!(
            self.session.is_some(),
            "Respond called without network context"
        );
        self.session_id.map_or_else(
            || Err(ErrorKind::Expired.into()),
            |id| self.send(id, packet_id, data),
        )
    }

    fn disable_peer(&self, peer: PeerId) {
        self.io
            .message(NetworkIoMessage::DisablePeer(peer))
            .unwrap_or_else(|e| warn!("Error disable_peer: {:?} {:?}", peer, e));
    }

    fn disconnect_peer(&self, peer: PeerId) {
        self.io
            .message(NetworkIoMessage::Disconnect(peer))
            .unwrap_or_else(|e| warn!("Error disconnect_peer: {:?} {:?}", peer, e));
    }

    fn is_expired(&self) -> bool {
        self.session.as_ref().map_or(false, |s| s.lock().expired())
    }

    fn register_timer(&self, token: TimerToken, delay: Duration) -> std::result::Result<(), Error> {
        trace!(target: "network", "Registering timer: {:?} for protocol: {} with delay {}", token, self.protocol, delay.as_millis());
        self.io
            .message(NetworkIoMessage::AddTimer {
                token,
                delay,
                protocol: self.protocol,
            })
            .unwrap_or_else(|e| warn!("Error register_timer: {:?}", e));
        Ok(())
    }

    fn peer_client_version(&self, peer: PeerId) -> ClientVersion {
        self.resolve_session(peer)
            .map_or(ClientVersion::from("unknown").to_owned(), |s| {
                s.lock().info.client_version.clone()
            })
    }

    fn session_info(&self, peer: PeerId) -> Option<SessionInfo> {
        self.resolve_session(peer).map(|s| s.lock().info.clone())
    }

    fn protocol_version(&self, protocol: ProtocolId, peer: PeerId) -> Option<u8> {
        let session = self.resolve_session(peer);
        session.and_then(|s| s.lock().capability_version(protocol))
    }

    fn subprotocol_name(&self) -> ProtocolId {
        self.protocol
    }

    fn is_reserved_peer(&self, peer: PeerId) -> bool {
        self.session_info(peer)
            .and_then(|info| info.id)
            .map(|node| self.reserved_peers.contains(&node))
            .unwrap_or(false)
    }

    fn node_id_to_peer_id(&self, node_id: &NodeId) -> Option<PeerId> {
        self.sessions.node_id_to_peer_id(node_id, true)
    }
}

/// Shared host information
pub struct HostInfo {
    /// Our private and public keys.
    keys: KeyPair,
    /// Current network configuration
    config: NetworkConfiguration,
    /// Connection nonce.
    nonce: H256,
    /// RLPx protocol version
    pub protocol_version: u32,
    /// Registered capabilities (handlers)
    pub capabilities: Vec<CapabilityInfo>,
    /// Local address + discovery port
    pub local_endpoint: NodeEndpoint,
    /// Public address + discovery port
    pub public_endpoint: Option<NodeEndpoint>,
}

impl HostInfo {
    fn next_nonce(&mut self) -> H256 {
        self.nonce = keccak(&self.nonce);
        self.nonce
    }

    pub(crate) fn client_version(&self) -> &str {
        &self.config.client_version
    }

    pub(crate) fn secret(&self) -> &Secret {
        self.keys.secret()
    }

    pub(crate) fn id(&self) -> &NodeId {
        self.keys.public()
    }
}

#[derive(Copy, Clone)]
struct ProtocolTimer {
    pub protocol: ProtocolId,
    pub token: TimerToken, // Handler level token
}

/// Root IO handler. Manages protocol handlers, IO timers and network connections.
///
/// NOTE: must keep the lock in order of: reserved_nodes (rwlock) -> session (mutex, from sessions)
pub struct Host {
    pub info: RwLock<HostInfo>,
    udp_socket: Mutex<Option<UdpSocket>>,
    tcp_listener: Mutex<TcpListener>,
    handshake_lock: Mutex<()>,
    sessions: SessionContainer,
    discovery: Mutex<Option<Discovery<'static>>>,
    nodes: RwLock<NodeTable>,
    handlers: RwLock<HashMap<ProtocolId, Arc<dyn NetworkProtocolHandler + Sync>>>,
    timers: RwLock<HashMap<TimerToken, ProtocolTimer>>,
    timer_counter: RwLock<usize>,
    reserved_nodes: RwLock<HashSet<NodeId>>,
    stopping: AtomicBool,
    filter: Option<Arc<dyn ConnectionFilter>>,
    statistics: NetworkingStatistics,
}

impl Host {
    /// Create a new instance
    pub fn new(
        mut config: NetworkConfiguration,
        filter: Option<Arc<dyn ConnectionFilter>>,
    ) -> Result<Host, Error> {
        let mut listen_address = match config.listen_address {
            None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), DEFAULT_PORT)),
            Some(addr) => addr,
        };

        let keys = if let Some(ref secret) = config.use_secret {
            KeyPair::from_secret(secret.clone())?
        } else {
            config
                .config_path
                .clone()
                .and_then(|ref p| load_key(Path::new(&p)))
                .map_or_else(
                    || {
                        let key = Random.generate();
                        if let Some(path) = config.config_path.clone() {
                            save_key(Path::new(&path), key.secret());
                        }
                        key
                    },
                    |s| KeyPair::from_secret(s).expect("Error creating node secret key"),
                )
        };
        let path = config.net_config_path.clone();
        // Setup the server socket
        let tcp_listener = TcpListener::bind(&listen_address)?;

        listen_address = SocketAddr::new(listen_address.ip(), tcp_listener.local_addr()?.port());
        debug!(target: "network", "Listening at {:?}", listen_address);
        let udp_port = config.udp_port.unwrap_or_else(|| listen_address.port());
        let local_endpoint = NodeEndpoint {
            address: listen_address,
            udp_port,
        };

        let boot_nodes = config.boot_nodes.clone();
        let reserved_nodes = config.reserved_nodes.clone();
        config.max_handshakes = min(config.max_handshakes, MAX_HANDSHAKES as u32);

        let mut host = Host {
            info: RwLock::new(HostInfo {
                keys,
                config,
                nonce: H256::random(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Vec::new(),
                public_endpoint: None,
                local_endpoint,
            }),
            discovery: Mutex::new(None),
            udp_socket: Mutex::new(None),
            tcp_listener: Mutex::new(tcp_listener),
            sessions: SessionContainer::new(
                FIRST_HANDSHAKE,
                MAX_SESSIONS,
                MAX_NODE_TO_PEER_MAPPINGS,
                MAX_HANDSHAKES,
            ),
            handshake_lock: Mutex::new(()),
            nodes: RwLock::new(NodeTable::new(path)),
            handlers: RwLock::new(HashMap::new()),
            timers: RwLock::new(HashMap::new()),
            timer_counter: RwLock::new(FIRST_USER_TIMER),
            reserved_nodes: RwLock::new(HashSet::new()),
            stopping: AtomicBool::new(false),
            filter,
            statistics: NetworkingStatistics::new(true),
        };

        for n in boot_nodes {
            host.add_node(&n);
        }

        for n in reserved_nodes {
            if let Err(e) = host.add_reserved_node(&n) {
                debug!(target: "network", "Error parsing node id: {}: {:?}", n, e);
            }
        }
        Ok(host)
    }

    pub fn add_node(&mut self, id: &str) {
        match Node::from_str(id) {
            Err(e) => {
                debug!(target: "network", "Could not add node {}: {:?}", id, e);
            }
            Ok(n) => {
                let entry = NodeEntry {
                    endpoint: n.endpoint.clone(),
                    id: n.id,
                };

                self.nodes.write().add_node(n);
                if let Some(ref mut discovery) = *self.discovery.lock() {
                    discovery.add_node(entry);
                }
            }
        }
    }

    pub fn add_reserved_node(&self, id: &str) -> Result<(), Error> {
        let n = Node::from_str(id)?;

        let entry = NodeEntry {
            endpoint: n.endpoint.clone(),
            id: n.id,
        };
        self.reserved_nodes.write().insert(n.id);
        self.nodes
            .write()
            .add_node(Node::new(entry.id, entry.endpoint.clone()));

        if let Some(ref mut discovery) = *self.discovery.lock() {
            discovery.add_node(entry);
        }

        Ok(())
    }

    pub fn set_non_reserved_mode(
        &self,
        mode: NonReservedPeerMode,
        io: &IoContext<NetworkIoMessage>,
    ) {
        let mut info = self.info.write();

        if info.config.non_reserved_mode != mode {
            info.config.non_reserved_mode = mode;
            drop(info);
            if let NonReservedPeerMode::Deny = mode {
                // disconnect all non-reserved peers here.
                let reserved = self.reserved_nodes.read();
                let mut to_kill = Vec::new();
                for e in self.sessions.read().iter() {
                    let mut s = e.1.lock();
                    {
                        let id = s.id();
                        if id.map_or(false, |id| reserved.contains(id)) {
                            continue;
                        }
                    }

                    s.disconnect(io, DisconnectReason::ClientQuit);
                    to_kill.push(s.token());
                }
                for p in to_kill {
                    trace!(target: "network", "Disconnecting on reserved-only mode: {}", p);
                    self.kill_connection(p, io, false);
                }
            }
        }
    }

    pub fn remove_reserved_node(&self, id: &str) -> Result<(), Error> {
        let n = Node::from_str(id)?;
        self.reserved_nodes.write().remove(&n.id);

        Ok(())
    }

    pub fn external_url(&self) -> Option<String> {
        let info = self.info.read();
        info.public_endpoint
            .as_ref()
            .map(|e| format!("{}", Node::new(*info.id(), e.clone())))
    }

    pub fn local_url(&self) -> String {
        let info = self.info.read();
        format!("{}", Node::new(*info.id(), info.local_endpoint.clone()))
    }

    pub fn stop(&self, io: &IoContext<NetworkIoMessage>) {
        self.stopping.store(true, AtomicOrdering::SeqCst);
        let mut to_kill = Vec::new();
        for e in self.sessions.read().iter() {
            let mut s = e.1.lock();
            s.disconnect(io, DisconnectReason::ClientQuit);
            to_kill.push(s.token());
        }

        for e in self.sessions.read_handshakes().iter() {
            let mut s = e.1.lock();
            s.disconnect(io, DisconnectReason::ClientQuit);
            to_kill.push(s.token());
        }

        for p in to_kill {
            trace!(target: "network", "Disconnecting on shutdown: {}", p);
            self.kill_connection(p, io, true);
        }
        io.unregister_handler();
    }

    /// Get all connected peers.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        let sessions = self.sessions.read();
        let sessions = &*sessions;

        let mut peers = Vec::with_capacity(sessions.len());

        for peer_id in sessions.keys() {
            peers.push(peer_id.clone());
        }
        peers
    }

    fn init_public_interface(&self, io: &IoContext<NetworkIoMessage>) -> Result<(), Error> {
        if self.info.read().public_endpoint.is_some() {
            return Ok(());
        }
        let local_endpoint = self.info.read().local_endpoint.clone();
        let public_address = self.info.read().config.public_address;
        let allow_ips = self.info.read().config.ip_filter.clone();
        let public_endpoint = match public_address {
            None => {
                let public_address = select_public_address(local_endpoint.address.port());
                let public_endpoint = NodeEndpoint {
                    address: public_address,
                    udp_port: local_endpoint.udp_port,
                };
                if self.info.read().config.nat_enabled {
                    match map_external_address(&local_endpoint) {
                        Some(endpoint) => {
                            info!("NAT mapped to external address {}", endpoint.address);
                            endpoint
                        }
                        None => public_endpoint,
                    }
                } else {
                    public_endpoint
                }
            }
            Some(addr) => NodeEndpoint {
                address: addr,
                udp_port: local_endpoint.udp_port,
            },
        };

        self.info.write().public_endpoint = Some(public_endpoint.clone());

        if let Some(url) = self.external_url() {
            io.message(NetworkIoMessage::NetworkStarted(url))
                .unwrap_or_else(|e| warn!("Error sending IO notification: {:?}", e));
        }

        // Initialize discovery.
        let discovery = {
            let info = self.info.read();
            if info.config.discovery_enabled
                && info.config.non_reserved_mode == NonReservedPeerMode::Accept
            {
                info!(target: "network", "Starting discovery on Endpoint: {}, ip_filter: {}", public_endpoint, allow_ips);
                Some(Discovery::new(&info.keys, public_endpoint, allow_ips))
            } else {
                None
            }
        };

        if let Some(mut discovery) = discovery {
            let mut udp_addr = local_endpoint.address;
            udp_addr.set_port(local_endpoint.udp_port);
            let socket = UdpSocket::bind(&udp_addr).expect("Error binding UDP socket");
            *self.udp_socket.lock() = Some(socket);

            discovery.add_node_list(self.nodes.read().entries());
            *self.discovery.lock() = Some(discovery);
            io.register_stream(DISCOVERY)?;
            io.register_timer(FAST_DISCOVERY_REFRESH, FAST_DISCOVERY_REFRESH_TIMEOUT)?;
            io.register_timer(DISCOVERY_REFRESH, DISCOVERY_REFRESH_TIMEOUT)?;
            io.register_timer(DISCOVERY_ROUND, DISCOVERY_ROUND_TIMEOUT)?;
        }
        io.register_timer(NODE_TABLE, NODE_TABLE_TIMEOUT)?;
        io.register_stream(TCP_ACCEPT)?;
        Ok(())
    }

    fn maintain_network(&self, io: &IoContext<NetworkIoMessage>) {
        self.keep_alive(io);
        self.connect_peers(io);
    }

    fn have_session(&self, id: &NodeId) -> bool {
        return self.sessions.get_session_for(id).is_some();
    }

    /// returns if there is a known handshake for the given node id is going on.
    /// Only Egress handshakes can be considered, for ingress handshakes the NodeID is unknown.
    fn have_handshake(&self, id: &NodeId) -> bool {
        return self.sessions.get_handshake_for(id).is_some();
    }

    // returns (handshakes, egress, ingress)
    fn session_count(&self) -> (usize, usize, usize) {
        self.sessions.session_count()
    }

    fn keep_alive(&self, io: &IoContext<NetworkIoMessage>) {
        let mut to_kill = Vec::new();
        for e in self.sessions.read().iter() {
            let mut s = e.1.lock();
            if !s.keep_alive(io) {
                s.disconnect(io, DisconnectReason::PingTimeout);
                to_kill.push(s.token());
            }
        }
        for p in to_kill {
            trace!(target: "network", "Ping timeout: {}", p);
            self.kill_connection(p, io, true);
        }
    }

    fn has_enough_peers(&self) -> bool {
        let min_peers = {
            let info = self.info.read();
            let config = &info.config;

            config.min_peers
        };
        let (_, egress_count, ingress_count) = self.session_count();

        return egress_count + ingress_count >= min_peers as usize;
    }

    fn connect_peers(&self, io: &IoContext<NetworkIoMessage>) {
        // dont connect to peers, while we are processing handshakes.
        let _handshake_lock = self.handshake_lock.lock();

        let (min_peers, pin, max_handshakes, allow_ips, self_id) = {
            let info = self.info.read();
            if info.capabilities.is_empty() {
                return;
            }
            let config = &info.config;

            (
                config.min_peers,
                config.non_reserved_mode == NonReservedPeerMode::Deny,
                config.max_handshakes as usize,
                config.ip_filter.clone(),
                *info.id(),
            )
        };

        let (mut handshake_count, egress_count, ingress_count) = self.session_count();

        trace!(target: "network", "initial handshake count: {handshake_count}");

        // we clone the reserved nodes, to avoid deadlocks and reduce locking time.
        let reserved_nodes = Arc::new(self.reserved_nodes.read().clone());
        let unconnected_reserved_nodes: Vec<NodeId> = reserved_nodes
            .as_ref()
            .into_iter()
            .filter(|f| f.ne(&&self_id) && !self.have_handshake(f) && !self.have_session(f))
            .cloned()
            .collect();

        // reserved peers are already findable in the SessionContainer, even they are handshaking.
        // so we wont trigger a second handshake here.

        let mut started: usize = 0;

        for reserved in &unconnected_reserved_nodes {
            trace!(target: "network", "connect_peer because it is unconnected reserved peer: {reserved}");
            self.connect_peer(reserved, io);
            started += 1;
            handshake_count += 1;
        }

        if pin {
            return;
        }

        if handshake_count >= max_handshakes {
            return;
        }

        let max_handshakes_per_round = max_handshakes / 2;

        // ip filter:
        //.nodes(&allow_ips))
        let number_of_connects_to_make = (min_peers as usize)
            .min(max_handshakes_per_round.min(max_handshakes - handshake_count));

        let nodes_to_connect =
            self.nodes
                .read()
                .nodes_filtered(number_of_connects_to_make, &allow_ips, |n: &Node| {
                    n.id != self_id
                        && !&reserved_nodes.contains(&n.id)
                        && self.filter.as_ref().map_or(true, |f| {
                            f.connection_allowed(&self_id, &n.id, ConnectionDirection::Outbound)
                        })
                        && !self.have_session(&n.id) // alternative strategy: we might also get a list of active connections, instead of locking here to figure out if we have a session or not. 
                });

        trace!(target: "network", "reserved nodes: {:?} nodes_to_connect: {:?}", reserved_nodes, nodes_to_connect);

        // now connect to nodes from the node table.
        for id in nodes_to_connect {
            self.connect_peer(&id, io);
            started += 1;
        }

        debug!(target: "network", "Connecting peers: {} sessions, {} handshakes {} started", egress_count + ingress_count, handshake_count, started);
    }

    fn connect_peer(&self, id: &NodeId, io: &IoContext<NetworkIoMessage>) {
        if self.have_session(id) {
            trace!(target: "network", "Aborted connect. Node already connected.");
            return;
        }

        let socket = {
            let address = {
                let mut nodes = self.nodes.write();
                if let Some(node) = nodes.get_mut(id) {
                    node.endpoint.address
                } else {
                    debug!(target: "network", "Connection to expired node aborted");
                    return;
                }
            };
            match TcpStream::connect(&address) {
                Ok(socket) => {
                    trace!(target: "network", "{}: Connecting to {:?}", id, address);
                    socket
                }
                Err(e) => {
                    debug!(target: "network", "{}: Can't connect to address {:?}: {:?}", id, address, e);
                    self.nodes.write().note_failure(&id);
                    return;
                }
            }
        };

        if let Err(e) = self.create_connection(socket, Some(id), io) {
            debug!(target: "network", "Can't create connection: {:?}", e);
        }
    }

    fn create_connection(
        &self,
        socket: TcpStream,
        id: Option<&NodeId>,
        io: &IoContext<NetworkIoMessage>,
    ) -> Result<usize, Error> {
        let nonce = self.info.write().next_nonce();
        self.sessions
            .create_handshake_connection(socket, id, io, &nonce, &self.info.read())
    }

    fn accept(&self, io: &IoContext<NetworkIoMessage>) {
        trace!(target: "network", "Accepting incoming connection");
        loop {
            let socket = match self.tcp_listener.lock().accept() {
                Ok((sock, _addr)) => sock,
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        debug!(target: "network", "Error accepting connection: {:?}", e);
                    }
                    break;
                }
            };
            if let Err(e) = self.create_connection(socket, None, io) {
                debug!(target: "network", "Can't accept connection: {:?}", e);
            }
        }
    }

    fn session_writable(&self, session: Option<SharedSession>, io: &IoContext<NetworkIoMessage>) {
        if let Some(session) = session {
            let mut s = session.lock();
            if let Err(e) = s.writable(io, &self.info.read()) {
                trace!(target: "network", "Session write error: {}: {:?}", s.token(), e);
            }
            if s.done() {
                io.deregister_stream(s.token())
                    .unwrap_or_else(|e| debug!("Error deregistering stream: {:?}", e));
            }
        }
    }

    fn connection_closed(&self, token: StreamToken, io: &IoContext<NetworkIoMessage>) {
        trace!(target: "network", "Connection closed: {}", token);
        self.kill_connection(token, io, true);
    }

    fn session_readable(&self, session: Option<SharedSession>, io: &IoContext<NetworkIoMessage>) {
        let mut ready_data: Vec<ProtocolId> = Vec::new();
        let mut packet_data: Vec<(ProtocolId, PacketId, Vec<u8>)> = Vec::new();
        let mut kill: Option<PeerId> = None;
        let mut ready_id = None;
        if let Some(session) = session {
            let mut token = session.lock().token();
            trace!(target: "network", "Session readable called: {}", token);
            {
                loop {
                    let session_result = session.lock().readable(io, &self.info.read());
                    match session_result {
                        Err(e) => {
                            let reserved_nodes = self.reserved_nodes.read();
                            let s = session.lock();
                            trace!(target: "network", "Session read error: {}:{:?} ({:?}) {:?}", token, s.id(), s.remote_addr(), e);
                            match *e.kind() {
                                ErrorKind::Disconnect(DisconnectReason::IncompatibleProtocol)
                                | ErrorKind::Disconnect(DisconnectReason::UselessPeer) => {
                                    if let Some(id) = s.id() {
                                        if !reserved_nodes.contains(id) {
                                            let mut nodes = self.nodes.write();
                                            nodes.note_failure(&id);
                                            nodes.mark_as_useless(id);
                                        }
                                    }
                                }
                                _ => {}
                            }
                            kill = Some(token);
                            break;
                        }
                        Ok(SessionData::Ready) => {
                            // we allow only one Handshake to be handlet at a time.
                            let _handshake_lock = self.handshake_lock.lock();

                            let (_, egress_count, ingress_count) = self.session_count();

                            //if self.sessions.is_duplicate(&session) {

                            kill = self.sessions.should_delete_duplicate_session(&session);

                            if let Some(session_to_kill) = kill {
                                if session_to_kill == token {
                                    // if its our session wich gets to be killed, we can skip the next setup steps.
                                    trace!(target: "network", "not registering session {session_to_kill}");
                                    break;
                                }
                            }

                            let mut s = session.lock();

                            let (min_peers, mut max_peers, reserved_only, self_id) = {
                                let info = self.info.read();
                                let mut max_peers = info.config.max_peers;
                                for cap in s.info.capabilities() {
                                    if let Some(num) =
                                        info.config.reserved_protocols.get(&cap.protocol)
                                    {
                                        max_peers += *num;
                                        break;
                                    }
                                }
                                (
                                    info.config.min_peers as usize,
                                    max_peers as usize,
                                    info.config.non_reserved_mode == NonReservedPeerMode::Deny,
                                    *info.id(),
                                )
                            };

                            max_peers = max(max_peers, min_peers);

                            let id = *s.id().expect("Ready session always has id");

                            // Check for the session limit.
                            // Outgoing connections are allowed as long as their count is <= min_peers
                            // Incoming connections are allowed to take all of the max_peers reserve, or at most half of the slots.
                            let max_ingress = max(max_peers - min_peers, min_peers / 2);
                            if reserved_only
                                || (s.info.originated && egress_count > min_peers)
                                || (!s.info.originated && ingress_count > max_ingress)
                            {
                                if !self.reserved_nodes.read().contains(&id) {
                                    // only proceed if the connecting peer is reserved.
                                    trace!(target: "network", "Disconnecting non-reserved peer {:?} (TooManyPeers)", id);
                                    s.disconnect(io, DisconnectReason::TooManyPeers);
                                    kill = Some(token);
                                    break;
                                }
                            }

                            if !self.filter.as_ref().map_or(true, |f| {
                                f.connection_allowed(&self_id, &id, ConnectionDirection::Inbound)
                            }) {
                                trace!(target: "network", "Inbound connection not allowed for {:?}", id);
                                s.disconnect(io, DisconnectReason::UnexpectedIdentity);
                                kill = Some(token);
                                break;
                            }

                            ready_id = Some(id);

                            let new_token = match self
                                .sessions
                                .register_finalized_handshake(&mut s, io)
                            {
                                Ok(t) => t,
                                Err(e) => {
                                    warn!(target: "network", "Unable to finalize handshake for token {token} reason: {e}");
                                    break;
                                }
                            };

                            trace!(target: "network", "upgraded handshake to regular session for token: {} -> {}", token, new_token);

                            token = new_token;

                            // Add it to the node table
                            if !s.info.originated {
                                if let Ok(address) = s.remote_addr() {
                                    // We can't know remote listening ports, so just assume defaults and hope for the best.
                                    let endpoint = NodeEndpoint {
                                        address: SocketAddr::new(address.ip(), DEFAULT_PORT),
                                        udp_port: DEFAULT_PORT,
                                    };
                                    let entry = NodeEntry { id, endpoint };
                                    let mut nodes = self.nodes.write();
                                    if !nodes.contains(&entry.id) {
                                        nodes.add_node(Node::new(entry.id, entry.endpoint.clone()));
                                        let mut discovery = self.discovery.lock();
                                        if let Some(ref mut discovery) = *discovery {
                                            discovery.add_node(entry);
                                        }
                                    }
                                }
                            }

                            // Note connection success
                            self.nodes.write().note_success(&id);

                            for (p, _) in self.handlers.read().iter() {
                                if s.have_capability(*p) {
                                    ready_data.push(*p);
                                }
                            }
                        }
                        Ok(SessionData::Packet {
                            data,
                            protocol,
                            packet_id,
                        }) => match self.handlers.read().get(&protocol) {
                            None => {
                                warn!(target: "network", "No handler found for protocol: {:?}", protocol)
                            }
                            Some(_) => packet_data.push((protocol, packet_id, data)),
                        },
                        Ok(SessionData::Continue) => (),
                        Ok(SessionData::None) => break,
                    }
                }
            }

            if let Some(peer_to_kill) = kill {
                self.kill_connection(peer_to_kill, io, true);
            }

            // todo: because of new duplicated session detection logic,
            // https://github.com/DMDcoin/diamond-node/issues/252
            // this code should realisticly not be able to find duplicate sessions.

            let handlers = self.handlers.read();
            if !ready_data.is_empty() {
                let duplicates: Vec<usize> = self
                    .sessions
                    .read()
                    .iter()
                    .filter_map(|e| {
                        let session = e.1.lock();
                        if session.token() != token
                            && session.info.id == ready_id
                            && !session.expired()
                        {
                            return Some(session.token());
                        } else {
                            return None;
                        }
                    })
                    .collect();

                if duplicates.len() > 0 {
                    trace!(target: "network", "Rejected duplicate connection for {:?}: token: {} other connections: {:?}", ready_id, token, duplicates);
                    session
                        .lock()
                        .disconnect(io, DisconnectReason::DuplicatePeer);
                    drop(handlers);
                    self.kill_connection(token, io, false);
                    return;
                }

                let reserved = self.reserved_nodes.read().clone();
                for p in ready_data {
                    if let Some(h) = handlers.get(&p) {
                        h.connected(
                            &NetworkContext::new(
                                io,
                                p,
                                Some(session.clone()),
                                &self.sessions,
                                &reserved,
                                &self.statistics,
                            ),
                            &token,
                        );
                        // accumulate pending packets.
                        let mut session = session.lock();
                        packet_data.extend(session.mark_connected(p));
                    }
                }
            }

            for (p, packet_id, data) in packet_data {
                let reserved = self.reserved_nodes.read();
                if let Some(h) = handlers.get(&p) {
                    h.read(
                        &NetworkContext::new(
                            io,
                            p,
                            Some(session.clone()),
                            &self.sessions,
                            &reserved,
                            &self.statistics,
                        ),
                        &token,
                        packet_id,
                        &data,
                    );
                }
            }
        } else {
            trace!(target: "network", "Session not found");
        }
    }

    fn discovery_readable(&self, io: &IoContext<NetworkIoMessage>) {
        let node_changes = match (
            self.udp_socket.lock().as_ref(),
            self.discovery.lock().as_mut(),
        ) {
            (Some(udp_socket), Some(discovery)) => {
                let mut buf = [0u8; MAX_DATAGRAM_SIZE];
                let writable = discovery.any_sends_queued();
                let res = match udp_socket.recv_from(&mut buf) {
                    Ok(Some((len, address))) => discovery
                        .on_packet(&buf[0..len], address)
                        .unwrap_or_else(|e| {
                            debug!(target: "network", "Error processing UDP packet: {:?}", e);
                            None
                        }),
                    Ok(_) => None,
                    Err(e) => {
                        debug!(target: "network", "Error reading UPD socket: {:?}", e);
                        None
                    }
                };
                let new_writable = discovery.any_sends_queued();
                if writable != new_writable {
                    io.update_registration(DISCOVERY)
						.unwrap_or_else(|e| {
							debug!(target: "network" ,"Error updating discovery registration: {:?}", e)
						});
                }
                res
            }
            _ => None,
        };
        if let Some(node_changes) = node_changes {
            self.update_nodes(io, node_changes);
        }
    }

    fn discovery_writable(&self, io: &IoContext<NetworkIoMessage>) {
        if let (Some(udp_socket), Some(discovery)) = (
            self.udp_socket.lock().as_ref(),
            self.discovery.lock().as_mut(),
        ) {
            while let Some(data) = discovery.dequeue_send() {
                match udp_socket.send_to(&data.payload, &data.address) {
                    Ok(Some(size)) if size == data.payload.len() => {}
                    Ok(Some(_)) => {
                        warn!(target: "network", "UDP sent incomplete datagram");
                    }
                    Ok(None) => {
                        discovery.requeue_send(data);
                        return;
                    }
                    Err(e) => {
                        debug!(target: "network", "UDP send error: {:?}, address: {:?}", e, &data.address);
                        return;
                    }
                }
            }
            io.update_registration(DISCOVERY).unwrap_or_else(
                |e| debug!(target: "network", "Error updating discovery registration: {:?}", e),
            );
        }
    }

    fn connection_timeout(&self, token: StreamToken, io: &IoContext<NetworkIoMessage>) {
        trace!(target: "network", "Connection timeout: {}", token);
        self.kill_connection(token, io, true);
    }

    fn kill_connection(&self, token: StreamToken, io: &IoContext<NetworkIoMessage>, remote: bool) {
        self.kill_connection_with_failure(token, io, remote, true);
    }

    fn kill_connection_with_failure(
        &self,
        token: StreamToken,
        io: &IoContext<NetworkIoMessage>,
        remote: bool,
        as_failure: bool,
    ) {
        let mut to_disconnect: Vec<ProtocolId> = Vec::new();
        let mut failure_id = None;
        let mut deregister = false;
        let mut expired_session = None;
        if token >= FIRST_HANDSHAKE {
            trace!(target: "network", "Killing connection: {}", token);
            let session_o = if token >= FIRST_SESSION {
                self.sessions.get_session(token)
            } else {
                self.sessions.get_handshake(token)
            };

            // we can shorten the session read lock here, if this causes a deadlock.
            // on the other hand it is good, so not that many sessions manipulations can take place
            // at the same time.

            if let Some(session) = session_o {
                expired_session = Some(session.clone());
                let mut s = session.lock();
                if !s.expired() {
                    if as_failure {
                        failure_id = s.id().cloned();
                    }
                    if s.is_ready() {
                        for (p, _) in self.handlers.read().iter() {
                            if s.have_capability(*p) {
                                to_disconnect.push(p.clone());
                            }
                        }
                    }

                    s.set_expired();
                }
                deregister = remote || s.done();
            } else {
                trace!(target: "network", "Session not found for token: {}", token);
            }
        }
        if let Some(id) = failure_id {
            if remote {
                self.nodes.write().note_failure(&id);
            }
        }
        for p in to_disconnect {
            let reserved = self.reserved_nodes.read();
            if let Some(h) = self.handlers.read().get(&p) {
                h.disconnected(
                    &NetworkContext::new(
                        io,
                        p,
                        expired_session.clone(),
                        &self.sessions,
                        &reserved,
                        &self.statistics,
                    ),
                    &token,
                );
            }
        }
        if deregister {
            io.deregister_stream(token)
                .unwrap_or_else(|e| debug!("Error deregistering stream: {:?}", e));
        }
    }

    fn update_nodes(&self, _io: &IoContext<NetworkIoMessage>, node_changes: TableUpdates) {
        let mut to_remove: Vec<PeerId> = Vec::new();
        {
            let sessions = self.sessions.read();
            for c in sessions.iter() {
                let s = c.1.lock();
                if let Some(id) = s.id() {
                    if node_changes.removed.contains(id) {
                        to_remove.push(s.token());
                    }
                }
            }
        }
        for i in to_remove {
            trace!(target: "network", "Removed from node table: {}", i);
        }
        let reserved_nodes = self.reserved_nodes.read();
        self.nodes.write().update(node_changes, &*reserved_nodes);
    }

    pub fn with_context<F>(&self, protocol: ProtocolId, io: &IoContext<NetworkIoMessage>, action: F)
    where
        F: FnOnce(&dyn NetworkContextTrait),
    {
        let reserved = { self.reserved_nodes.read() };

        let context = NetworkContext::new(
            io,
            protocol,
            None,
            &self.sessions,
            &reserved,
            &self.statistics,
        );
        action(&context);
    }

    pub fn with_context_eval<F, T>(
        &self,
        protocol: ProtocolId,
        io: &IoContext<NetworkIoMessage>,
        action: F,
    ) -> T
    where
        F: FnOnce(&dyn NetworkContextTrait) -> T,
    {
        let reserved = { self.reserved_nodes.read() };

        let context = NetworkContext::new(
            io,
            protocol,
            None,
            &self.sessions,
            &reserved,
            &self.statistics,
        );
        action(&context)
    }

    fn get_session_or_handshake(&self, token: StreamToken) -> Option<SharedSession> {
        if token >= FIRST_HANDSHAKE && token <= LAST_HANDSHAKE {
            return self.sessions.get_handshake(token);
        } else if token >= FIRST_SESSION && token <= LAST_SESSION {
            return self.sessions.get_session(token);
        }
        warn!(target: "network", "get_session_or_handshake called with unexpected token: {}", token);
        return None;
    }
}

impl IoHandler<NetworkIoMessage> for Host {
    /// Initialize networking
    fn initialize(&self, io: &IoContext<NetworkIoMessage>) {
        io.register_timer(IDLE, MAINTENANCE_TIMEOUT)
            .expect("Error registering Network idle timer");
        io.message(NetworkIoMessage::InitPublicInterface)
            .unwrap_or_else(|e| warn!("Error sending IO notification: {:?}", e));
        self.maintain_network(io)
    }

    fn stream_hup(&self, io: &IoContext<NetworkIoMessage>, stream: StreamToken) {
        trace!(target: "network", "Hup: {}", stream);
        if stream >= FIRST_HANDSHAKE {
            self.connection_closed(stream, io)
        } else {
            warn!(target: "network", "Unexpected hup for session {}", stream);
        }
    }

    fn stream_readable(&self, io: &IoContext<NetworkIoMessage>, stream: StreamToken) {
        if self.stopping.load(AtomicOrdering::SeqCst) {
            return;
        }
        match stream {
            FIRST_HANDSHAKE..=LAST_HANDSHAKE => {
                self.session_readable(self.sessions.get_handshake(stream), io)
            }
            FIRST_SESSION..=LAST_SESSION => {
                self.session_readable(self.sessions.get_session(stream), io)
            }
            DISCOVERY => self.discovery_readable(io),
            TCP_ACCEPT => self.accept(io),
            _ => panic!("Received unknown readable token"),
        }
    }

    fn stream_writable(&self, io: &IoContext<NetworkIoMessage>, stream: StreamToken) {
        if self.stopping.load(AtomicOrdering::SeqCst) {
            return;
        }
        match stream {
            FIRST_HANDSHAKE..=LAST_HANDSHAKE => {
                self.session_writable(self.sessions.get_handshake(stream), io)
            }
            FIRST_SESSION..=LAST_SESSION => {
                self.session_writable(self.sessions.get_session(stream), io)
            }
            DISCOVERY => self.discovery_writable(io),
            _ => panic!("Received unknown writable token"),
        }
    }

    fn timeout(&self, io: &IoContext<NetworkIoMessage>, token: TimerToken) {
        if self.stopping.load(AtomicOrdering::SeqCst) {
            return;
        }
        match token {
            IDLE => self.maintain_network(io),

            DISCOVERY_REFRESH => {
                // Run the _slow_ discovery if enough peers are connected
                if !self.has_enough_peers() {
                    return;
                }
                self.discovery.lock().as_mut().map(|d| d.refresh());
                io.update_registration(DISCOVERY)
                    .unwrap_or_else(|e| debug!("Error updating discovery registration: {:?}", e));
            }
            FAST_DISCOVERY_REFRESH => {
                // Run the fast discovery if not enough peers are connected
                if self.has_enough_peers() {
                    return;
                }
                self.discovery.lock().as_mut().map(|d| d.refresh());
                io.update_registration(DISCOVERY)
                    .unwrap_or_else(|e| debug!("Error updating discovery registration: {:?}", e));
            }
            DISCOVERY_ROUND => {
                self.discovery.lock().as_mut().map(|d| d.round());
                io.update_registration(DISCOVERY)
                    .unwrap_or_else(|e| debug!("Error updating discovery registration: {:?}", e));
            }
            NODE_TABLE => {
                trace!(target: "network", "Refreshing node table");
                let mut nodes = self.nodes.write();
                nodes.clear_useless();
                nodes.save();
            }
            FIRST_USER_TIMER..=LAST_USER_TIMER => match self.timers.read().get(&token).cloned() {
                Some(timer) => match self.handlers.read().get(&timer.protocol).cloned() {
                    None => {
                        warn!(target: "network", "No handler found for protocol: {:?}", timer.protocol)
                    }
                    Some(h) => {
                        let reserved = self.reserved_nodes.read();
                        h.timeout(
                            &NetworkContext::new(
                                io,
                                timer.protocol,
                                None,
                                &self.sessions,
                                &reserved,
                                &self.statistics,
                            ),
                            timer.token,
                        );
                    }
                },
                None => {
                    warn!("Unknown timer token: {}", token);
                } // timer is not registerd through us
            },
            FIRST_HANDSHAKE..=LAST_SESSION => {
                trace!(target: "network", "Timeout from Host impl: {}", token);
                self.connection_timeout(token, io);
            }
            _ => {
                warn!(target: "network", "HOST: Unknown timer token tick: {}", token);
            }
        }
    }

    fn message(&self, io: &::io::IoContext<NetworkIoMessage>, message: &NetworkIoMessage) {
        if self.stopping.load(AtomicOrdering::SeqCst) {
            return;
        }
        match *message {
            NetworkIoMessage::AddHandler {
                ref handler,
                ref protocol,
                ref versions,
            } => {
                let h = handler.clone();
                let reserved = self.reserved_nodes.read();
                h.initialize(&NetworkContext::new(
                    io,
                    *protocol,
                    None,
                    &self.sessions,
                    &reserved,
                    &self.statistics,
                ));
                self.handlers.write().insert(*protocol, h);
                let mut info = self.info.write();
                for &(version, packet_count) in versions {
                    info.capabilities.push(CapabilityInfo {
                        protocol: *protocol,
                        version,
                        packet_count,
                    });
                }
            }
            NetworkIoMessage::AddTimer {
                ref protocol,
                ref delay,
                ref token,
            } => {
                trace!(target: "network", "Adding timer for protocol: {:?}, delay: {:?}, token: {}", protocol, delay.as_millis(), token);

                if token >= &MAX_USER_TIMERS {
                    warn!(target: "network", "Tried to register timer with token {} which is larger than MAX_USER_TIMERS {}", token, MAX_USER_TIMERS);
                    return;
                }

                let handler_token = {
                    let mut timer_counter = self.timer_counter.write();
                    let counter = &mut *timer_counter;
                    let handler_token = *counter;
                    *counter += 1;
                    handler_token
                };

                if handler_token > LAST_USER_TIMER {
                    warn!(target: "network", "Tried to register timer witch Index {token} what would be over the boundaries of usertimers: {LAST_USER_TIMER}");
                    return;
                }
                self.timers.write().insert(
                    handler_token,
                    ProtocolTimer {
                        protocol: *protocol,
                        token: *token,
                    },
                );

                trace!(target: "network", "Registering handler_token {} token {} for protocol {:?} with delay {:?}", handler_token, token, protocol, delay);
                io.register_timer(handler_token, *delay)
                    .unwrap_or_else(|e| debug!("Error registering timer {}: {:?}", token, e));
            }
            NetworkIoMessage::Disconnect(ref peer) => {
                let session = self.get_session_or_handshake(peer.clone());
                if let Some(session) = session {
                    session
                        .lock()
                        .disconnect(io, DisconnectReason::DisconnectRequested);
                }
                trace!(target: "network", "Disconnect requested {}", peer);
                self.kill_connection(*peer, io, false);
            }
            NetworkIoMessage::DisablePeer(ref peer) => {
                let session = self.get_session_or_handshake(peer.clone());
                if let Some(session) = session {
                    session
                        .lock()
                        .disconnect(io, DisconnectReason::DisconnectRequested);
                    if let Some(id) = session.lock().id() {
                        let mut nodes = self.nodes.write();
                        nodes.note_failure(&id);
                        nodes.mark_as_useless(id);
                    }
                }
                debug!(target: "network", "Disabling peer {}", peer);
                self.kill_connection(*peer, io, false);
            }
            NetworkIoMessage::InitPublicInterface => self
                .init_public_interface(io)
                .unwrap_or_else(|e| warn!("Error initializing public interface: {:?}", e)),
            _ => {} // ignore others.
        }
    }

    fn register_stream(
        &self,
        stream: StreamToken,
        reg: Token,
        event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
    ) {
        trace!(target: "network", "register_stream {}", stream);
        match stream {
            FIRST_HANDSHAKE..=LAST_HANDSHAKE => {
                let session = { self.sessions.get_handshake(stream) };
                if let Some(session) = session {
                    session
                        .lock()
                        .register_socket(reg, event_loop)
                        .expect("Error registering socket");
                }
            }
            FIRST_SESSION.. => {
                let session = { self.sessions.get_session(stream) };
                if let Some(session) = session {
                    session
                        .lock()
                        .register_socket(reg, event_loop)
                        .expect("Error registering socket");
                }
            }
            DISCOVERY => match self.udp_socket.lock().as_ref() {
                Some(udp_socket) => {
                    event_loop
                        .register(udp_socket, reg, Ready::all(), PollOpt::edge())
                        .expect("Error registering UDP socket");
                }
                _ => panic!("Error registering discovery socket"),
            },
            TCP_ACCEPT => event_loop
                .register(
                    &*self.tcp_listener.lock(),
                    Token(TCP_ACCEPT),
                    Ready::all(),
                    PollOpt::edge(),
                )
                .expect("Error registering stream"),
            _ => warn!("Unexpected stream registration"),
        }
    }

    fn deregister_stream(
        &self,
        stream: StreamToken,
        event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
    ) {
        match stream {
            FIRST_HANDSHAKE.. => {
                self.sessions.deregister_session_stream(stream, event_loop);
            }
            DISCOVERY => (),
            _ => warn!("Unexpected stream deregistration"),
        }
    }

    fn update_stream(
        &self,
        stream: StreamToken,
        reg: Token,
        event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
    ) {
        match stream {
            DISCOVERY => match (
                self.udp_socket.lock().as_ref(),
                self.discovery.lock().as_ref(),
            ) {
                (Some(udp_socket), Some(discovery)) => {
                    let registration = if discovery.any_sends_queued() {
                        Ready::readable() | Ready::writable()
                    } else {
                        Ready::readable()
                    };
                    event_loop
                        .reregister(udp_socket, reg, registration, PollOpt::edge())
                        .expect("Error reregistering UDP socket");
                }
                _ => panic!("Error reregistering discovery socket"),
            },
            TCP_ACCEPT => event_loop
                .reregister(
                    &*self.tcp_listener.lock(),
                    Token(TCP_ACCEPT),
                    Ready::all(),
                    PollOpt::edge(),
                )
                .expect("Error reregistering stream"),
            _ => {
                let connection = self.get_session_or_handshake(stream);
                if let Some(connection) = connection {
                    connection
                        .lock()
                        .update_socket(reg, event_loop)
                        .expect("Error updating socket");
                }
            }
        }
    }
}

impl PrometheusMetrics for Host {
    fn prometheus_metrics(&self, r: &mut PrometheusRegistry) {
        let lockdur = Duration::from_millis(50);

        if let Some((handshakes, egress, ingress)) =
            self.sessions.session_count_try(Duration::from_millis(20))
        {
            r.register_gauge("p2p_ingress", "count", ingress as i64);
            r.register_gauge("p2p_egress", "count", egress as i64);
            r.register_gauge("p2p_handshakes", "count", handshakes as i64);
        }

        if let Some(reserved_nodes) = self.reserved_nodes.try_read_for(lockdur) {
            r.register_gauge("p2p_reserved_nodes", "count", reserved_nodes.len() as i64);
        }

        if let Some(nodes) = self.nodes.try_read_for(lockdur) {
            r.register_gauge("p2p_nodes", "count", nodes.count_nodes() as i64);
            r.register_gauge("p2p_uselessnodes", "count", nodes.count_useless() as i64);
        }

        self.statistics.prometheus_metrics(r);
    }

    //r.register_gauge("connected_peers", "", self.connect_peers(io));
}

fn save_key(path: &Path, key: &Secret) {
    let mut path_buf = PathBuf::from(path);
    if let Err(e) = fs::create_dir_all(path_buf.as_path()) {
        warn!("Error creating key directory: {:?}", e);
        return;
    };
    path_buf.push("key");
    let path = path_buf.as_path();
    let mut file = match fs::File::create(&path) {
        Ok(file) => file,
        Err(e) => {
            warn!("Error creating key file: {:?}", e);
            return;
        }
    };
    if let Err(e) = restrict_permissions_owner(path, true, false) {
        warn!(target: "network", "Failed to modify permissions of the file ({})", e);
    }
    if let Err(e) = file.write(&key.to_hex().into_bytes()) {
        warn!("Error writing key file: {:?}", e);
    }
}

fn load_key(path: &Path) -> Option<Secret> {
    let mut path_buf = PathBuf::from(path);
    path_buf.push("key");
    let mut file = match fs::File::open(path_buf.as_path()) {
        Ok(file) => file,
        Err(e) => {
            debug!("Error opening key file: {:?}", e);
            return None;
        }
    };
    let mut buf = String::new();
    match file.read_to_string(&mut buf) {
        Ok(_) => {}
        Err(e) => {
            warn!("Error reading key file: {:?}", e);
            return None;
        }
    }
    match Secret::from_str(&buf) {
        Ok(key) => Some(key),
        Err(e) => {
            warn!("Error parsing key file: {:?}", e);
            None
        }
    }
}

#[test]
fn key_save_load() {
    use tempdir::TempDir;

    let tempdir = TempDir::new("").unwrap();
    let key = H256::random().into();
    save_key(tempdir.path(), &key);
    let r = load_key(tempdir.path());
    assert_eq!(key, r.unwrap());
}

#[test]
fn host_client_url() {
    let mut config = NetworkConfiguration::new_local();
    let key = "6f7b0d801bc7b5ce7bbd930b84fd0369b3eb25d09be58d64ba811091046f3aa2"
        .parse()
        .unwrap();
    config.use_secret = Some(key);
    let host: Host = Host::new(config, None).unwrap();
    assert!(host.local_url().starts_with("enode://101b3ef5a4ea7a1c7928e24c4c75fd053c235d7b80c22ae5c03d145d0ac7396e2a4ffff9adee3133a7b05044a5cee08115fd65145e5165d646bde371010d803c@"));
}
