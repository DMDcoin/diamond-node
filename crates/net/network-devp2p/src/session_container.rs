use crate::host::HostInfo;
use ethereum_types::H256;
use lru_cache::LruCache;
use mio::net::TcpStream;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use crate::{io::*, node_table::*, session::Session};
use network::{Error, ErrorKind, NetworkIoMessage, PeerId};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};

pub type SharedSession = Arc<Mutex<Session>>;

fn socket_address_to_string(socket: &TcpStream) -> String {
    socket
        .peer_addr()
        .map_or("unknown".to_string(), |a| a.to_string())
}

/// SessionContainer manages handshakes, and their upgrade to regular encrypted sessions.
/// It has high performance lookup capabilities for NodeIDs by using a hashmap, instead of linear locking iteration of sessions.
pub struct SessionContainer {
    max_sessions: usize,
    max_handshakes: usize, // New field to limit concurrent handshakes
    first_handshake: usize,
    last_handshake: usize,
    // the handshake cursor is a improvement to find new available handshake slots. it defines the next starting search position.
    current_handshake_cursor: Mutex<usize>,
    sessions: Arc<RwLock<std::collections::BTreeMap<usize, SharedSession>>>,
    handshakes: Arc<RwLock<std::collections::BTreeMap<usize, SharedSession>>>, // Separate map for handshakes
    // for egress handshakes, we know the Node ID we want to do a handshake with, so we can do efficient lookups.
    handshakes_egress_map: RwLock<BTreeMap<ethereum_types::H512, usize>>,
    node_id_to_session: Mutex<LruCache<ethereum_types::H512, usize>>, // used to map Node IDs to last used session tokens.
    sessions_token_max: Mutex<usize>, // curent last used token for regular sessions.
}

impl SessionContainer {
    pub fn new(
        first_handshake_token: usize,
        max_sessions: usize,
        max_node_mappings: usize,
        max_handshakes: usize,
    ) -> Self {
        SessionContainer {
            sessions: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            handshakes: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            handshakes_egress_map: RwLock::new(BTreeMap::new()),
            current_handshake_cursor: Mutex::new(first_handshake_token),
            first_handshake: first_handshake_token,
            last_handshake: first_handshake_token + max_handshakes,
            node_id_to_session: Mutex::new(LruCache::new(max_node_mappings)),
            sessions_token_max: Mutex::new(first_handshake_token + max_handshakes + 1),
            max_sessions,
            max_handshakes,
        }
    }

    /// Returns a Read guard to the sessions.
    pub fn read(&self) -> RwLockReadGuard<BTreeMap<usize, SharedSession>> {
        self.sessions.read()
    }

    /// Returns a Read guard to the sessions.
    pub fn read_handshakes(&self) -> RwLockReadGuard<BTreeMap<usize, SharedSession>> {
        self.handshakes.read()
    }

    /// gets the next token ID and store this information
    fn create_token_id(
        &self,
        node_id: &NodeId,
        tokens: &mut LruCache<ethereum_types::H512, usize>,
    ) -> usize {
        let mut session_token_max = self.sessions_token_max.lock();
        let next_id = session_token_max.clone();

        *session_token_max += 1;

        // TODO: if we run out of token ids,
        // we need to recycle Ids that are not used anymore.

        if let Some(old) = tokens.insert(node_id.clone(), next_id) {
            warn!(target: "network", "Node ID {} already exists with token {}, overwriting with {}", node_id, old, next_id);
        }

        return next_id;
    }

    fn create_token_id_for_handshake(
        &self,
        handshakes: &std::collections::BTreeMap<usize, SharedSession>,
    ) -> Result<usize, Error> {
        let mut cursor_lock = self.current_handshake_cursor.lock();
        let start_cursor = *cursor_lock;

        for _ in 0..self.max_handshakes {
            let current_token = *cursor_lock;
            *cursor_lock = if current_token + 1 < self.last_handshake {
                current_token + 1
            } else {
                self.first_handshake
            };

            if !handshakes.contains_key(&current_token) {
                // Found an available token
                return Ok(current_token);
            }

            if *cursor_lock == start_cursor {
                // We've looped through all possible handshake tokens and found none free.
                break;
            }
        }

        // If we reach here, it means no available handshake token was found.
        Err(ErrorKind::TooManyConnections.into())
    }

    pub(crate) fn session_count(&self) -> (usize, usize, usize) {
        let mut egress = 0;
        let mut ingress = 0;

        // we avoid an intensive read lock on the sessions, and take a snapshot of current sessions.
        for s in self.sessions.read().clone().iter() {
            match s.1.lock() {
                ref s if s.is_ready() && s.info.originated => egress += 1,
                ref s if s.is_ready() && !s.info.originated => ingress += 1,
                _ => {}
            }
        }

        (self.handshakes.read().len(), egress, ingress)
    }

    // like session count, but does not block if read can not be achieved.
    pub fn session_count_try(&self, lock_duration: Duration) -> Option<(usize, usize, usize)> {
        let mut egress = 0;
        let mut ingress = 0;

        let deadline = time_utils::DeadlineStopwatch::new(lock_duration);

        if let Some(lock) = self.sessions.try_read_for(deadline.time_left()) {
            for s in lock.iter() {
                match s.1.try_lock_for(deadline.time_left()) {
                    Some(ref s) => {
                        if s.is_ready() {
                            if s.info.originated {
                                egress += 1
                            } else {
                                ingress += 1;
                            }
                        }
                    }
                    None => return None,
                }
            }
        } else {
            return None;
        }

        if let Some(lock) = self.handshakes.try_read_for(deadline.time_left()) {
            return Some((lock.len(), egress, ingress));
        } else {
            return None;
        }
    }

    /// Creates a new session and adds it to the session container.
    /// returns the token ID of the new session, or an Error if not successful.
    pub fn create_handshake_connection(
        &self,
        socket: TcpStream,
        id: Option<&ethereum_types::H512>,
        io: &IoContext<NetworkIoMessage>,
        nonce: &H256,
        host: &HostInfo,
    ) -> Result<usize, Error> {
        let mut node_ids = self.node_id_to_session.lock();

        // if we known the ID, we also require a lock on the egress map in the same order as we do use to read the egress map

        let handshakes_egress_map = id.map(|_| self.handshakes_egress_map.write());

        let mut handshakes = self.handshakes.write();

        if self.sessions.read().len() >= self.max_sessions {
            return Err(ErrorKind::TooManyConnections.into());
        }

        if handshakes.len() >= self.max_handshakes {
            return Err(ErrorKind::TooManyConnections.into());
        }

        if let Some(node_id) = id {
            // check if there is already a connection for the given node id.
            if let Some(existing_peer_id) = node_ids.get_mut(node_id) {
                let existing_session_mutex_o = self.get_session(existing_peer_id.clone());

                if let Some(existing_session_mutex) = existing_session_mutex_o {
                    let session = existing_session_mutex.lock();
                    if let Some(id_from_session) = &session.info.id {
                        if session.info.id == Some(*node_id) {
                            // we got already got a session for the specified node.
                            // maybe the old session is already scheduled for getting deleted.
                            if !session.expired() {
                                return Err(ErrorKind::AlreadyExists.into());
                            }
                        } else {
                            error!(target: "network", "host cache inconsistency: Session node id mismatch. expected: {} is {}.", existing_peer_id, id_from_session);
                            return Err(ErrorKind::HostCacheInconsistency.into());
                        }
                    } else {
                        error!(target: "network", "host cache inconsistency: Session has no Node_id defined where it should for {}", existing_peer_id);
                        return Err(ErrorKind::HostCacheInconsistency.into());
                    }
                    // session guard is dropped here
                }
            }
        }

        let next_free_token = self.create_token_id_for_handshake(&mut handshakes)?;

        trace!(target: "network", "creating session for handshaking peer: {} token: {}", socket_address_to_string(&socket), next_free_token);
        // we dont know the NodeID,
        // we still need a session to do the handshake.

        let new_session = Session::new(io, socket, next_free_token.clone(), id, nonce, host);
        // the token is already registerd.
        match new_session {
            Ok(session) => {
                let session = Arc::new(Mutex::new(session));
                handshakes.insert(next_free_token, session.clone()); // Insert into handshakes map
                if let Some(mut egress_map) = handshakes_egress_map {
                    egress_map.insert(id.unwrap().clone(), next_free_token);
                }
                // register the stream for the new session.
                if let Err(err) = io.register_stream(next_free_token) {
                    debug!(target: "network", "Failed to register stream for token: {} : {}", next_free_token, err);
                }
                return Ok(next_free_token);
            }
            Err(e) => {
                error!(target: "network", "Failed to create handshake session for: {}", next_free_token);
                return Err(e);
            }
        }
    }

    pub fn get_session_for(&self, id: &NodeId) -> Option<SharedSession> {
        self.node_id_to_session
            .lock()
            .get_mut(id)
            .cloned()
            .map_or(None, |peer_id| {
                let sessions = self.sessions.read();
                sessions.get(&peer_id).cloned()
            })
    }

    pub fn get_handshake_for(&self, id: &NodeId) -> Option<SharedSession> {
        self.handshakes_egress_map
            .read()
            .get(id)
            .cloned()
            .map_or(None, |peer_id| {
                self.handshakes.read().get(&peer_id).cloned()
            })
    }

    pub fn node_id_to_peer_id(
        &self,
        node_id: &NodeId,
        only_available_sessions: bool,
    ) -> Option<usize> {
        self.node_id_to_session
            .lock()
            .get_mut(node_id)
            .map_or(None, |peer_id| {
                if !only_available_sessions {
                    return Some(*peer_id);
                }
                let sessions = self.sessions.read();

                // we can do additional checks:
                // we could ensure that the Node ID matches.
                // we could also read the flag and check if it is not marked for
                // getting disconnected.

                if sessions.contains_key(peer_id) {
                    return Some(*peer_id);
                }

                return None;
            })
    }

    // This method will now handle both registration and promotion if applicable
    pub fn register_finalized_handshake(
        &self,
        session: &mut Session,
        io: &IoContext<NetworkIoMessage>,
    ) -> Result<usize, Error> {
        let token = session.token();
        let id = session.id();

        trace!(target: "network", "register_finalized_handshake for token: {} with id: {:?}", token,id);
        let node_id = match id {
            Some(id) => id.clone(),
            None => {
                error!(target: "network", "Tried to register finalized handshake without node id");
                // We have no Node ID, so we can't promote it to a full session mapped by Node ID.
                // This might indicate an error state, or a handshake that failed to yield a Node ID.
                // For now, we'll just log and return.
                return Err(ErrorKind::HostCacheInconsistency.into());
            }
        };

        let mut node_ids_lock = self.node_id_to_session.lock();
        let mut sessions_lock = self.sessions.write();
        let mut handshakes_egress_map = self.handshakes_egress_map.write();
        let mut handshakes_lock = self.handshakes.write();

        // 1. Try to promote from handshakes map
        if let Some(handshake_session) = handshakes_lock.remove(&token) {
            // we remove the known handshake here.
            // for ingress handshakes, this call doesnt do anything,
            // because we can only track egress handshakes.
            // but thats fine.
            handshakes_egress_map.remove(&node_id);

            // Check session limit before promoting
            if sessions_lock.len() >= self.max_sessions {
                error!(target: "network", "Failed to promote handshake {}: too many active sessions.", token);
                // The handshake session is removed from 'handshakes_lock' but not added to 'sessions_lock'.
                // This session will effectively be dropped, and eventually cleaned up by `deregister_session_stream`.
                return Err(ErrorKind::TooManyConnections.into());
            }

            io.deregister_stream(token)?;

            // either we reuse an old token, or we create a new token.
            let upgraded_token = match node_ids_lock.get_mut(&node_id) {
                Some(t) => t.clone(),
                None => self.create_token_id(&node_id, &mut node_ids_lock),
            };

            io.register_stream(upgraded_token.clone())?;
            session.update_token_id(upgraded_token)?;

            // Move to the sessions map
            sessions_lock.insert(upgraded_token, handshake_session.clone());

            // Register/update the NodeId to session token mapping
            if let Some(old_token) = node_ids_lock.insert(node_id.clone(), upgraded_token) {
                if old_token != upgraded_token {
                    debug!(target: "network", "Handshake completed: changed primary session for node id {} from {} to {}", node_id, old_token, upgraded_token);
                }
            } else {
                debug!(target: "network", "Handshake completed: node id {} registered primary session token {}", node_id, upgraded_token);
            }
            return Ok(upgraded_token);
        } else {
            return Err(ErrorKind::HostCacheInconsistency.into());
        }
    }

    // handles duplicated sessions and desides wich one to be deleted. a duplicated session if it exists in a deterministic way, so both sides agree on the same session to keep.
    // returns if this session is marked for deletion, and not being accepted by the SessionContainer.
    // see: https://github.com/DMDcoin/diamond-node/issues/252
    pub fn should_delete_duplicate_session(&self, session: &SharedSession) -> Option<PeerId> {
        let (node_id, peer_id, uid) = {
            let lock = session.lock();
            let peer_id = lock.token().clone();

            let node_id = match lock.id() {
                Some(id) => id.clone(),
                None => {
                    // based on the control flow of the software, this should never happen.
                    warn!(target: "network", "Tried to delete duplicate session without node id");
                    return None; // we have no node id, so we can not delete it.
                }
            };

            let uid = match lock.info.session_uid {
                Some(u) => u.clone(),
                None => {
                    // based on the control flow of the software, this should never happen.
                    warn!(target: "network", "Tried to delete duplicate session without session uid");
                    return None; // we have no session uid, so we can not delete it.
                }
            };

            (node_id, peer_id, uid)
        };

        if let Some(existing_peer_id) = self.node_id_to_peer_id(&node_id, true) {
            if existing_peer_id != peer_id {
                // there may be an active session for this peer id.
                let existing_session = self.get_session_for(&node_id);
                if let Some(existing_session_mutex) = existing_session {
                    let existing_lock = existing_session_mutex.lock();
                    if existing_lock.expired() {
                        // other session is already about to get deleted.
                        trace!(target:"network", "existing peer session {existing_peer_id} is already about to get deleted.");
                        return None;
                    }
                    if let Some(existing_uid) = existing_lock.info.session_uid {
                        // the highest RNG wins.
                        if existing_uid.lt(&uid) {
                            // we keep the existing session, and delete the new one.
                            trace!(target: "network", "Session {peer_id} has a duplicate :{existing_peer_id} for {node_id}, deleting this session");
                            // we savely mark this connection to get killed softly.
                            return Some(peer_id);
                        } else {
                            trace!(target: "network", "Session {peer_id} has a duplicate :{existing_peer_id} for {node_id}, deleting duplicated session");
                            // and delete the existing one.
                            return Some(existing_peer_id);
                        }
                    }
                } else {
                    trace!(target: "network", "No session active for {node_id} with peer id {existing_peer_id}");
                    // todo: make sure the mapping is rewritten.
                }

                trace!(target: "network", "Session {peer_id} has a duplicate :{existing_peer_id} {node_id}");
                return Some(existing_peer_id);
            }
        } else {
            trace!(target: "network", "No session known for {node_id}");
        }

        return None;
    }

    pub(crate) fn deregister_session_stream<Host: mio::deprecated::Handler>(
        &self,
        stream: usize,
        event_loop: &mut mio::deprecated::EventLoop<Host>,
    ) {
        let mut connections = if stream < self.last_handshake {
            self.handshakes.write()
        } else {
            self.sessions.write()
        };

        if let Some(connection) = connections.get(&stream).cloned() {
            let c = connection.lock();
            if c.expired() {
                // make sure it is the same connection that the event was generated for
                c.deregister_socket(event_loop)
                    .expect("Error deregistering socket");
                connections.remove(&stream);
            }
        }
    }

    pub(crate) fn get_handshake(&self, stream: usize) -> Option<SharedSession> {
        trace!(target: "network", "get_handshake for stream: {}. total handshakes: {}", stream, self.handshakes.read().len() );
        self.handshakes.read().get(&stream).cloned()
    }

    pub(crate) fn get_session(&self, stream: usize) -> Option<SharedSession> {
        self.sessions.read().get(&stream).cloned()
    }
}
