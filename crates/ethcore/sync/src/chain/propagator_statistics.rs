use std::collections::HashMap;

use stats::PrometheusMetrics;

use crate::sync_io::SyncIo;

#[derive(Default)]
pub struct SyncPropagatorStatistics {
    logging_enabled: bool,
    logging_peer_details_enabled: bool,
    propagated_blocks: i64,
    propagated_blocks_bytes: i64,

    consensus_bytes: i64,
    consensus_packages: i64,

    consensus_broadcast_bytes: i64,
    consensus_broadcast_packages: i64,

    transactions_propagated: i64,
    transactions_propagated_bytes: i64,

    transaction_hashes_propagated: i64,
    transaction_hashes_propagated_bytes: i64,

    responded_transactions_bytes: i64,
    responded_transactions: i64,

    node_statistics: HashMap<String, SyncPropagatorNodeStatistics>,
}

struct SyncPropagatorNodeStatistics {
    address: String,
    propagated_blocks: i64,
    propagated_blocks_bytes: i64,
}

impl SyncPropagatorStatistics {
    pub fn new() -> Self {
        SyncPropagatorStatistics {
            logging_enabled: true,
            logging_peer_details_enabled: true,
            ..Default::default()
        }
    }

    pub fn logging_enabled(&self) -> bool {
        return self.logging_enabled;
    }

    pub fn log_propagated_block(
        &mut self,
        io: &mut dyn SyncIo,
        peer_id: usize,
        blocks: usize,
        bytes: usize,
    ) {
        if self.logging_enabled() {
            self.propagated_blocks += blocks as i64;
            self.propagated_blocks_bytes += bytes as i64;

            if self.logging_peer_details_enabled {
                if let Some(peer_info) = io.peer_session_info(peer_id) {
                    //let mut node_statistics = &self.node_statistics;
                    let node_statistics = self
                        .node_statistics
                        .entry(peer_info.remote_address.clone())
                        .or_insert_with(|| SyncPropagatorNodeStatistics {
                            address: peer_info.remote_address,
                            propagated_blocks: 0,
                            propagated_blocks_bytes: 0,
                        });

                    node_statistics.propagated_blocks += blocks as i64;

                    node_statistics.propagated_blocks_bytes += bytes as i64;
                }
            }
        }
    }

    pub(crate) fn log_consensus(&mut self, _peer_id: usize, bytelen: usize) {
        if self.logging_enabled {
            self.consensus_bytes += bytelen as i64;
            self.consensus_packages += 1;
        }
    }

    pub(crate) fn log_consensus_broadcast(&mut self, num_peers: usize, bytes_len: usize) {
        if self.logging_enabled {
            self.consensus_broadcast_bytes += (bytes_len * num_peers) as i64;
            self.consensus_broadcast_packages += num_peers as i64;
        }
    }

    pub(crate) fn log_propagated_hashes(&mut self, sent: usize, size: usize) {
        if self.logging_enabled {
            self.transaction_hashes_propagated += sent as i64;
            self.transaction_hashes_propagated_bytes += size as i64;
        }
    }

    pub(crate) fn log_propagated_transactions(&mut self, sent: usize, size: usize) {
        if self.logging_enabled {
            self.transactions_propagated += sent as i64;
            self.transactions_propagated_bytes += size as i64;
        }
    }

    pub(crate) fn log_requested_transactions_response(
        &mut self,
        num_txs: usize,
        bytes_sent: usize,
    ) {
        if self.logging_enabled {
            self.responded_transactions_bytes += bytes_sent as i64;
            self.responded_transactions += num_txs as i64;
        }
    }
}

impl PrometheusMetrics for SyncPropagatorStatistics {
    fn prometheus_metrics(&self, registry: &mut stats::PrometheusRegistry) {
        registry.register_counter(
            "p2p_propagated_blocks",
            "blocks sent",
            self.propagated_blocks,
        );
        registry.register_counter(
            "p2p_propagated_blocks_bytes",
            "block byte sent",
            self.propagated_blocks_bytes,
        );

        registry.register_counter(
            "p2p_cons_bytes",
            "consensus bytes sent",
            self.consensus_bytes,
        );

        registry.register_counter(
            "p2p_cons_package",
            "consensus packages sent",
            self.consensus_packages,
        );

        registry.register_counter(
            "p2p_cons_broadcast_bytes",
            "consensus bytes broadcasted",
            self.consensus_broadcast_bytes,
        );

        registry.register_counter(
            "p2p_cons_broadcast_packages",
            "total number consensus packages send through broadcast",
            self.consensus_broadcast_packages,
        );

        registry.register_counter(
            "p2p_propagated_txs",
            "transactions propagated",
            self.transactions_propagated,
        );

        registry.register_counter(
            "p2p_propagated_txs_bytes",
            "transactions propagated (byte size)",
            self.transactions_propagated_bytes,
        );

        registry.register_counter(
            "p2p_propagated_hashes",
            "transaction hashes propagated",
            self.transaction_hashes_propagated,
        );

        registry.register_counter(
            "p2p_propagated_hashes_bytes",
            "transaction hashes propagated (byte size)",
            self.transaction_hashes_propagated_bytes,
        );

        registry.register_counter(
            "p2p_responded_transactions",
            "number of responded transactions",
            self.responded_transactions,
        );

        registry.register_counter(
            "p2p_responded_transactions_bytes",
            "bytes of responded transactions",
            self.responded_transactions_bytes,
        );

        self.node_statistics
            .iter()
            .for_each(|(_, node_statistics)| {
                registry.register_gauge_with_other_node_label(
                    "p2p_propagated_blocks_peer",
                    "# blocks to peer",
                    &node_statistics.address,
                    node_statistics.propagated_blocks,
                );
                registry.register_gauge_with_other_node_label(
                    "p2p_propagated_bytes_peer",
                    "bytes to peer",
                    &node_statistics.address,
                    node_statistics.propagated_blocks_bytes,
                );
            });
    }
}
