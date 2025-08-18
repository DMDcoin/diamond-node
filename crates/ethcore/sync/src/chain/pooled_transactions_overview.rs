use std::{num::NonZeroUsize, time::Instant};

use fastmap::{H256FastLruMap, new_h256_fast_lru_map};
use hash::H256;

/// memorizs currently pooled transactions, so they are not pooled to often from different hosts.
pub(crate) struct PooledTransactionOverview {
    //  number_of_requests: H256FastMap<usize>,
    /// The cache of pooled transactions.
    last_fetched: H256FastLruMap<Instant>,
}

impl PooledTransactionOverview {
    /// Create a new `PooledTransactionOverview` with a given maximum cache size.
    pub fn new() -> Self {
        // we are defaulting here to a memory usage of maximum 1 MB netto data.
        // 40 byte per entry (32 byte hash + 8 byte usize)
        // so we can store about 26214 cached entries per megabyte of date.

        Self {
            last_fetched: new_h256_fast_lru_map::<Instant>(
                NonZeroUsize::new(26214).unwrap(), /* about 1 MB + some overhead */
            ),
        }
    }

    /// Check if a transaction is already pooled.
    pub fn get_last_fetched(&mut self, hash: &H256) -> Option<&Instant> {
        self.last_fetched.get(hash)
    }

    /// Add a transaction to the cache.
    pub fn report_transaction_pooling(&mut self, hash: &H256) {
        self.last_fetched.push(hash.clone(), Instant::now());
    }

    // pub fn report_transaction_pooling_finished(&mut self, hash: &H256) {
    //     self.last_fetched.pop(hash);
    //     // if we tried to access an entry that is not in the map, we ignore it.
    // }
}
