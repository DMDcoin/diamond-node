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

#![warn(missing_docs)]

//! Miner module
//! Keeps track of transactions and currently sealed pending block.

mod cache;
mod miner;

pub mod pool_client;
#[cfg(feature = "stratum")]
pub mod stratum;

pub use self::miner::{Author, AuthoringParams, Miner, MinerOptions, Penalization, PendingSet};
pub use ethcore_miner::{
    local_accounts::LocalAccounts,
    pool::{PendingOrdering, transaction_filter::TransactionFilter},
};

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use crate::types::{
    BlockNumber,
    block::Block,
    header::Header,
    receipt::RichReceipt,
    transaction::{self, PendingTransaction, SignedTransaction, UnverifiedTransaction},
};
use bytes::Bytes;
use ethcore_miner::pool::{QueueStatus, VerifiedTransaction, local_transactions};
use ethereum_types::{Address, H256, U256};

use crate::{
    block::SealedBlock,
    client::{
        AccountData, BlockChain, BlockProducer, Nonce, ScheduleInfo, SealedBlockImporter,
        traits::ForceUpdateSealing,
    },
    error::Error,
    state::StateInfo,
};
use call_contract::{CallContract, RegistryInfo};

/// Provides methods to verify incoming external transactions
pub trait TransactionVerifierClient: Send + Sync
	// Required for ServiceTransactionChecker
	+ CallContract + RegistryInfo
	// Required for verifiying transactions
	+ BlockChain + ScheduleInfo + AccountData
{}

/// Extended client interface used for mining
pub trait BlockChainClient:
    TransactionVerifierClient + BlockProducer + SealedBlockImporter
{
}

/// Miner client API
pub trait MinerService: Send + Sync {
    /// Type representing chain state
    type State: StateInfo + 'static;

    // Sealing

    /// Submit `seal` as a valid solution for the header of `pow_hash`.
    /// Will check the seal, but not actually insert the block into the chain.
    fn submit_seal(&self, pow_hash: H256, seal: Vec<Bytes>) -> Result<SealedBlock, Error>;

    /// Is it currently sealing?
    fn is_currently_sealing(&self) -> bool;

    /// Get the sealing work package preparing it if doesn't exist yet.
    ///
    /// Returns `None` if engine seals internally.
    fn work_package<C>(&self, chain: &C) -> Option<(H256, BlockNumber, u64, U256)>
    where
        C: BlockChain + CallContract + BlockProducer + SealedBlockImporter + Nonce + Sync;

    /// Update current pending block
    fn update_sealing<C>(&self, chain: &C, force: ForceUpdateSealing)
    where
        C: BlockChain + CallContract + BlockProducer + SealedBlockImporter + Nonce + Sync;

    // Notifications

    /// Called when blocks are imported to chain, updates transactions queue.
    /// `is_internal_import` indicates that the block has just been created in miner and internally sealed by the engine,
    /// so we shouldn't attempt creating new block again.
    fn chain_new_blocks<C>(
        &self,
        chain: &C,
        imported: &[H256],
        invalid: &[H256],
        enacted: &[H256],
        retracted: &[H256],
        is_internal_import: bool,
    ) where
        C: BlockChainClient;

    // Pending block

    /// Get a list of all pending receipts from pending block.
    fn pending_receipts(&self, best_block: BlockNumber) -> Option<Vec<RichReceipt>>;

    /// Get a particular receipt from pending block.
    fn pending_receipt(&self, best_block: BlockNumber, hash: &H256) -> Option<RichReceipt> {
        let receipts = self.pending_receipts(best_block)?;
        receipts.into_iter().find(|r| &r.transaction_hash == hash)
    }

    /// Get `Some` `clone()` of the current pending block's state or `None` if we're not sealing.
    fn pending_state(&self, latest_block_number: BlockNumber) -> Option<Self::State>;

    /// Get `Some` `clone()` of the current pending block header or `None` if we're not sealing.
    fn pending_block_header(&self, latest_block_number: BlockNumber) -> Option<Header>;

    /// Get `Some` `clone()` of the current pending block or `None` if we're not sealing.
    fn pending_block(&self, latest_block_number: BlockNumber) -> Option<Block>;

    /// Get `Some` `clone()` of the current pending block transactions or `None` if we're not sealing.
    fn pending_transactions(
        &self,
        latest_block_number: BlockNumber,
    ) -> Option<Vec<SignedTransaction>>;

    // Block authoring

    /// Get current authoring parameters.
    fn authoring_params(&self) -> AuthoringParams;

    /// Set the lower and upper bound of gas limit we wish to target when sealing a new block.
    fn set_gas_range_target(&self, gas_range_target: (U256, U256));

    /// Set the extra_data that we will seal blocks with.
    fn set_extra_data(&self, extra_data: Bytes);

    /// Set info necessary to sign consensus messages and block authoring.
    ///
    /// On chains where sealing is done externally (e.g. PoW) we provide only reward beneficiary.
    fn set_author<T: Into<Option<Author>>>(&self, author: T);

    // Transaction Pool

    /// Imports transactions to transaction queue.
    fn import_external_transactions<C>(
        &self,
        client: &C,
        transactions: Vec<UnverifiedTransaction>,
    ) -> Vec<Result<(), transaction::Error>>
    where
        C: BlockChainClient;

    /// Imports own (node owner) transaction to queue.
    fn import_own_transaction<C>(
        &self,
        chain: &C,
        transaction: PendingTransaction,
        silently: bool,
    ) -> Result<(), transaction::Error>
    where
        C: BlockChainClient;

    /// Imports transactions from potentially external sources, with behaviour determined
    /// by the config flag `tx_queue_allow_unfamiliar_locals`
    fn import_claimed_local_transaction<C>(
        &self,
        chain: &C,
        transaction: PendingTransaction,
        trusted: bool,
    ) -> Result<(), transaction::Error>
    where
        C: BlockChainClient;

    /// Removes transaction from the pool.
    ///
    /// Attempts to "cancel" a transaction. If it was not propagated yet (or not accepted by other peers)
    /// there is a good chance that the transaction will actually be removed.
    /// NOTE: The transaction is not removed from pending block if there is one.
    fn remove_transaction(&self, hash: &H256) -> Option<Arc<VerifiedTransaction>>;

    /// Query transaction from the pool given it's hash.
    fn transaction(&self, hash: &H256) -> Option<Arc<VerifiedTransaction>>;

    /// Query transaction from the pool given it's hash, without blocking.
    /// Might return "None" in cases when the lock could not get acquired.
    fn transaction_if_readable(
        &self,
        hash: &H256,
        max_lock_duration: &Duration,
    ) -> Option<Arc<VerifiedTransaction>>;

    /// Returns next valid nonce for given address.
    ///
    /// This includes nonces of all transactions from this address in the pending queue
    /// if they are consecutive.
    /// NOTE: pool may contain some future transactions that will become pending after
    /// transaction with nonce returned from this function is signed on.
    fn next_nonce<C>(&self, chain: &C, address: &Address) -> U256
    where
        C: Nonce + Sync;

    /// Get a set of all pending transaction hashes.
    ///
    /// Depending on the settings may look in transaction pool or only in pending block.
    fn pending_transaction_hashes<C>(&self, chain: &C) -> BTreeSet<H256>
    where
        C: BlockChain + CallContract + Nonce + Sync;

    /// Get a list of all ready transactions either ordered by priority or unordered (cheaper),
    /// and optionally filtered by sender, recipient, gas, gas price, value and/or nonce.
    ///
    /// Depending on the settings may look in transaction pool or only in pending block.
    /// If you don't need a full set of transactions, you can add `max_len` and create only a limited set of
    /// transactions.
    fn ready_transactions_filtered<C>(
        &self,
        chain: &C,
        max_len: usize,
        filter: Option<TransactionFilter>,
        ordering: PendingOrdering,
    ) -> Vec<Arc<VerifiedTransaction>>
    where
        C: BlockChain + CallContract + Nonce + Sync;

    /// Get an unfiltered list of all ready transactions.
    fn ready_transactions<C>(
        &self,
        chain: &C,
        max_len: usize,
        ordering: PendingOrdering,
    ) -> Vec<Arc<VerifiedTransaction>>
    where
        C: BlockChain + CallContract + Nonce + Sync,
    {
        self.ready_transactions_filtered(chain, max_len, None, ordering)
    }

    /// Get a list of queued transactions in the pool (some of them might not be ready for inclusion yet).
    fn queued_transactions<C>(&self, chain: &C) -> Vec<Arc<VerifiedTransaction>>
    where
        C: BlockChain + CallContract + Nonce + Sync;

    /// Get a list of all transactions in the pool (some of them might not be ready for inclusion yet).
    fn all_transactions(&self) -> Vec<Arc<VerifiedTransaction>>;

    /// Get a list of all transaction hashes in the pool (some of them might not be ready for inclusion yet).
    fn queued_transaction_hashes(&self) -> Vec<H256>;

    /// Get a list of local transactions with statuses.
    fn local_transactions(&self) -> BTreeMap<H256, local_transactions::Status>;

    /// Get current queue status.
    ///
    /// Status includes verification thresholds and current pool utilization and limits.
    fn queue_status(&self) -> QueueStatus;

    // Misc

    /// Suggested gas price.
    fn sensible_gas_price(&self) -> U256;

    /// Suggested max priority fee gas price
    fn sensible_max_priority_fee(&self) -> U256;

    /// Suggested gas limit.
    fn sensible_gas_limit(&self) -> U256;

    /// Set a new minimum gas limit.
    /// Will not work if dynamic gas calibration is set.
    fn set_minimal_gas_price(&self, gas_price: U256) -> Result<bool, &str>;
}
