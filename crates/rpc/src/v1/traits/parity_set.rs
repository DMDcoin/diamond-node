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

//! Parity-specific rpc interface for operations altering the settings.

use ethereum_types::{H160, H256, U256};
use jsonrpc_core::{BoxFuture, Result};
use jsonrpc_derive::rpc;

use crate::v1::types::{Bytes, Transaction};

/// Parity-specific rpc interface for operations altering the account-related settings.
#[rpc(server)]
pub trait ParitySetAccounts {
    /// Sets account for signing consensus messages.
    #[rpc(name = "parity_setEngineSigner")]
    fn set_engine_signer(&self, _: H160, _: String) -> Result<bool>;
}

/// Parity-specific rpc interface for operations altering the settings.
#[rpc(server)]
pub trait ParitySet {
    /// Sets new minimal gas price for mined blocks.
    #[rpc(name = "parity_setMinGasPrice")]
    fn set_min_gas_price(&self, _: U256) -> Result<bool>;

    /// Sets new gas floor target for mined blocks.
    #[rpc(name = "parity_setGasFloorTarget")]
    fn set_gas_floor_target(&self, _: U256) -> Result<bool>;

    /// Sets new gas ceiling target for mined blocks.
    #[rpc(name = "parity_setGasCeilTarget")]
    fn set_gas_ceil_target(&self, _: U256) -> Result<bool>;

    /// Sets new extra data for mined blocks.
    #[rpc(name = "parity_setExtraData")]
    fn set_extra_data(&self, _: Bytes) -> Result<bool>;

    /// Sets new author for mined block.
    #[rpc(name = "parity_setAuthor")]
    fn set_author(&self, _: H160) -> Result<bool>;

    /// Sets the secret of engine signer account.
    #[rpc(name = "parity_setEngineSignerSecret")]
    fn set_engine_signer_secret(&self, _: H256) -> Result<bool>;

    /// Unsets the engine signer account address.
    #[rpc(name = "parity_clearEngineSigner")]
    fn clear_engine_signer(&self) -> Result<bool>;

    /// Sets the limits for transaction queue.
    #[rpc(name = "parity_setTransactionsLimit")]
    fn set_transactions_limit(&self, _: usize) -> Result<bool>;

    /// Sets the maximum amount of gas a single transaction may consume.
    #[rpc(name = "parity_setMaxTransactionGas")]
    fn set_tx_gas_limit(&self, _: U256) -> Result<bool>;

    /// Add a reserved peer.
    #[rpc(name = "parity_addReservedPeer")]
    fn add_reserved_peer(&self, _: String) -> Result<bool>;

    /// Remove a reserved peer.
    #[rpc(name = "parity_removeReservedPeer")]
    fn remove_reserved_peer(&self, _: String) -> Result<bool>;

    /// Drop all non-reserved peers.
    #[rpc(name = "parity_dropNonReservedPeers")]
    fn drop_non_reserved_peers(&self) -> Result<bool>;

    /// Accept non-reserved peers (default behavior)
    #[rpc(name = "parity_acceptNonReservedPeers")]
    fn accept_non_reserved_peers(&self) -> Result<bool>;

    /// Start the network.
    ///
    /// @deprecated - Use `set_mode("active")` instead.
    #[rpc(name = "parity_startNetwork")]
    fn start_network(&self) -> Result<bool>;

    /// Stop the network.
    ///
    /// @deprecated - Use `set_mode("offline")` instead.
    #[rpc(name = "parity_stopNetwork")]
    fn stop_network(&self) -> Result<bool>;

    /// Set the mode. Argument must be one of: "active", "passive", "dark", "offline".
    #[rpc(name = "parity_setMode")]
    fn set_mode(&self, _: String) -> Result<bool>;

    /// Set the network spec. Argument must be one of pre-configured chains or a filename.
    #[rpc(name = "parity_setChain")]
    fn set_spec_name(&self, _: String) -> Result<bool>;

    /// Hash a file content under given URL.
    #[rpc(name = "parity_hashContent")]
    fn hash_content(&self, _: String) -> BoxFuture<H256>;

    /// Removes transaction from transaction queue.
    /// Makes sense only for transactions that were not propagated to other peers yet
    /// like scheduled transactions or transactions in future.
    /// It might also work for some local transactions with to low gas price
    /// or excessive gas limit that are not accepted by other peers whp.
    /// Returns `true` when transaction was removed, `false` if it was not found.
    #[rpc(name = "parity_removeTransaction")]
    fn remove_transaction(&self, _: H256) -> Result<Option<Transaction>>;
}
