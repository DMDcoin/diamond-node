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

#![warn(missing_docs, unused_extern_crates)]

//! Ethcore library

extern crate common_types as types;
extern crate ethcore_blockchain as blockchain;
extern crate ethcore_builtin as builtin;
extern crate ethcore_call_contract as call_contract;
extern crate ethcore_db as db;
extern crate ethcore_io as io;
extern crate keccak_hash as hash;
extern crate parity_bytes as bytes;
extern crate parity_crypto as crypto;
extern crate parity_snappy as snappy;
extern crate patricia_trie_ethereum as ethtrie;
extern crate trie_db as trie;
extern crate triehash_ethereum as triehash;

#[cfg(any(test, feature = "blooms-db"))]
extern crate blooms_db;
#[cfg(test)]
extern crate ethcore_accounts as accounts;
#[cfg(any(test, feature = "kvdb-rocksdb"))]
extern crate kvdb_rocksdb;

#[macro_use]
extern crate ethabi_contract;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate macros;
#[macro_use]
extern crate rlp_derive;
#[macro_use]
extern crate trace_time;
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
use evm;

pub mod block;
pub mod client;
pub mod engines;
pub mod error;
pub mod ethereum;
pub mod executed;
pub mod executive;
pub mod exit;
pub mod machine;
pub mod miner;
pub mod pod_account;
pub mod pod_state;
pub mod snapshot;
pub mod spec;
pub mod state;
pub mod state_db;
pub mod trace;
pub mod transaction_ext;
pub mod verification;

mod account_db;
mod externalities;
mod factory;
mod tx_filter;

#[cfg(feature = "json-tests")]
pub mod json_tests;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;
#[cfg(test)]
mod tests;

pub use crate::executive::contract_address;
pub use evm::CreateContractAddress;
pub use trie::TrieSpec;
