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

//! OpenEthereum JSON-RPC Servers (WS, HTTP, IPC).

#![warn(missing_docs, unused_extern_crates)]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::all, clippy::pedantic))]
#![cfg_attr(
	feature = "cargo-clippy",
	allow(
		// things are often more readable this way
		clippy::cast_lossless,
		clippy::module_name_repetitions,
		clippy::single_match_else,
		clippy::type_complexity,
		clippy::use_self,
		// not practical
		clippy::match_bool,
		clippy::needless_pass_by_value,
		clippy::similar_names,
		// don't require markdown syntax for docs
		clippy::doc_markdown,
	),
	warn(clippy::indexing_slicing)
)]

#[macro_use]
extern crate futures;

use order_stat;
use tokio_timer;

use jsonrpc_core;
extern crate jsonrpc_http_server as http;
extern crate jsonrpc_ipc_server as ipc;
use jsonrpc_pubsub;

extern crate common_types as types;
use ethash;
extern crate ethcore_miner as miner;
extern crate ethcore_network as network;
extern crate ethcore_sync as sync;
use fetch;
extern crate keccak_hash as hash;
extern crate parity_bytes as bytes;
extern crate parity_crypto as crypto;
use parity_runtime;
extern crate parity_version as version;
use rlp;

#[cfg(any(test, feature = "ethcore-accounts"))]
extern crate ethcore_accounts as accounts;

#[cfg(any(test, feature = "ethcore-accounts"))]
extern crate tiny_keccak;

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
use ethjson;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[cfg(test)]
#[macro_use]
extern crate macros;

#[cfg(test)]
extern crate fake_fetch;

#[cfg(test)]
extern crate ethcore_io as io;

#[cfg(test)]
extern crate ethcore_call_contract as call_contract;

// #[cfg(test)]

#[cfg(test)]
extern crate rpc_servers;

pub extern crate jsonrpc_ws_server as ws;

mod authcodes;
pub mod v1;

// #[cfg(test)]
pub mod tests;

pub use http::{
    AccessControlAllowOrigin, DomainsValidation, Host, RequestMiddleware, RequestMiddlewareAction,
    cors::AccessControlAllowHeaders, hyper,
};
pub use ipc::{
    MetaExtractor as IpcMetaExtractor, RequestContext as IpcRequestContext, Server as IpcServer,
};
pub use jsonrpc_pubsub::Session as PubSubSession;

pub use crate::{
    authcodes::{AuthCodes, TimeProvider},
    v1::{
        Metadata, NetworkSettings, Origin,
        block_import::{is_major_importing, is_major_importing_or_waiting},
        dispatch,
        extractors::{RpcExtractor, WsDispatcher, WsExtractor, WsStats},
        informant, signer,
    },
};

/// RPC HTTP Server instance
pub type HttpServer = http::Server;
