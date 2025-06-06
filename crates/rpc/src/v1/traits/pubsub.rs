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

//! Parity-specific PUB-SUB rpc interface.

use jsonrpc_core::{Params, Result, Value};
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{SubscriptionId, typed::Subscriber};

/// Parity-specific PUB-SUB rpc interface.
#[rpc(server)]
pub trait PubSub {
    /// Pub/Sub Metadata
    type Metadata;

    /// Subscribe to changes of any RPC method in Parity.
    #[pubsub(
        subscription = "parity_subscription",
        subscribe,
        name = "parity_subscribe"
    )]
    fn parity_subscribe(
        &self,
        _: Self::Metadata,
        _: Subscriber<Value>,
        _: String,
        _: Option<Params>,
    );

    /// Unsubscribe from existing Parity subscription.
    #[pubsub(
        subscription = "parity_subscription",
        unsubscribe,
        name = "parity_unsubscribe"
    )]
    fn parity_unsubscribe(&self, _: Option<Self::Metadata>, _: SubscriptionId) -> Result<bool>;
}
