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

mod contract;
mod multi;
mod safe_contract;
mod simple_list;
/// Validator lists.

#[cfg(test)]
mod test;

use std::sync::Weak;

use crate::{
    machine::{AuxiliaryData, Call, EthereumMachine},
    types::{BlockNumber, header::Header, ids::BlockId},
};
use bytes::Bytes;
use ethereum_types::{Address, H256};
use ethjson::spec::ValidatorSet as ValidatorSpec;

use crate::client::EngineClient;

use crate::error::Error as EthcoreError;

pub use self::simple_list::SimpleList;
#[cfg(test)]
pub use self::test::TestSet;
use self::{contract::ValidatorContract, multi::Multi, safe_contract::ValidatorSafeContract};
use super::SystemCall;

/// Creates a validator set from the given spec and initializes a transition to POSDAO AuRa consensus.
pub fn new_validator_set_posdao(
    spec: ValidatorSpec,
    posdao_transition: Option<BlockNumber>,
) -> Box<dyn ValidatorSet> {
    match spec {
        ValidatorSpec::List(list) => {
            Box::new(SimpleList::new(list.into_iter().map(Into::into).collect()))
        }
        ValidatorSpec::SafeContract(address) => Box::new(ValidatorSafeContract::new(
            address.into(),
            posdao_transition,
        )),
        ValidatorSpec::Contract(address) => {
            Box::new(ValidatorContract::new(address.into(), posdao_transition))
        }
        ValidatorSpec::Multi(sequence) => Box::new(Multi::new(
            sequence
                .into_iter()
                .map(|(block, set)| {
                    (
                        block.into(),
                        new_validator_set_posdao(set, posdao_transition),
                    )
                })
                .collect(),
        )),
    }
}

/// Creates a validator set from the given spec.
pub fn new_validator_set(spec: ValidatorSpec) -> Box<dyn ValidatorSet> {
    new_validator_set_posdao(spec, None)
}

/// A validator set.
pub trait ValidatorSet: Send + Sync + 'static {
    /// Get the default "Call" helper, for use in general operation.
    // TODO [keorn]: this is a hack intended to migrate off of
    // a strict dependency on state always being available.
    fn default_caller(&self, block_id: BlockId) -> Box<Call>;

    /// Called for each new block this node is creating.  If this block is
    /// the first block of an epoch, this is called *after* `on_epoch_begin()`,
    /// but with the same parameters.
    ///
    /// Returns a list of contract calls to be pushed onto the new block.
    fn generate_engine_transactions(
        &self,
        _first: bool,
        _header: &Header,
        _call: &mut SystemCall,
    ) -> Result<Vec<(Address, Bytes)>, EthcoreError>;

    /// Called on the close of every block.
    fn on_close_block(&self, _header: &Header, _address: &Address) -> Result<(), EthcoreError>;

    /// Checks if a given address is a validator,
    /// using underlying, default call mechanism.
    fn contains(&self, parent: &H256, address: &Address) -> bool {
        let default = self.default_caller(BlockId::Hash(*parent));
        self.contains_with_caller(parent, address, &*default)
    }

    /// Draws an validator nonce modulo number of validators.
    fn get(&self, parent: &H256, nonce: usize) -> Address {
        let default = self.default_caller(BlockId::Hash(*parent));
        self.get_with_caller(parent, nonce, &*default)
    }

    /// Returns the current number of validators.
    fn count(&self, parent: &H256) -> usize {
        let default = self.default_caller(BlockId::Hash(*parent));
        self.count_with_caller(parent, &*default)
    }

    /// Signalling that a new epoch has begun.
    ///
    /// All calls here will be from the `SYSTEM_ADDRESS`: 2^160 - 2
    /// and will have an effect on the block's state.
    /// The caller provided here may not generate proofs.
    ///
    /// `first` is true if this is the first block in the set.
    fn on_epoch_begin(
        &self,
        _first: bool,
        _header: &Header,
        _call: &mut SystemCall,
    ) -> Result<(), crate::error::Error> {
        Ok(())
    }

    /// Extract genesis epoch data from the genesis state and header.
    fn genesis_epoch_data(&self, _header: &Header, _call: &Call) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    /// Whether this block is the last one in its epoch.
    ///
    /// Indicates that the validator set changed at the given block in a manner
    /// that doesn't require finality.
    ///
    /// `first` is true if this is the first block in the set.
    fn is_epoch_end(&self, first: bool, chain_head: &Header) -> Option<Vec<u8>>;

    /// Whether the given block signals the end of an epoch, but change won't take effect
    /// until finality.
    ///
    /// Engine should set `first` only if the header is genesis. Multiplexing validator
    /// sets can set `first` to internal changes.
    fn signals_epoch_end(
        &self,
        first: bool,
        header: &Header,
        aux: AuxiliaryData,
    ) -> crate::engines::EpochChange<EthereumMachine>;

    /// Recover the validator set from the given proof, the block number, and
    /// whether this header is first in its set.
    ///
    /// May fail if the given header doesn't kick off an epoch or
    /// the proof is invalid.
    ///
    /// Returns the set, along with a flag indicating whether finality of a specific
    /// hash should be proven.
    fn epoch_set(
        &self,
        first: bool,
        machine: &EthereumMachine,
        number: BlockNumber,
        proof: &[u8],
    ) -> Result<(SimpleList, Option<H256>), crate::error::Error>;

    /// Checks if a given address is a validator, with the given function
    /// for executing synchronous calls to contracts.
    fn contains_with_caller(
        &self,
        parent_block_hash: &H256,
        address: &Address,
        caller: &Call,
    ) -> bool;

    /// Draws an validator nonce modulo number of validators.
    fn get_with_caller(&self, parent_block_hash: &H256, nonce: usize, caller: &Call) -> Address;

    /// Returns the current number of validators.
    fn count_with_caller(&self, parent_block_hash: &H256, caller: &Call) -> usize;

    /// Notifies about malicious behaviour.
    fn report_malicious(
        &self,
        _validator: &Address,
        _set_block: BlockNumber,
        _block: BlockNumber,
        _proof: Bytes,
    ) {
    }
    /// Notifies about benign misbehaviour.
    fn report_benign(&self, _validator: &Address, _set_block: BlockNumber, _block: BlockNumber) {}
    /// Allows blockchain state access.
    fn register_client(&self, _client: Weak<dyn EngineClient>) {}
}
