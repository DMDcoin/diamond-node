// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Open Ethereum.

// Open Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Open Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Open Ethereum.  If not, see <http://www.gnu.org/licenses/>.

//! Types for declaring block rewards and a client interface for interacting with a
//! block reward contract.

use crate::{
    engines::{SystemOrCodeCall, SystemOrCodeCallKind},
    error::Error,
};
use ethabi::FunctionOutputDecoder;
use ethabi_contract::use_contract;
use ethereum_types::Address;

use_contract!(
    block_reward_contract,
    "res/contracts/block_reward_hbbft.json"
);

/// A client for the block reward contract.
#[derive(PartialEq, Debug)]
pub struct BlockRewardContract {
    kind: SystemOrCodeCallKind,
}

impl BlockRewardContract {
    /// Create a new block reward contract client targeting the system call kind.
    pub fn new(kind: SystemOrCodeCallKind) -> BlockRewardContract {
        BlockRewardContract { kind }
    }

    /// Create a new block reward contract client targeting the contract address.
    pub fn new_from_address(address: Address) -> BlockRewardContract {
        Self::new(SystemOrCodeCallKind::Address(address))
    }

    /// Calls the block reward contract with the given beneficiaries list (and associated reward kind)
    /// and returns the reward allocation (address - value). The block reward contract *must* be
    /// called by the system address so the `caller` must ensure that (e.g. using
    /// `machine.execute_as_system`).
    pub fn reward(&self, caller: &mut SystemOrCodeCall, is_epoch_end: bool) -> Result<(), Error> {
        let (input, decoder) = block_reward_contract::functions::reward::call(is_epoch_end);
        let output = caller(self.kind.clone(), input)
            .map_err(Into::into)
            .map_err(crate::engines::EngineError::FailedSystemCall)?;

        match decoder.decode(&output) {
            Ok(_rewards_native) => {}
            Err(err) => {
                debug!(target: "engine", "Failed to decode block reward contract. output length {:?} output: {:?}: Error {:?}", output.len(), output, err);
            }
        }

        return Ok(());

        // let rewards_native = decoder
        //     .decode(&output)
        //     .map_err(|err| err.to_string())
        //     .map_err(crate::engines::EngineError::FailedSystemCall)?;
    }
}
