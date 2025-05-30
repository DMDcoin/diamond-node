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

//! A service transactions contract checker.

use crate::types::{ids::BlockId, transaction::SignedTransaction};
use call_contract::{CallContract, RegistryInfo};
use ethabi::FunctionOutputDecoder;
use ethereum_types::Address;
use parking_lot::RwLock;
use std::{collections::HashMap, str::FromStr, sync::Arc};

use_contract!(
    service_transaction,
    "res/contracts/service_transaction.json"
);

/// Service transactions checker.
#[derive(Default, Clone)]
pub struct ServiceTransactionChecker {
    certified_addresses_cache: Arc<RwLock<HashMap<Address, bool>>>,
}

impl ServiceTransactionChecker {
    /// Checks if given address in tx is whitelisted to send service transactions.
    pub fn check<C: CallContract + RegistryInfo>(
        &self,
        client: &C,
        tx: &SignedTransaction,
    ) -> Result<bool, String> {
        let sender = tx.sender();
        // Skip checking the contract if the transaction does not have zero gas price
        if !tx.has_zero_gas_price() {
            return Ok(false);
        }

        self.check_address(client, sender)
    }

    /// Checks if given address is whitelisted to send service transactions.
    pub fn check_address<C: CallContract + RegistryInfo>(
        &self,
        client: &C,
        sender: Address,
    ) -> Result<bool, String> {
        trace!(target: "txqueue", "Checking service transaction checker contract for {}", sender);
        if let Some(allowed) = self
            .certified_addresses_cache
            .try_read()
            .as_ref()
            .and_then(|c| c.get(&sender))
        {
            return Ok(*allowed);
        }
        let x = Address::from_str("5000000000000000000000000000000000000001".into()).unwrap();
        let contract_address = x;

        trace!(target: "txfilter", "Checking service transaction from contract for: {}", sender);

        self.call_contract(client, contract_address, sender)
            .and_then(|allowed| {
                if let Some(mut cache) = self.certified_addresses_cache.try_write() {
                    cache.insert(sender, allowed);
                };
                Ok(allowed)
            })
    }

    /// Refresh certified addresses cache
    pub fn refresh_cache<C: CallContract + RegistryInfo>(
        &self,
        _client: &C,
    ) -> Result<bool, String> {
        trace!(target: "txqueue", "Refreshing certified addresses cache");

        self.certified_addresses_cache.write().clear();

        Ok(true)
    }

    fn call_contract<C: CallContract + RegistryInfo>(
        &self,
        client: &C,
        contract_address: Address,
        sender: Address,
    ) -> Result<bool, String> {
        let (data, decoder) = service_transaction::functions::certified::call(sender);
        let value = client.call_contract(BlockId::Latest, contract_address, data)?;
        decoder.decode(&value).map_err(|e| e.to_string())
    }
}
