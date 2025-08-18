use crate::{client::EngineClient, types::ids::BlockId};
use ethereum_types::{Address, H256, U256};
use std::str::FromStr;

use crate::{
    client::{BlockChainClient, traits::TransactionRequest},
    engines::hbbft::utils::bound_contract::{BoundContract, CallError},
};

use_contract!(
    connectivity_tracker_hbbft_contract,
    "res/contracts//hbbft_connectivity_tracker.json"
);

lazy_static! {
    static ref CONNECTIVITY_TRACKER_HBBFT_CONTRACT_ADDRESS: Address =
        Address::from_str("1200000000000000000000000000000000000001").unwrap();
}

macro_rules! call_const_connectivity_tracker_hbbft {
	($c:ident, $x:ident $(, $a:expr )*) => {
		$c.call_const(connectivity_tracker_hbbft_contract::functions::$x::call($($a),*))
	};
}

pub fn is_connectivity_loss_reported(
    client: &dyn EngineClient,
    block_id: BlockId,
    reporter: &Address,
    epoch: u64,
    validator: &Address,
) -> Result<bool, CallError> {
    let c = BoundContract::bind(
        client,
        block_id,
        *CONNECTIVITY_TRACKER_HBBFT_CONTRACT_ADDRESS,
    );
    return Ok(call_const_connectivity_tracker_hbbft!(
        c,
        is_reported,
        epoch,
        *validator,
        *reporter
    )?);
}

// currently not required for operation.
// we just check if "we" have reported the validator.
// pub fn get_current_flagged_validators_from_contract(
//     client: &dyn EngineClient,
//     block_id: BlockId,
// ) -> Result<Vec<Address>, CallError> {
//     let c = BoundContract::bind(
//         client,
//         block_id,
//         *CONNECTIVITY_TRACKER_HBBFT_CONTRACT_ADDRESS,
//     );
//     return Ok(call_const_connectivity_tracker_hbbft!(
//         c,
//         get_flagged_validators
//     )?);
// }

fn get_block_data(client: &dyn EngineClient) -> (u64, H256) {
    if let Some(block_number) = client.block_number(BlockId::Latest) {
        if let Some(header) = client.block_header(BlockId::Number(block_number - 1)) {
            return (header.number(), header.hash());
        } else {
            warn!(target:"engine", "early-epoch-end: could not get block number for block: {block_number}");
            return (0, H256::zero());
        }
    } else {
        warn!(target:"engine", "early-epoch-end: could not get latest block.");
        return (0, H256::zero());
    };
}

pub fn report_missing_connectivity(
    client: &dyn EngineClient,
    full_client: &dyn BlockChainClient,
    missing_validator: &Address,
    signing_address: &Address,
) -> bool {
    let (block_number, block_hash) = get_block_data(client);
    if block_number == 0 {
        return false;
    }

    let send_data =
        connectivity_tracker_hbbft_contract::functions::report_missing_connectivity::call(
            *missing_validator,
            block_number,
            block_hash,
        );

    let nonce = full_client.next_nonce(signing_address);

    let transaction =
        TransactionRequest::call(*CONNECTIVITY_TRACKER_HBBFT_CONTRACT_ADDRESS, send_data.0)
            .gas(U256::from(500_000))
            .gas_price(U256::from(10000000000u64))
            .nonce(nonce);

    info!(target:"engine", "early-epoch-end: sending report_missing_connectivity for with nonce: {nonce}, missing: {:?} ", missing_validator);
    if let Err(e) = full_client.transact_silently(transaction) {
        warn!(target:"engine", "early-epoch-end: could not report_missing_connectivity {e:?}");
        return false;
    }
    return true;
}

pub fn report_reconnect(
    client: &dyn EngineClient,
    full_client: &dyn BlockChainClient,
    reconnected_validator: &Address,
    signing_address: &Address,
) -> bool {
    let (block_number, block_hash) = get_block_data(client);
    if block_number == 0 {
        return false;
    }

    let send_data = connectivity_tracker_hbbft_contract::functions::report_reconnect::call(
        *reconnected_validator,
        block_number,
        block_hash,
    );

    let nonce = full_client.next_nonce(signing_address);

    let transaction =
        TransactionRequest::call(*CONNECTIVITY_TRACKER_HBBFT_CONTRACT_ADDRESS, send_data.0)
            .gas(U256::from(200_000))
            .nonce(nonce);

    info!(target:"engine", "early-epoch-end: sending report_reconnect for with nonce: {nonce}, missing: {:?} ", reconnected_validator);
    if let Err(e) = full_client.transact_silently(transaction) {
        warn!(target:"engine", "early-epoch-end: could not report_missing_connectivity {e:?}");
        return false;
    }
    return true;
}
