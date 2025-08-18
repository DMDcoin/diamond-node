use ethereum_types::{Address, U256};
use std::str::FromStr;

use crate::{
    client::EngineClient,
    engines::hbbft::utils::bound_contract::{BoundContract, CallError},
    types::ids::BlockId,
};

use_contract!(permission_contract, "res/contracts/permission_hbbft.json");

lazy_static! {
    static ref PERMISSION_CONTRACT_ADDRESS: Address =
        Address::from_str("4000000000000000000000000000000000000001").unwrap();
}

macro_rules! call_const_permission {
    ($c:ident, $x:ident $(, $a:expr )*) => {
        $c.call_const(permission_contract::functions::$x::call($($a),*))
    };
}

pub fn get_minimum_gas_from_permission_contract(
    client: &dyn EngineClient,
    block_id: BlockId,
) -> Result<U256, CallError> {
    // permission_contract.
    //let decoder = permission_contract::functions::minimum_gas_price::call();
    // let decoder = random_hbbft_contract::functions::set_current_seed::call(random_value);
    //return U256::from_ decoder.0
    let c = BoundContract::bind(client, block_id, *PERMISSION_CONTRACT_ADDRESS);
    call_const_permission!(c, minimum_gas_price)
}
