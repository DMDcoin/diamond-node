use crate::types::transaction::{Action, SignedTransaction, Transaction, TypedTransaction};
use crypto::publickey::KeyPair;
use ethereum_types::{Address, U256};

pub fn create_transaction(keypair: &KeyPair, nonce: &U256) -> SignedTransaction {
    TypedTransaction::Legacy(Transaction {
        action: Action::Call(Address::from_low_u64_be(5798439875)),
        value: U256::zero(),
        data: vec![],
        gas: U256::from(100_000),
        gas_price: "10000000000".into(),
        nonce: *nonce,
    })
    .sign(keypair.secret(), None)
}

pub fn create_transfer(
    keypair: &KeyPair,
    receiver: &Address,
    amount: &U256,
    nonce: &U256,
) -> SignedTransaction {
    TypedTransaction::Legacy(Transaction {
        action: Action::Call(receiver.clone()),
        value: amount.clone(),
        data: vec![],
        gas: U256::from(100_000),
        gas_price: "10000000000".into(),
        nonce: *nonce,
    })
    .sign(keypair.secret(), None)
}

pub fn create_call(
    keypair: &KeyPair,
    receiver: &Address,
    abi_call: ethabi::Bytes,
    amount: &U256,
    nonce: &U256,
) -> SignedTransaction {
    TypedTransaction::Legacy(Transaction {
        action: Action::Call(receiver.clone()),
        value: amount.clone(),
        data: abi_call,
        gas: U256::from(900_000),
        gas_price: "10000000000".into(),
        nonce: *nonce,
    })
    .sign(keypair.secret(), None)
}
