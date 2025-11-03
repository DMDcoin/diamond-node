use super::create_transactions::{create_call, create_transaction, create_transfer};
use crate::{
    client::{
        BlockChainClient, ChainSyncing, Client, ImportExportBlocks,
        traits::{Balance, StateOrBlock},
    },
    engines::signer::from_keypair,
    miner::{Miner, MinerService},
    spec::Spec,
    test_helpers::{TestNotify, generate_dummy_client_with_spec},
    types::{data_format::DataFormat, ids::BlockId},
};
use crypto::publickey::{Generator, KeyPair, Random};
use ethereum_types::{Address, U256};
use parking_lot::RwLock;
use std::{ops::Deref, sync::Arc};

pub fn hbbft_spec() -> Spec {
    Spec::load(
        &::std::env::temp_dir(),
        include_bytes!("../../../../res/chainspec/honey_badger_bft.json") as &[u8],
    )
    .expect(concat!("Chain spec is invalid."))
}

struct SyncProviderWrapper();
impl ChainSyncing for SyncProviderWrapper {
    fn is_major_syncing(&self) -> bool {
        false
    }

    fn is_syncing(&self) -> bool {
        false
    }
}

pub fn hbbft_client() -> std::sync::Arc<Client> {
    let client = generate_dummy_client_with_spec(hbbft_spec);
    client.set_sync_provider(Box::new(SyncProviderWrapper()));
    client
}

#[derive(Clone)]
pub struct HbbftTestClient {
    pub client: Arc<Client>,
    pub notify: Arc<TestNotify>,
    pub miner: Arc<Miner>,
    pub keypair: KeyPair,
}

impl HbbftTestClient {
    pub fn transfer_to(&mut self, receiver: &Address, amount: &U256) {
        self.transfer(&self.keypair.clone(), receiver, amount);
    }

    pub fn transfer(&mut self, sender: &KeyPair, receiver: &Address, amount: &U256) {
        let nonce = self.client.next_nonce(&sender.address());
        let transaction = create_transfer(sender, receiver, amount, &nonce);
        if let Err(err) =
            self.miner
                .import_own_transaction(self.client.as_ref(), transaction.into(), false)
        {
            //err.
            error!(
                "could not transfer from {:?} to {:?} error: {:?}",
                sender.address(),
                receiver,
                err
            );
        }
    }

    // Trigger a generic transaction to force block creation.
    pub fn create_some_transaction(&mut self, caller: Option<&KeyPair>) {
        let keypair = caller.unwrap_or(&self.keypair);
        let cur_nonce = self.client.next_nonce(&keypair.address());
        let transaction = create_transaction(keypair, &cur_nonce);
        self.miner
            .import_own_transaction(self.client.as_ref(), transaction.into(), false)
            .unwrap();
    }

    pub fn call_as(
        &mut self,
        caller: &KeyPair,
        receiver: &Address,
        abi_call: ethabi::Bytes,
        amount: &U256,
    ) {
        let cur_nonce = self.client.next_nonce(&caller.address());
        let transaction = create_call(caller, receiver, abi_call, amount, &cur_nonce);
        self.miner
            .import_claimed_local_transaction(self.client.as_ref(), transaction.into(), false)
            .unwrap();
    }

    pub fn balance(&self, address: &Address) -> U256 {
        self.client
            .balance(address, StateOrBlock::Block(BlockId::Latest))
            .expect("Querying address balance should always succeed.")
    }

    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    pub fn sync_blocks_to(&self, other: &mut Self) {
        let self_block_nr = self.client.chain().best_block_number();
        let other_block_nr = other.client.chain().best_block_number();

        if self_block_nr <= other_block_nr {
            return;
        }

        let mut out = Vec::new();
        self.client
            .export_blocks(
                Box::new(&mut out),
                BlockId::Number(other_block_nr + 1),
                BlockId::Number(self_block_nr),
                Some(DataFormat::Binary),
            )
            .unwrap();

        other
            .client
            .import_blocks(Box::new(&*out), Some(DataFormat::Binary))
            .unwrap();
    }

    pub fn sync_transactions_to(&self, other: &mut Self) {
        let transactions = self
            .miner
            .all_transactions()
            //.transactions_to_propagate()
            .iter()
            .map(|i| i.signed().deref().clone())
            .collect();

        other
            .miner
            .import_external_transactions(&*self.client, transactions);
    }
}

pub fn create_hbbft_client(keypair: KeyPair) -> HbbftTestClient {
    let client = hbbft_client();
    let miner = client.miner();
    let engine = client.engine();
    let signer = from_keypair(keypair.clone());
    engine.set_signer(Some(signer));
    engine.register_client(Arc::downgrade(&client) as _);
    let notify = Arc::new(TestNotify::default());
    client.add_notify(notify.clone());

    HbbftTestClient {
        client,
        notify,
        miner,
        keypair,
    }
}

pub fn create_hbbft_clients(
    moc: HbbftTestClient,
    num_clients: u32,
    _funder: &KeyPair,
) -> Vec<RwLock<HbbftTestClient>> {
    let mut clients = vec![RwLock::new(moc)];
    for _ in 0..num_clients {
        clients.push(RwLock::new(create_hbbft_client(Random.generate())));
    }

    clients
}
