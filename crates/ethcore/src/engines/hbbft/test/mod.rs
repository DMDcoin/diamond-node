use super::{
    contracts::{
        staking::{
            get_posdao_epoch, start_time_of_next_phase_transition,
            tests::{create_staker, is_pool_active},
        },
        validator_set::{is_pending_validator, mining_by_staking_address},
    },
    contribution::unix_now_secs,
    test::hbbft_test_client::{HbbftTestClient, create_hbbft_client, create_hbbft_clients},
};
use crate::{client::traits::BlockInfo, types::ids::BlockId};
use crypto::publickey::{Generator, KeyPair, Random, Secret};
use ethereum_types::{Address, U256};
use std::str::FromStr;

pub mod create_transactions;
pub mod hbbft_test_client;
pub mod network_simulator;

lazy_static! {
    /// Keypair for initial validator
    ///
    /// Contract update procedure:
    /// 1. Generate chain spec with a single initial validator(MOC)
    ///     a. Adapt the environment variables declared in 'setup_testnet.py'
    /// 2. Adapt the generated chain spec
    ///     a. Change the 'minimumBlockTime' to 0
    ///     b. Add '"isUnitTest": true' to the hbbft params section
    ///     c. Fund the new MOC address sufficiently
    /// 5. Copy the private key of the MOC to initialize the MASTER_OF_CEREMONIES_KEYPAIR variable below.
    static ref MASTER_OF_CEREMONIES_KEYPAIR: KeyPair = KeyPair::from_secret(
        Secret::from_str("5bbd61411b3f6f7c38187c0534060e3b310597868933d8820105410dd223b8d7")
            .expect("Secret from hex string must succeed")
    )
    .expect("KeyPair generation from secret must succeed");
}

#[test]
fn test_miner_transaction_injection() {
    let mut test_data = create_hbbft_client(MASTER_OF_CEREMONIES_KEYPAIR.clone());

    // Verify that we actually start at block 0.
    assert_eq!(test_data.client.chain().best_block_number(), 0);

    // Inject a transaction, with instant sealing a block will be created right away.
    test_data.create_some_transaction(None);

    // Expect a new block to be created.
    assert_eq!(test_data.client.chain().best_block_number(), 1);

    // Expect one transaction in the block.
    let block = test_data
        .client
        .block(BlockId::Number(1))
        .expect("Block 1 must exist");
    assert_eq!(block.transactions_count(), 1);
}

#[test]
fn test_staking_account_creation() {
    // Create Master of Ceremonies
    let mut moc = create_hbbft_client(MASTER_OF_CEREMONIES_KEYPAIR.clone());

    // Verify the master of ceremony is funded.
    assert!(moc.balance(&moc.address()) > U256::from(10000000));

    // Create a potential validator.
    let miner_1 = create_hbbft_client(Random.generate());

    // Verify the pending validator is unfunded.
    assert_eq!(moc.balance(&miner_1.address()), U256::from(0));

    // Verify that we actually start at block 0.
    assert_eq!(moc.client.chain().best_block_number(), 0);

    let transaction_funds = U256::from(9000000000000000000u64);

    // Inject a transaction, with instant sealing a block will be created right away.
    moc.transfer_to(&miner_1.address(), &transaction_funds);

    // Expect a new block to be created.
    assert_eq!(moc.client.chain().best_block_number(), 1);

    // Verify the pending validator is now funded.
    assert_eq!(moc.balance(&miner_1.address()), transaction_funds);

    // Create staking address
    let funder = moc.keypair.clone();
    let staker_1 = create_staker(&mut moc, &funder, &miner_1, transaction_funds);

    // Expect two new blocks to be created, one for the transfer of staking funds,
    // one for registering the staker as pool.
    assert_eq!(moc.client.chain().best_block_number(), 3);

    // Expect one transaction in the block.
    let block = moc
        .client
        .block(BlockId::Number(3))
        .expect("Block must exist");
    assert_eq!(block.transactions_count(), 1);

    assert_ne!(
        mining_by_staking_address(moc.client.as_ref(), &staker_1.address())
            .expect("Constant call must succeed."),
        Address::zero()
    );

    // Check if the staking pool is active.
    assert_eq!(
        is_pool_active(moc.client.as_ref(), staker_1.address())
            .expect("Pool active query must succeed."),
        true
    );
}

fn skip_n_blocks(n: u64, hbbft_client: &mut HbbftTestClient, transactor: &KeyPair) {
    for _ in 0..n {
        hbbft_client.create_some_transaction(Some(&transactor));
    }
}

#[test]
fn test_epoch_transition() {
    // Create Master of Ceremonies
    let mut moc = create_hbbft_client(MASTER_OF_CEREMONIES_KEYPAIR.clone());
    // To avoid performing external transactions with the MoC we create and fund a random address.
    let transactor: KeyPair = Random.generate();

    let genesis_transition_time = start_time_of_next_phase_transition(moc.client.as_ref())
        .expect("start_time_of_next_phase_transition call must succeed");

    // Genesis block is at time 0, current unix time must be much larger.
    assert!(genesis_transition_time.as_u64() < unix_now_secs());

    // We should not be in the pending validator set at the genesis block.
    assert!(
        !is_pending_validator(moc.client.as_ref(), &moc.address())
            .expect("is_pending_validator call must succeed")
    );

    // Fund the transactor.
    // Also triggers the creation of a block.
    // This implicitly calls the block reward contract, which should trigger a phase transition
    // since we already verified that the genesis transition time threshold has been reached.
    let transaction_funds = U256::from(9000000000000000000u64);
    moc.transfer_to(&transactor.address(), &transaction_funds);

    // Expect a new block to be created.
    assert_eq!(moc.client.chain().best_block_number(), 1);

    // Now we should be part of the pending validator set.
    assert!(
        is_pending_validator(moc.client.as_ref(), &moc.address())
            .expect("Constant call must succeed")
    );

    // Check if we are still in the first epoch.
    assert_eq!(
        get_posdao_epoch(moc.client.as_ref(), BlockId::Latest).expect("Constant call must succeed"),
        U256::from(0)
    );

    // We analyze what happens at each block if the key generation transactions are sent with a 3 block delay,
    // and why it takes exactly 11 Blocks to complete.
    //
    // On part writing the following steps happen (remember the transaction send call
    // happens in "on_close", when the new block is not integrated into the chain state yet!):
    // Block 1: Client realizes it has to write its part, sets the send delay counter to 1.
    // Block 2: Client sets the send delay counter to 2
    // Block 3: Client sets the send delay counter to 3 - sends its Part transaction
    // Block 4: Part transaction is part of the new block (but not in the chain state yet in the on_close function)
    // Block 5: Client realizes it has to write its Acks, sets the send delay counter to 1.
    // Block 6: Client sets the send delay counter to 2
    // Block 7: Client sets the send delay counter to 3 - sends its Acks transaction
    // Block 8: Acks transaction is part of the new block (but not in the chain state yet in the on_close function)
    //   Remember that the Block reward call is also done in the "on_close" function and only respects the state of the *previous* block.
    //   No epoch transition can happen in Block 10 for that reason, even though all Parts and Acks are sent and part of a block at that point.
    // Block 9: In the "on_close" function all Parts and Acks are now on the chain state and the block reward system call request the epoch change.
    skip_n_blocks(9, &mut moc, &transactor);

    // At this point we should be in the new epoch.
    assert_eq!(
        get_posdao_epoch(moc.client.as_ref(), BlockId::Latest).expect("Constant call must succeed"),
        U256::from(1)
    );

    // Let's do another one to check if the transition to the new honey badger and keys works.
    moc.create_some_transaction(Some(&transactor));
}

#[test]
fn sync_two_validators() {
    // Create the MOC client
    let mut moc = create_hbbft_client(MASTER_OF_CEREMONIES_KEYPAIR.clone());

    // To avoid performing external transactions with the MoC we create and fund a random address.
    let transactor: KeyPair = Random.generate();

    // Fund the transactor.
    // Also triggers the creation of a block.
    // This implicitly calls the block reward contract, which should trigger a phase transition
    // since we already verified that the genesis transition time threshold has been reached.
    let transaction_funds = U256::from(9000000000000000000u64);
    moc.transfer_to(&transactor.address(), &transaction_funds);

    // Expect a new block to be created.
    assert_eq!(moc.client.chain().best_block_number(), 1);

    // Verify the pending validator is now funded.
    assert_eq!(moc.balance(&transactor.address()), transaction_funds);

    // Create the pool 1 client and set up the pool
    let mut validator_1 = create_hbbft_client(Random.generate());

    // Verify the pending validator is now funded.
    assert_eq!(validator_1.balance(&transactor.address()), U256::zero());

    // Sync blocks from moc to validator 1
    moc.sync_blocks_to(&mut validator_1);

    // Check if new blocks have been added to validator_1 client.
    assert_eq!(
        validator_1.balance(&transactor.address()),
        transaction_funds
    );

    moc.sync_transactions_to(&mut validator_1);
}

// #[test]
// fn test_moc_to_first_validator() {
//     // Create MOC client
//     let mut moc = create_hbbft_client(MASTER_OF_CEREMONIES_KEYPAIR.clone());

//     // Create first validator client
//     let mut validator_1 = create_hbbft_client(Random.generate());

//     // To avoid performing external transactions with the MoC we create and fund a random address.
//     let transactor: KeyPair = Random.generate();

//     // Fund the transactor.
//     // Also triggers the creation of a block.
//     // This implicitly calls the block reward contract, which should trigger a phase transition
//     // since we already verified that the genesis transition time threshold has been reached.
//     moc.transfer_to(
//         &transactor.address(),
//         &U256::from_dec_str("1000000000000000000000000").unwrap(),
//     );

//     let transaction_funds = U256::from(9000000000000000000u64);
//     moc.transfer(&transactor, &validator_1.address(), &transaction_funds);

//     // Create first pool
//     // Create staking address
//     let _staker_1 = create_staker(&mut moc, &transactor, &validator_1, transaction_funds);

//     // Wait for moc keygen phase to finish
//     moc.create_some_transaction(Some(&transactor));
//     moc.create_some_transaction(Some(&transactor));
//     //moc.create_some_transaction(Some(&transactor));

//     // In the next block the POSDAO contracts realize they need to
//     // switch to the new validator.
//     moc.create_some_transaction(Some(&transactor));
//     // We need to create another block to give the new validator a chance
//     // to find out it is in the pending validator set.
//     moc.create_some_transaction(Some(&transactor));

//     // Now we should be part of the pending validator set.
//     assert!(
//         is_pending_validator(moc.client.as_ref(), &validator_1.address())
//             .expect("Constant call must succeed")
//     );
//     // ..and the MOC should not be a pending validator.
//     assert!(!is_pending_validator(moc.client.as_ref(), &moc.address())
//         .expect("Constant call must succeed"));

//     // Sync blocks from MOC to validator_1.
//     // On importing the last block validator_1 should realize he is the next
//     // validator and generate a Parts transaction.
//     moc.sync_blocks_to(&mut validator_1);

//     // validator_1 created a transaction to write its part, but it is not
//     // the current validator and cannot create a block.
//     // We need to gossip the transaction from validator_1 to the moc for a new block
//     // to be created, including the transaction from validator_1.
//     validator_1.sync_transactions_to(&mut moc);

//     // Write another dummy block to give validator_1 the chance to realize he wrote
//     // his Part already so he sends his Acks.
//     // Due to the Parts/Acks sending delay of 3 blocks we have to inject 3 blocks here
//     moc.create_some_transaction(Some(&transactor));
//     moc.create_some_transaction(Some(&transactor));
//     moc.create_some_transaction(Some(&transactor));

//     // At this point the transaction from validator_1 has written its Keygen part,
//     // and we need to sync the new blocks from moc to validator_1.
//     moc.sync_blocks_to(&mut validator_1);

//     // At this point validator_1 realizes his Part is included on the chain and
//     // generates a transaction to write it Acks.
//     // We need to gossip the transactions from validator_1 to the moc.
//     validator_1.sync_transactions_to(&mut moc);

//     // Create a dummy transaction for the moc to see the Acks on the chain state,
//     // and make him switch to the new validator.
//     moc.create_some_transaction(Some(&transactor));

//     // Sync blocks from moc to validator_1, which is now the only active validator.
//     moc.sync_blocks_to(&mut validator_1);

//     let pre_block_nr = validator_1.client.chain().best_block_number();

//     // Create a dummy transaction on the validator_1 client to verify it can create blocks.
//     validator_1.create_some_transaction(Some(&transactor));

//     let post_block_nr = validator_1.client.chain().best_block_number();

//     assert_eq!(post_block_nr, pre_block_nr + 1);
// }

#[test]
fn test_initialize_n_validators() {
    let mut moc = create_hbbft_client(MASTER_OF_CEREMONIES_KEYPAIR.clone());

    let funder: KeyPair = Random.generate();
    let fund_amount = U256::from_dec_str("1000000000000000000000000").unwrap();
    moc.transfer_to(&funder.address(), &fund_amount);

    let mut clients = create_hbbft_clients(moc, 2, &funder);

    assert_eq!(
        clients
            .iter()
            .nth(1)
            .unwrap()
            .read()
            .balance(&funder.address()),
        U256::zero()
    );

    network_simulator::crank_network(&mut clients);

    assert_eq!(
        clients
            .iter()
            .nth(1)
            .unwrap()
            .read()
            .balance(&funder.address()),
        fund_amount
    );
}
