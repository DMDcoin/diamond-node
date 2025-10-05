use crate::{
    client::traits::{EngineClient, TransactionRequest},
    engines::{
        hbbft::{
            contracts::{
                keygen_history::{
                    KEYGEN_HISTORY_ADDRESS, PublicWrapper, engine_signer_to_synckeygen,
                    get_current_key_gen_round, has_acks_of_address_data, key_history_contract,
                    part_of_address,
                },
                staking::get_posdao_epoch,
                validator_set::{
                    KeyGenMode, ValidatorType, get_pending_validator_key_generation_mode,
                    get_validator_pubkeys,
                },
            },
            utils::bound_contract::CallError,
        },
        signer::EngineSigner,
    },
    types::ids::BlockId,
};
use ethcore_miner::pool::local_transactions::Status;
use ethereum_types::{Address, Public, U256};
use hash::H256;
use hbbft::sync_key_gen::SyncKeyGen;
use itertools::Itertools;
use parking_lot::RwLock;
use std::{collections::BTreeMap, sync::Arc, time::Instant};

use crate::client::BlockChainClient;

static MAX_BLOCKCHAIN_AGE_FOR_KEYGEN: u64 = 10; // seconds

pub enum ServiceTransactionType {
    /// KeyGenTransaction: (u64: epoch, u64: round, KeyGenMode)
    KeyGenTransaction(u64, u64, KeyGenMode),
}

pub struct ServiceTransactionMemory {
    /// Time when the transaction was send.
    pub send_time: Instant,

    // It would be good to have a transaction Hash here.
    pub transaction_hash: H256,

    /// Type of the transaction, e.g. KeyGen Part or Ack.
    pub transaction_type: ServiceTransactionType,

    /// Nonce of the transaction it was send with.
    //pub nonce: U256,

    /// Block number, at which this transaction was "sent",
    /// in the meaning of prepared to be propagated.
    pub block_sent: u64,
    // It would be good to know if the Service Transaction got included.
    // pub inclusion_block: Option<u64>,
}

pub struct KeygenTransactionSender {
    /// Minimum delay between for resending key gen transactions in milliseconds.
    key_gen_transaction_delay_milliseconds: u128,

    /// Minimum delay for resending key gen transactions, in milliseconds.
    key_gen_transaction_delay_blocks: u64,

    /// Last key gen service transaction we sent.
    last_keygen_service_transaction: Option<ServiceTransactionMemory>,
}

enum ShouldSendKeyAnswer {
    // no, we are not in this key gen phase.
    NoNotThisKeyGenMode,
    // no, we are waiting to send key later.
    NoWaiting,
    // yes, keys should be send now.
    Yes,
}

#[derive(Debug)]
pub enum KeyGenError {
    NoSigner,
    NoFullClient,
    NoPartToWrite,
    #[allow(dead_code)]
    CallError(CallError),
    Unexpected,
}

impl From<CallError> for KeyGenError {
    fn from(e: CallError) -> Self {
        KeyGenError::CallError(e)
    }
}

impl KeygenTransactionSender {
    pub fn new(
        key_gen_transaction_delay_blocks: u64,
        key_gen_transaction_delay_milliseconds: u128,
    ) -> Self {
        KeygenTransactionSender {
            last_keygen_service_transaction: None,
            key_gen_transaction_delay_blocks,
            key_gen_transaction_delay_milliseconds,
        }
    }

    fn should_send(
        &mut self,
        client: &dyn EngineClient,
        mining_address: &Address,
        mode_to_check: KeyGenMode,
        upcoming_epoch: &U256,
        current_round: &U256,
    ) -> Result<ShouldSendKeyAnswer, CallError> {
        let keygen_mode = get_pending_validator_key_generation_mode(client, mining_address)?;
        if keygen_mode == mode_to_check {
            match &self.last_keygen_service_transaction {
                Some(last_sent) => {
                    match &last_sent.transaction_type {
                        ServiceTransactionType::KeyGenTransaction(
                            historic_upcoming_epoch,
                            historic_round,
                            historic_key_gen_mode,
                        ) => {
                            if *historic_key_gen_mode != keygen_mode
                                || *historic_upcoming_epoch != upcoming_epoch.as_u64()
                                || *historic_round != current_round.as_u64()
                            {
                                // other key gen mode, we need to send.
                                return Ok(ShouldSendKeyAnswer::Yes);
                            }

                            let mut transaction_lost = false;
                            // check if our last sent transaction is still pending.
                            if let Some(service_tx_state) =
                                client.local_transaction_status(&last_sent.transaction_hash)
                            {
                                match service_tx_state {
                                    Status::Culled(_)
                                    | Status::Dropped(_)
                                    | Status::Rejected(..)
                                    | Status::Replaced { .. }
                                    | Status::Invalid(_)
                                    | Status::Canceled(_) => {
                                        transaction_lost = true;
                                    }
                                    _ => {}
                                }
                            } else {
                                // the transaction got lost, and probably transaction info got already deleted.
                                // it still might also got already included into a block.
                                transaction_lost = true;
                            }

                            if transaction_lost {
                                // maybe we lost the key gen transaction, because it got included into a block.

                                // make sure we did not just witness block inclusion.
                                if let Some(full_client) = client.as_full_client() {
                                    if let Some(transaction) = full_client.block_transaction(
                                        types::ids::TransactionId::Hash(
                                            last_sent.transaction_hash,
                                        ),
                                    ) {
                                        // our service transaction got included.
                                        warn!(target: "engine", "key gen transaction got included in block {} but we are still in wrong state ?!", transaction.block_number);
                                        return Ok(ShouldSendKeyAnswer::NoWaiting);
                                    } else {
                                        // our transaction is not pending anymore, and also has not got included into a block, we should resend.
                                        return Ok(ShouldSendKeyAnswer::Yes);
                                    }
                                } else {
                                    // that should really never happen.
                                    warn!(target:"engine", "could not get full client to check for inclusion of key gen transaction");
                                }
                            }

                            // if we are still in the same situation, we need to figure out if we just should retry to send our last transaction.
                            if last_sent.send_time.elapsed().as_millis()
                                < self.key_gen_transaction_delay_milliseconds
                            {
                                // we sent a transaction recently, so we should wait a bit.
                                return Ok(ShouldSendKeyAnswer::NoWaiting);
                            }

                            let current_block = client.block_number(BlockId::Latest).unwrap_or(0);

                            // this check also prevents the resending of Transactions if no block got mined. (e.g. because of stalled network)
                            if last_sent.block_sent + self.key_gen_transaction_delay_blocks
                                > current_block
                            {
                                // rational behind:
                                // if blocks are not created anyway,
                                // we do not have to send new transactions.

                                // example:
                                // send on block 10 (last_sent.block_sent = 10)
                                // key_gen_transaction_delay_blocks = 2
                                // resent after Block 12.
                                // current block is 11: waiting
                                // current block is 12: waiting
                                // current block is 13: not entering => YES

                                // we sent a transaction recently, so we should wait a bit.
                                return Ok(ShouldSendKeyAnswer::NoWaiting);
                            }

                            return Ok(ShouldSendKeyAnswer::Yes);
                        }
                    }
                }
                None => {
                    // we never sent a key gen transaction, so we should send one.
                    return Ok(ShouldSendKeyAnswer::Yes);
                }
            }
        }
        return Ok(ShouldSendKeyAnswer::NoNotThisKeyGenMode);
    }

    fn should_send_part(
        &mut self,
        client: &dyn EngineClient,
        mining_address: &Address,
        upcoming_epoch: &U256,
        current_round: &U256,
    ) -> Result<ShouldSendKeyAnswer, CallError> {
        self.should_send(
            client,
            mining_address,
            KeyGenMode::WritePart,
            upcoming_epoch,
            current_round,
        )
    }

    fn should_send_ack(
        &mut self,
        client: &dyn EngineClient,
        mining_address: &Address,
        upcoming_epoch: &U256,
        current_round: &U256,
    ) -> Result<ShouldSendKeyAnswer, CallError> {
        self.should_send(
            client,
            mining_address,
            KeyGenMode::WriteAck,
            upcoming_epoch,
            current_round,
        )
    }

    /// sends key gen transaction if there are any to send.
    pub fn send_keygen_transactions(
        &mut self,
        client: &dyn EngineClient,
        signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
    ) -> Result<(), KeyGenError> {
        // If we have no signer there is nothing for us to send.
        let address = match signer.read().as_ref() {
            Some(signer) => signer.address(),
            None => {
                warn!(target: "engine", "Could not send keygen transactions, because signer module could not be retrieved");
                return Err(KeyGenError::NoSigner);
            }
        };

        let full_client = client.as_full_client().ok_or(KeyGenError::NoFullClient)?;

        // If the chain is still syncing, do not send Parts or Acks.
        if full_client.is_major_syncing() {
            if let Some(lastes_block) = client.block_header(BlockId::Latest) {
                let now = std::time::UNIX_EPOCH
                    .elapsed()
                    .expect("Time not available")
                    .as_secs();
                if now > lastes_block.timestamp() + MAX_BLOCKCHAIN_AGE_FOR_KEYGEN {
                    debug!(target:"engine", "skipping sending key gen transaction, because we are syncing.");
                    return Ok(());
                } else {
                    trace!(target:"engine", "We are syncing, but the latest block is recent. continuing sending key gen transactions");
                }
            } else {
                debug!(target:"engine", "skipping sending key gen transaction, because we are syncing and could not retrieve latest block.");
                return Ok(());
            }
        }

        trace!(target:"engine", " get_validator_pubkeys...");

        let vmap = get_validator_pubkeys(&*client, BlockId::Latest, ValidatorType::Pending)
            .map_err(|e| KeyGenError::CallError(e))?;

        let pub_keys: BTreeMap<_, _> = vmap
            .values()
            .map(|p| (*p, PublicWrapper { inner: p.clone() }))
            .collect();

        let pub_keys_arc = Arc::new(pub_keys);
        let upcoming_epoch =
            get_posdao_epoch(client, BlockId::Latest).map_err(|e| KeyGenError::CallError(e))? + 1;

        //let pub_key_len = pub_keys.len();
        // if synckeygen creation fails then either signer or validator pub keys are problematic.
        // Todo: We should expect up to f clients to write invalid pub keys. Report and re-start pending validator set selection.
        let (mut synckeygen, part) = match engine_signer_to_synckeygen(signer, pub_keys_arc.clone())
        {
            Ok((synckeygen_, part_)) => (synckeygen_, part_),
            Err(e) => {
                warn!(target:"engine", "engine_signer_to_synckeygen pub keys count {:?} error {:?}", pub_keys_arc.len(), e);
                //let mut failure_pub_keys: Vec<Public> = Vec::new();
                let mut failure_pub_keys: Vec<u8> = Vec::new();
                pub_keys_arc.iter().for_each(|(k, v)| {
                    warn!(target:"engine", "pub key {}", k.as_bytes().iter().join(""));

                    if !v.is_valid() {
                        warn!(target:"engine", "INVALID pub key {}", k);

                        // append the bytes of the public key to the failure_pub_keys.
                        k.as_bytes().iter().for_each(|b| {
                            failure_pub_keys.push(*b);
                        });
                    }
                });

                // if we should send our parts, we will send the public keys of the troublemakers instead.

                let current_round = get_current_key_gen_round(client)?;

                match self
                    .should_send_part(client, &address, &upcoming_epoch, &current_round)
                    .map_err(|e| KeyGenError::CallError(e))?
                {
                    ShouldSendKeyAnswer::NoNotThisKeyGenMode => {
                        return Err(KeyGenError::Unexpected);
                    }
                    ShouldSendKeyAnswer::NoWaiting => return Err(KeyGenError::Unexpected),
                    ShouldSendKeyAnswer::Yes => {
                        let serialized_part = match bincode::serialize(&failure_pub_keys) {
                            Ok(part) => part,
                            Err(e) => {
                                warn!(target:"engine", "could not serialize part: {:?}", e);
                                return Err(KeyGenError::Unexpected);
                            }
                        };

                        let current_round = get_current_key_gen_round(client)?;

                        self.send_part_transaction(
                            full_client,
                            client,
                            &address,
                            &upcoming_epoch,
                            &current_round,
                            serialized_part,
                        )?;
                        return Ok(());
                    }
                }
            }
        };

        // If there is no part then we are not part of the pending validator set and there is nothing for us to do.
        let part_data = match part {
            Some(part) => part,
            None => {
                warn!(target:"engine", "no part to write.");
                return Err(KeyGenError::NoPartToWrite);
            }
        };

        let current_round = get_current_key_gen_round(client)?;

        trace!(target:"engine", "preparing to send keys for upcoming epoch: {} - round {}", upcoming_epoch, current_round);

        // Check if we already sent our part.
        match self.should_send_part(client, &address, &upcoming_epoch, &current_round)? {
            ShouldSendKeyAnswer::Yes => {
                let serialized_part = match bincode::serialize(&part_data) {
                    Ok(part) => part,
                    Err(e) => {
                        warn!(target:"engine", "could not serialize part: {:?}", e);
                        return Err(KeyGenError::Unexpected);
                    }
                };

                self.send_part_transaction(
                    full_client,
                    client,
                    &address,
                    &upcoming_epoch,
                    &current_round,
                    serialized_part,
                )?;

                return Ok(());
            }
            ShouldSendKeyAnswer::NoWaiting => {
                // we are waiting for parts to get written,
                // we do not need to continue any further with current key gen history.
                return Ok(());
            }
            ShouldSendKeyAnswer::NoNotThisKeyGenMode => {}
        }

        trace!(target:"engine", "has_acks_of_address_data: {:?}", has_acks_of_address_data(client, address));

        // Now we are sure all parts are ready, let's check if we sent our Acks.
        match self.should_send_ack(client, &address, &upcoming_epoch, &current_round)? {
            ShouldSendKeyAnswer::Yes => {
                self.send_ack_transaction(
                    full_client,
                    client,
                    &address,
                    &upcoming_epoch,
                    &current_round,
                    &vmap,
                    &mut synckeygen,
                )?;
            }
            _ => {}
        }

        Ok(())
    }

    fn send_ack_transaction(
        &mut self,
        full_client: &dyn BlockChainClient,
        client: &dyn EngineClient,
        mining_address: &Address,
        upcoming_epoch: &U256,
        current_round: &U256,
        vmap: &BTreeMap<Address, Public>,
        synckeygen: &mut SyncKeyGen<Public, PublicWrapper>,
    ) -> Result<(), KeyGenError> {
        // Return if any Part is missing.
        let mut acks = Vec::new();
        for v in vmap.keys().sorted() {
            acks.push(
                        match part_of_address(&*client, *v, &vmap, synckeygen, BlockId::Latest) {
                            Ok(part_result) => {
                                match part_result {
                                        Some(ack) => ack,
                                        None => {
                                            trace!(target:"engine", "could not retrieve part for {}", *v);
                                            return Ok(());
                                        }
                                    }
                            }
                            Err(err) => {
                                error!(target:"engine", "could not retrieve part for {} call failed. Error: {:?}", *v, err);
                                return Err(KeyGenError::CallError(err));
                            }
                        }
                    );
        }

        let mut serialized_acks = Vec::new();
        let mut total_bytes_for_acks = 0;

        for ack in acks {
            let ack_to_push = match bincode::serialize(&ack) {
                Ok(serialized_ack) => serialized_ack,
                Err(_) => return Err(KeyGenError::Unexpected),
            };
            total_bytes_for_acks += ack_to_push.len();
            serialized_acks.push(ack_to_push);
        }

        let write_acks_data = key_history_contract::functions::write_acks::call(
            upcoming_epoch,
            current_round,
            serialized_acks,
        );

        // the required gas values have been approximated by
        // experimenting and it's a very rough estimation.
        // it can be further fine tuned to be just above the real consumption.
        let gas = total_bytes_for_acks * 850 + 200_000;
        trace!(target: "engine","acks-len: {} gas: {}", total_bytes_for_acks, gas);

        // Nonce Management is complex.
        // we wont include queued transactions here,
        // because key gen transactions are so important,
        // that they are topic to "replace" other service transactions.
        // it could trigger in a scenario where a service transaction was just sent,
        // is getting included by other nodes, but this one does not know about it yet,
        // sending a Nonce that is to small.
        // if a transaction gets replaced, "own_tx  Transaction culled" happens,
        // in this case we there are signs, that our key gen transaction was not included,
        // and we might need to resend it.
        // currently there is no "observer" available, to observe culled transactions,
        // local_transactions frequently deletes outdated transactions.
        // however: we could check if the transaction is neither available in the service transaction pool,
        // nor available as included transaction.
        // A better ServiceTransactionManager could be implemented to handle this more gracefully.

        let nonce = full_client
            .nonce(&*mining_address, BlockId::Latest)
            .unwrap_or(U256::zero());

        let acks_transaction = TransactionRequest::call(*KEYGEN_HISTORY_ADDRESS, write_acks_data.0)
            .gas(U256::from(gas))
            .nonce(nonce.clone())
            .gas_price(U256::from(10000000000u64));
        debug!(target: "engine", "sending acks with nonce: {}",  acks_transaction.nonce.unwrap());
        let hash = full_client
            .transact_silently(acks_transaction)
            .map_err(|_| CallError::ReturnValueInvalid)?;
        debug!(target: "engine", "sending acks tx: {}",  hash);

        self.last_keygen_service_transaction = Some(ServiceTransactionMemory {
            send_time: Instant::now(),
            transaction_type: ServiceTransactionType::KeyGenTransaction(
                upcoming_epoch.as_u64(),
                current_round.as_u64(),
                KeyGenMode::WriteAck,
            ),
            //nonce: nonce,
            transaction_hash: hash,
            block_sent: client.block_number(BlockId::Latest).unwrap_or(0),
        });

        Ok(())
    }

    fn send_part_transaction(
        &mut self,
        full_client: &dyn BlockChainClient,
        client: &dyn EngineClient,
        mining_address: &Address,
        upcoming_epoch: &U256,
        current_round: &U256,
        data: Vec<u8>,
    ) -> Result<U256, KeyGenError> {
        // the required gas values have been approximated by
        // experimenting and it's a very rough estimation.
        // it can be further fine tuned to be just above the real consumption.
        // ACKs require much more gas,
        // and usually run into the gas limit problems.
        let gas: usize = data.len() * 800 + 100_000;

        // for detailed nonce management rational, check up send_ack_transaction.
        let nonce = full_client
            .nonce(&*mining_address, BlockId::Latest)
            .unwrap_or(U256::zero());

        let write_part_data =
            key_history_contract::functions::write_part::call(upcoming_epoch, current_round, data);

        let part_transaction = TransactionRequest::call(*KEYGEN_HISTORY_ADDRESS, write_part_data.0)
            .gas(U256::from(gas))
            .nonce(nonce)
            .gas_price(U256::from(10000000000u64));
        let hash = full_client
            .transact_silently(part_transaction)
            .map_err(|e| {
                warn!(target:"engine", "could not transact_silently: {:?}", e);
                CallError::ReturnValueInvalid
            })?;

        self.last_keygen_service_transaction = Some(ServiceTransactionMemory {
            send_time: Instant::now(),
            transaction_hash: hash,
            transaction_type: ServiceTransactionType::KeyGenTransaction(
                upcoming_epoch.as_u64(),
                current_round.as_u64(),
                KeyGenMode::WritePart,
            ),
            //nonce,
            block_sent: client.block_number(BlockId::Latest).unwrap_or(0),
        });

        debug!(target: "engine", "sending part tx: {}",  hash);
        debug!(target: "engine", "sending Part with nonce: {}",  nonce);

        return Ok(nonce);
    }
}
