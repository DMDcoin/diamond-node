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
use ethereum_types::{Address, Public, U256};
use hbbft::sync_key_gen::SyncKeyGen;
use itertools::Itertools;
use parking_lot::RwLock;
use std::{collections::BTreeMap, sync::Arc, time::Instant};

use crate::client::BlockChainClient;

pub enum ServiceTransactionType {
    /// KeyGenTransaction: (u64: epoch, u64: round, KeyGenMode)
    KeyGenTransaction(u64, u64, KeyGenMode),
}

pub struct ServiceTransactionMemory {
    /// Time when the transaction was send.
    pub send_time: Instant,

    // It would be good to have a transaction Hash here.
    //pub transaction_hash: H256,
    /// Type of the transaction, e.g. KeyGen Part or Ack.
    pub transaction_type: ServiceTransactionType,

    /// Nonce of the transaction it was send with.
    //pub nonce: U256,

    /// Block number, at wich this transaction was "sent",
    /// in the meaning of prepared to be propagated.
    pub block_sent: u64,
    // It would be good to know if the Service Transaction got included.
    // pub inclusion_block: Option<u64>,
}

pub struct KeygenTransactionSender {
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

static KEYGEN_TRANSACTION_RESEND_DELAY_SECONDS: u64 = 30;
static KEYGEN_TRANSACTION_RESEND_DELAY_BLOCKS: u64 = 2;

impl KeygenTransactionSender {
    pub fn new() -> Self {
        KeygenTransactionSender {
            last_keygen_service_transaction: None,
        }
    }

    fn should_send(
        &mut self,
        client: &dyn EngineClient,
        mining_address: &Address,
        mode_to_check: KeyGenMode,
        upcomming_epoch: &U256,
        current_round: &U256,
    ) -> Result<ShouldSendKeyAnswer, CallError> {
        let keygen_mode = get_pending_validator_key_generation_mode(client, mining_address)?;
        if keygen_mode == mode_to_check {
            match &self.last_keygen_service_transaction {
                Some(last_sent) => {
                    match &last_sent.transaction_type {
                        ServiceTransactionType::KeyGenTransaction(
                            historic_upcomming_epoch,
                            historic_round,
                            historic_key_gen_mode,
                        ) => {
                            if *historic_key_gen_mode != keygen_mode
                                || *historic_upcomming_epoch != upcomming_epoch.as_u64()
                                || *historic_round != current_round.as_u64()
                            {
                                // other key gen mode, we need to send.
                                return Ok(ShouldSendKeyAnswer::Yes);
                            }

                            // we will check the state of our send transaction.
                            // client.queued_transactions().

                            // if we are still in the same situation, we need to figure out if we just should retry to send our last transaction.
                            if last_sent.send_time.elapsed().as_secs()
                                < KEYGEN_TRANSACTION_RESEND_DELAY_SECONDS
                            {
                                // we sent a transaction recently, so we should wait a bit.
                                return Ok(ShouldSendKeyAnswer::NoWaiting);
                            }

                            let current_block = client.block_number(BlockId::Latest).unwrap_or(0);

                            // this check also prevents the resending of Transactions if no block got mined. (e.g. because of stalled network)
                            if last_sent.block_sent + KEYGEN_TRANSACTION_RESEND_DELAY_BLOCKS
                                > current_block
                            {
                                // example:
                                // send on block 10 (last_sent.block_sent = 10)
                                // KEYGEN_TRANSACTION_RESEND_DELAY_BLOCKS = 2
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
        upcomming_epoch: &U256,
        current_round: &U256,
    ) -> Result<ShouldSendKeyAnswer, CallError> {
        self.should_send(
            client,
            mining_address,
            KeyGenMode::WritePart,
            upcomming_epoch,
            current_round,
        )
    }

    fn should_send_ack(
        &mut self,
        client: &dyn EngineClient,
        mining_address: &Address,
        upcomming_epoch: &U256,
        current_round: &U256,
    ) -> Result<ShouldSendKeyAnswer, CallError> {
        self.should_send(
            client,
            mining_address,
            KeyGenMode::WriteAck,
            upcomming_epoch,
            current_round,
        )
    }

    /// Returns a collection of transactions the pending validator has to submit in order to
    /// complete the keygen history contract data necessary to generate the next key and switch to the new validator set.
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
            debug!(target:"engine", "skipping sending key gen transaction, because we are syncing");
            return Ok(());
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

        // full_client.nonce(&mining_address, BlockId::Latest).unwrap();
        // Nonce Management is complex.
        // we will include queued transactions here,
        // but it could lead to a problem where "unprocessed" stuck transactions are producing Nonce gaps.

        let nonce = full_client.next_nonce(&*mining_address);

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
            //transaction_hash: hash,
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

        // WARNING: This Nonce could conflict with other Service Transactions.
        // a better ServiceTransactionManager could be improve this here.
        let nonce = full_client.next_nonce(&*mining_address); //full_client.nonce(&mining_address, BlockId::Latest).unwrap();

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
            //transaction_hash: hash,
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
