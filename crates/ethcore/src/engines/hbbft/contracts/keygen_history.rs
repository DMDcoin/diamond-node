use crate::{
    client::traits::EngineClient,
    engines::{
        hbbft::{
            NodeId,
            contracts::validator_set::{ValidatorType, get_validator_pubkeys},
            utils::bound_contract::{BoundContract, CallError},
        },
        signer::EngineSigner,
    },
    types::ids::BlockId,
};
use crypto::{self, publickey::Public};
use ethereum_types::{Address, H512, U256};
use hbbft::{
    NetworkInfo,
    crypto::{PublicKeySet, SecretKeyShare},
    sync_key_gen::{
        Ack, AckOutcome, Error, Part, PartOutcome, PubKeyMap, PublicKey, SecretKey, SyncKeyGen,
    },
    util::max_faulty,
};
use itertools::Itertools;
use parking_lot::RwLock;
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

use_contract!(
    key_history_contract,
    "res/contracts/key_history_contract.json"
);

lazy_static! {
    pub static ref KEYGEN_HISTORY_ADDRESS: Address =
        Address::from_str("7000000000000000000000000000000000000001").unwrap();
}

macro_rules! call_const_key_history {
	($c:ident, $x:ident $(, $a:expr )*) => {
		$c.call_const(key_history_contract::functions::$x::call($($a),*))
	};
}

pub fn engine_signer_to_synckeygen<'a>(
    signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
    pub_keys: PubKeyMap<Public, PublicWrapper>,
) -> Result<(SyncKeyGen<Public, PublicWrapper>, Option<Part>), Error> {
    let wrapper = KeyPairWrapper {
        inner: signer.clone(),
    };
    let public = match signer.read().as_ref() {
        Some(signer) => {
            if let Some(this_public) = signer.public() {
                this_public
            } else {
                error!(target: "engine", "Signer's public key must be available for address {:?}", signer.address());
                return Err(hbbft::sync_key_gen::Error::UnknownSender);
            }
        }
        None => Public::from(H512::from_low_u64_be(0)),
    };
    let mut rng = rand::thread_rng();
    let num_nodes = pub_keys.len();
    SyncKeyGen::new(public, wrapper, pub_keys, max_faulty(num_nodes), &mut rng)
}

pub fn synckeygen_to_network_info(
    synckeygen: &SyncKeyGen<Public, PublicWrapper>,
    pks: PublicKeySet,
    sks: Option<SecretKeyShare>,
) -> Option<NetworkInfo<NodeId>> {
    let pub_keys = synckeygen
        .public_keys()
        .keys()
        .map(|p| NodeId(*p))
        .collect::<Vec<_>>();
    println!("Creating Network Info");
    println!("pub_keys: {:?}", pub_keys);
    println!(
        "pks: {:?}",
        (0..(pub_keys.len()))
            .map(|i| pks.public_key_share(i))
            .collect::<Vec<_>>()
    );
    let sks = sks.unwrap();
    println!("sks.public_key_share: {:?}", sks.public_key_share());
    println!("sks.reveal: {:?}", sks.reveal());

    Some(NetworkInfo::new(
        NodeId(synckeygen.our_id().clone()),
        sks,
        pks,
        pub_keys,
    ))
}

pub fn part_of_address(
    client: &dyn EngineClient,
    address: Address,
    vmap: &BTreeMap<Address, Public>,
    skg: &mut SyncKeyGen<Public, PublicWrapper>,
    block_id: BlockId,
) -> Result<Option<Ack>, CallError> {
    let c = BoundContract::bind(client, block_id, *KEYGEN_HISTORY_ADDRESS);
    let serialized_part = call_const_key_history!(c, parts, address)?;
    //println!("Part for address {}: {:?}", address, serialized_part);
    if serialized_part.is_empty() {
        return Ok(None);
    }
    let deserialized_part: Part = bincode::deserialize(&serialized_part).unwrap();
    let mut rng = rand::thread_rng();
    let outcome = skg
        .handle_part(vmap.get(&address).unwrap(), deserialized_part, &mut rng)
        .unwrap();

    match outcome {
        PartOutcome::Invalid(e) => {
            error!(target: "engine", "Part for address {} is invalid: {:?}", address, e);
            Err(CallError::ReturnValueInvalid)
        }
        PartOutcome::Valid(ack) => Ok(ack),
    }
}

pub fn get_current_key_gen_round(client: &dyn EngineClient) -> Result<U256, CallError> {
    let c = BoundContract::bind(client, BlockId::Latest, *KEYGEN_HISTORY_ADDRESS);
    let serialized_result = call_const_key_history!(c, get_current_key_gen_round)?;
    Ok(U256::from(serialized_result))
}

pub fn has_acks_of_address_data(
    client: &dyn EngineClient,
    address: Address,
) -> Result<bool, CallError> {
    let c = BoundContract::bind(client, BlockId::Latest, *KEYGEN_HISTORY_ADDRESS);
    let serialized_length = call_const_key_history!(c, get_acks_length, address)?;
    Ok(serialized_length.low_u64() != 0)
}

pub fn acks_of_address(
    client: &dyn EngineClient,
    address: Address,
    vmap: &BTreeMap<Address, Public>,
    skg: &mut SyncKeyGen<Public, PublicWrapper>,
    block_id: BlockId,
) -> Result<(), CallError> {
    let c = BoundContract::bind(client, block_id, *KEYGEN_HISTORY_ADDRESS);
    let serialized_length = call_const_key_history!(c, get_acks_length, address)?;

    // println!(
    // 	"Acks for address {} is of size: {:?}",
    // 	address, serialized_length
    // );
    for n in 0..serialized_length.low_u64() {
        let serialized_ack = call_const_key_history!(c, acks, address, n)?;
        //println!("Ack #{} for address {}: {:?}", n, address, serialized_ack);
        if serialized_ack.is_empty() {
            return Err(CallError::ReturnValueInvalid);
        }
        let deserialized_ack: Ack = bincode::deserialize(&serialized_ack).unwrap();
        let outcome = skg
            .handle_ack(vmap.get(&address).unwrap(), deserialized_ack)
            .unwrap();
        if let AckOutcome::Invalid(fault) = outcome {
            panic!("Expected Ack Outcome to be valid. {:?}", fault);
        }
    }

    Ok(())
}

#[derive(Clone)]
pub struct PublicWrapper {
    pub inner: Public,
}

#[derive(Clone)]
pub struct KeyPairWrapper {
    pub inner: Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
}

impl PublicWrapper {
    /// Check if the public key is valid.
    pub fn is_valid(&self) -> bool {
        self.encrypt(b"a", &mut rand::thread_rng()).is_ok()
    }
}

impl<'a> PublicKey for PublicWrapper {
    type Error = crypto::publickey::Error;
    type SecretKey = KeyPairWrapper;
    fn encrypt<M: AsRef<[u8]>, R: rand::Rng>(
        &self,
        msg: M,
        _rng: &mut R,
    ) -> Result<Vec<u8>, Self::Error> {
        crypto::publickey::ecies::encrypt(&self.inner, b"", msg.as_ref())
    }
}

impl<'a> SecretKey for KeyPairWrapper {
    type Error = crypto::publickey::Error;
    fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner
            .read()
            .as_ref()
            .ok_or(parity_crypto::publickey::Error::InvalidSecretKey)
            .expect("Signer must be set!")
            .decrypt(b"", ct)
    }
}

pub fn all_parts_acks_available(
    client: &dyn EngineClient,
    block_timestamp: u64,
    num_validators: usize,
) -> Result<bool, CallError> {
    // backward compatibility:
    // this is a performance improvement introduced on the DMD Alpha Testnet.
    // more about https://github.com/DMDcoin/openethereum-3.x/issues/71
    // this piece of  code exists only for the DMD public alpha testnet,
    // in order to support the v1 protocol version.
    // since the v2 protocol version is better,
    // v1 should be never used.
    // remove the code:
    // see: https://github.com/DMDcoin/openethereum-3.x/issues/72

    let trigger_timestamp: u64 = 1646395200; // Friday, March 4, 2022 12:00:00 PM

    if block_timestamp > 0 && trigger_timestamp > 0 && block_timestamp < trigger_timestamp {
        return Ok(true);
    }

    let c = BoundContract::bind(client, BlockId::Latest, *KEYGEN_HISTORY_ADDRESS);
    let (num_parts, num_acks) = call_const_key_history!(c, get_number_of_key_fragments_written)?;
    Ok(num_parts.low_u64() == (num_validators as u64)
        && num_acks.low_u64() == (num_validators) as u64)
}

/// Read available keygen data from the blockchain and initialize a SyncKeyGen instance with it.
pub fn initialize_synckeygen(
    client: &dyn EngineClient,
    signer: &Arc<RwLock<Option<Box<dyn EngineSigner>>>>,
    block_id: BlockId,
    validator_type: ValidatorType,
) -> Result<SyncKeyGen<Public, PublicWrapper>, CallError> {
    debug!(target: "engine", "Initializing SyncKeyGen with block_id: {:?}", block_id);
    let vmap = get_validator_pubkeys(&*client, block_id, validator_type)?;
    let pub_keys: BTreeMap<_, _> = vmap
        .values()
        .map(|p| (*p, PublicWrapper { inner: p.clone() }))
        .collect();

    // if synckeygen creation fails then either signer or validator pub keys are problematic.
    // Todo: We should expect up to f clients to write invalid pub keys. Report and re-start pending validator set selection.
    let (mut synckeygen, _) = engine_signer_to_synckeygen(signer, Arc::new(pub_keys))
        .map_err(|_| CallError::ReturnValueInvalid)?;

    for v in vmap.keys().sorted() {
        part_of_address(&*client, *v, &vmap, &mut synckeygen, block_id)?;
    }
    for v in vmap.keys().sorted() {
        acks_of_address(&*client, *v, &vmap, &mut synckeygen, block_id)?;
    }

    Ok(synckeygen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::signer::{EngineSigner, from_keypair};
    use crypto::publickey::{KeyPair, Secret};
    use std::{collections::BTreeMap, sync::Arc};

    #[test]
    fn test_synckeygen_initialization() {
        // Create a keypair
        let secret =
            Secret::from_str("49c437676c600660905204e5f3710a6db5d3f46e3da9ba5168b9d34b0b787317")
                .unwrap();
        let keypair = KeyPair::from_secret(secret).expect("KeyPair generation must succeed");
        let public = keypair.public().clone();
        let wrapper = PublicWrapper {
            inner: public.clone(),
        };

        // Convert it to a EngineSigner trait object
        let signer: Arc<RwLock<Option<Box<dyn EngineSigner>>>> =
            Arc::new(RwLock::new(Some(from_keypair(keypair))));

        // Initialize SyncKeyGen with the EngineSigner wrapper
        let mut pub_keys: BTreeMap<Public, PublicWrapper> = BTreeMap::new();
        pub_keys.insert(public, wrapper);

        assert!(engine_signer_to_synckeygen(&signer, Arc::new(pub_keys)).is_ok());
    }
}
