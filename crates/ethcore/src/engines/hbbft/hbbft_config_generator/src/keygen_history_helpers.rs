use crate::Enode;
use ethereum_types::H128;
use ethjson::spec::hbbft::HbbftNetworkFork;
use hbbft::sync_key_gen::{AckOutcome, Part, PartOutcome, PublicKey, SecretKey, SyncKeyGen};
use parity_crypto::publickey::{Address, Public, Secret, public_to_address};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone)]
pub struct KeyPairWrapper {
    pub public: Public,
    pub secret: Secret,
}

impl PublicKey for KeyPairWrapper {
    type Error = parity_crypto::publickey::Error;
    type SecretKey = KeyPairWrapper;
    fn encrypt<M: AsRef<[u8]>, R: rand::Rng>(
        &self,
        msg: M,
        _rng: &mut R,
    ) -> Result<Vec<u8>, Self::Error> {
        parity_crypto::publickey::ecies::encrypt(&self.public, b"", msg.as_ref())
    }
}

impl SecretKey for KeyPairWrapper {
    type Error = parity_crypto::publickey::Error;
    fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Self::Error> {
        parity_crypto::publickey::ecies::decrypt(&self.secret, b"", ct)
    }
}

pub fn generate_keygens<R: rand::Rng>(
    key_pairs: Arc<BTreeMap<Public, KeyPairWrapper>>,
    mut rng: &mut R,
    t: usize,
) -> (
    Vec<SyncKeyGen<Public, KeyPairWrapper>>,
    BTreeMap<Public, Part>,
    BTreeMap<Public, Vec<PartOutcome>>,
) {
    // Get SyncKeyGen and Parts
    let (mut sync_keygen, parts): (Vec<_>, BTreeMap<_, _>) = key_pairs
        .iter()
        .map(|(n, kp)| {
            let s = SyncKeyGen::new(n.clone(), kp.clone(), key_pairs.clone(), t, &mut rng).unwrap();
            (s.0, (n.clone(), s.1.unwrap()))
        })
        .unzip();

    // All SyncKeyGen process all parts, returning Acks
    let acks: BTreeMap<_, _> = sync_keygen
        .iter_mut()
        .map(|s| {
            (
                s.our_id().clone(),
                parts
                    .iter()
                    .map(|(n, p)| s.handle_part(n, p.clone(), &mut rng).unwrap())
                    .collect::<Vec<_>>(),
            )
        })
        .collect();

    // All SyncKeyGen process all Acks
    let ack_outcomes: Vec<_> = sync_keygen
        .iter_mut()
        .flat_map(|s| {
            acks.iter()
                .flat_map(|(n, p_outcomes)| {
                    p_outcomes
                        .iter()
                        .map(|p| match p {
                            PartOutcome::Valid(a) => {
                                s.handle_ack(n, a.as_ref().unwrap().clone()).unwrap()
                            }
                            _ => panic!("Expected Part Outcome to be valid"),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect();

    // Check all Ack Outcomes
    for ao in ack_outcomes {
        if let AckOutcome::Invalid(_) = ao {
            panic!("Expecting Ack Outcome to be valid");
        }
    }

    (sync_keygen, parts, acks)
}

pub fn enodes_to_pub_keys(enodes: &Vec<Enode>) -> Arc<BTreeMap<Public, KeyPairWrapper>> {
    Arc::new(
        enodes
            .iter()
            .map(|e| {
                (
                    e.public.clone(),
                    KeyPairWrapper {
                        public: e.public,
                        secret: e.secret.clone(),
                    },
                )
            })
            .collect(),
    )
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct KeyGenHistoryData {
    validators: Vec<String>,
    staking_addresses: Vec<String>,
    public_keys: Vec<String>,
    ip_addresses: Vec<String>,
    #[serde_as(as = "Vec<serde_with::hex::Hex>")]
    parts: Vec<Vec<u8>>,
    #[serde_as(as = "Vec<Vec<serde_with::hex::Hex>>")]
    acks: Vec<Vec<Vec<u8>>>,
}

impl KeyGenHistoryData {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Keygen History must convert to JSON")
    }

    pub fn create_example_fork_definition(&self) -> HbbftNetworkFork {
        let validators: Vec<Vec<u8>> = self
            .public_keys
            .iter()
            .map(|v| {
                let mut hex = v.clone();
                println!("public key: {}", v);
                if v.starts_with("0x") {
                    hex = v.split_at(2).1.to_string();
                }

                let public = hex.parse::<Public>().expect("Could not parse public key");
                public.as_bytes().to_vec()
            })
            .collect();

        HbbftNetworkFork {
            block_number_start: 10,
            block_number_end: Some(100),
            validators: validators,
            parts: self.parts.clone(),
            acks: self.acks.clone(),
        }
    }
}

pub fn key_sync_history_data(
    parts: &BTreeMap<Public, Part>,
    acks: &BTreeMap<Public, Vec<PartOutcome>>,
    enodes: &Vec<Enode>,
    include_validators_only: bool,
) -> KeyGenHistoryData {
    let mut data = KeyGenHistoryData {
        validators: Vec::new(),
        staking_addresses: Vec::new(),
        public_keys: Vec::new(),
        ip_addresses: Vec::new(),
        parts: Vec::new(),
        acks: Vec::new(),
    };

    let mut parts_total_bytes = 0;
    let mut num_parts = 0;
    let mut acks_total_bytes = 0;
    let mut num_acks = 0;

    //let ids: Vec<Public> = enodes.iter().map(|e| e.public.clone()).collect();

    let mut staking_counter = 1;
    // Add Parts and Acks in strict order
    for enode in enodes.iter() {
        let id = &enode.public;

        // if there is no part available for this node,
        // then the it is not a initial validator.

        let is_validator = parts.get(id).is_some();
        if include_validators_only && !is_validator {
            continue;
        }

        data.validators.push(format!("{:?}", public_to_address(id)));
        data.staking_addresses
            .push(format!("{:?}", Address::from_low_u64_be(staking_counter)));
        staking_counter += 1;
        data.public_keys.push(format!("{:?}", id));
        data.ip_addresses
            .push(format!("{:?}", H128::from_low_u64_be(1)));

        if !is_validator {
            continue;
        }
        // Append to parts vector
        let part = parts.get(id).unwrap();
        let serialized = bincode::serialize(part).expect("Part has to serialize");
        parts_total_bytes += serialized.len();
        num_parts += 1;
        data.parts.push(serialized);

        // Append to parts vector of vectors
        let acks = acks.get(id).unwrap();
        data.acks.push(
            acks.iter()
                .map(|outcome| match outcome {
                    PartOutcome::Valid(ack_option) => {
                        if let Some(ack) = ack_option {
                            let ack_serialized =
                                bincode::serialize(&ack).expect("Ack has to serialize");
                            acks_total_bytes += ack_serialized.len();
                            num_acks += 1;
                            ack_serialized
                        } else {
                            panic!("Unexpected valid part outcome without Ack message")
                        }
                    }
                    _ => panic!("Expected Part Outcome to be valid"),
                })
                .collect(),
        );
    }

    println!(
        "{} parts, total number of bytes: {}",
        num_parts, parts_total_bytes
    );
    println!(
        "{} Acks, total number of bytes: {}",
        num_acks, acks_total_bytes
    );
    println!(
        "Total number of bytes: {}",
        parts_total_bytes + acks_total_bytes
    );
    println!(
        "{},{},{},{},{}",
        num_parts,
        num_acks,
        parts_total_bytes,
        acks_total_bytes,
        parts_total_bytes + acks_total_bytes
    );

    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;

    #[test]
    fn test_keygen_history_data_serde() {
        let mut rng = rand::thread_rng();
        let (secret, public, _) = crate::create_account();
        let keypair = KeyPairWrapper { public, secret };
        let mut pub_keys: BTreeMap<Public, KeyPairWrapper> = BTreeMap::new();
        pub_keys.insert(public, keypair.clone());
        let (_, parts, _) = generate_keygens(Arc::new(pub_keys), &mut rng, 1);

        let part = parts
            .iter()
            .nth(0)
            .expect("At least one part needs to exist");
        let part_ser = bincode::serialize(&part.1).expect("Part has to serialize");
        let part_deser: Part =
            bincode::deserialize(&part_ser).expect("Deserialization expected to succeed");
        assert_eq!(part.1, &part_deser);
    }
}
