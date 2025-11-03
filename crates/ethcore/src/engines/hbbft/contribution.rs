use crate::types::transaction::SignedTransaction;
use rand::{self, Rng, distributions::Standard};
use rlp::RlpStream;
use std::time::UNIX_EPOCH;

#[derive(Clone, Eq, PartialEq, Debug, Hash, Serialize, Deserialize)]
pub(crate) struct Contribution {
    pub transactions: Vec<Vec<u8>>,
    pub timestamp: u64,
    /// Random data for on-chain randomness.
    ///
    /// The invariant of `random_data.len()` == RANDOM_BYTES_PER_EPOCH **must** hold true.
    pub random_data: Vec<u8>,
}

/// Number of random bytes to generate per epoch.
///
/// Currently, we want twenty u32s worth of random data to generated on each epoch.
// TODO: Make this configurable somewhere.
const RANDOM_BYTES_PER_EPOCH: usize = 4 * 20;

/// Returns the current UNIX Epoch time, in seconds.
pub fn unix_now_secs() -> u64 {
    UNIX_EPOCH.elapsed().expect("Time not available").as_secs()
}

/// Returns the current UNIX Epoch time, in milliseconds.
pub fn unix_now_millis() -> u128 {
    UNIX_EPOCH
        .elapsed()
        .expect("Time not available")
        .as_millis()
}

impl Contribution {
    pub fn new(txns: &Vec<SignedTransaction>) -> Self {
        let ser_txns: Vec<_> = txns
            .iter()
            .map(|txn| {
                let mut s = RlpStream::new();
                txn.rlp_append(&mut s);
                s.drain()
            })
            .collect();

        Contribution {
            transactions: ser_txns,
            timestamp: unix_now_secs(),
            random_data: rand::thread_rng()
                .sample_iter(&Standard)
                .take(RANDOM_BYTES_PER_EPOCH)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        engines::hbbft::test::create_transactions::create_transaction,
        types::transaction::{SignedTransaction, TypedTransaction},
    };
    use crypto::publickey::{Generator, Random};
    use ethereum_types::U256;

    #[test]
    fn test_contribution_serialization() {
        let mut pending: Vec<SignedTransaction> = Vec::new();
        let keypair = Random.generate();
        pending.push(create_transaction(&keypair, &U256::from(1)));
        let contribution = super::Contribution::new(&pending);

        let deser_txns: Vec<_> = contribution
            .transactions
            .iter()
            .filter_map(|ser_txn| TypedTransaction::decode(ser_txn).ok())
            .filter_map(|txn| SignedTransaction::new(txn).ok())
            .collect();

        assert_eq!(pending.len(), deser_txns.len());
        assert_eq!(
            pending.iter().nth(0).unwrap(),
            deser_txns.iter().nth(0).unwrap()
        );
    }
}
