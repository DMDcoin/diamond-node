// Warning: Part of the Consensus protocol, changes need to produce *exactly* the same result or
// block verification will fail. Intentional breaking changes constitute a fork.

use ethereum_types::{Address, U256};
use std::collections::HashMap;
use types::transaction::SignedTransaction;

/// Combining an address with a random U256 seed using XOR, using big-endian byte ordering always.
fn address_xor_u256(address: &Address, seed: U256) -> Address {
    // Address bytes are always assuming big-endian order.
    let address_bytes = address.as_bytes();

    // Explicitly convert U256 to big endian order
    let mut seed_bytes = [0u8; 32];
    seed.to_big_endian(&mut seed_bytes);

    // Byte-wise XOR, constructing a new, big-endian array
    let mut result = [0u8; 20];
    for i in 0..20 {
        result[i] = address_bytes[i] ^ seed_bytes[i];
    }

    // Construct a new Address from the big-endian array
    Address::from(result)
}

/// The list of transactions is expected to be free of duplicates.
fn deterministic_transactions_shuffling(
    transactions: Vec<SignedTransaction>,
    seed: U256,
) -> Vec<SignedTransaction> {
    // The implementation needs to be both portable and deterministic.
    // There is no guarantee that the input list of transactions does not contain transactions
    // with the same nonce but different content.
    // There is also no guarantee the transactions are sorted by nonce.

    // Group transactions by sender.
    // * Walk the transactions from first to last
    // * Add transactions with unique nonce to a per-sender vector
    //   * Discard transactions with a nonce already existing in the list of transactions
    let mut txs_by_sender: HashMap<_, Vec<SignedTransaction>> = HashMap::new();
    for tx in transactions {
        let sender = tx.sender();
        let entry = txs_by_sender.entry(sender).or_insert_with(Vec::new);
        if entry
            .iter()
            .any(|existing_tx| existing_tx.tx().nonce == tx.tx().nonce)
        {
            // Duplicate nonce found, ignore this transaction.
            continue;
        }
        entry.push(tx);
    }

    // For each sender, sort their transactions by nonce (lowest first).
    // Nonces are expected to be unique at this point, guaranteeing portable
    // and deterministic results independent of the sorting algorithm as long as
    // the sorting algorithm works and is implemented correctly.
    for txs in txs_by_sender.values_mut() {
        txs.sort_by_key(|tx| tx.tx().nonce);
    }

    // Deterministically randomize the order of senders.
    // Same as with transactions we rely on the uniqueness of list members and
    // a properly functioning sorting algorithm. To prevent predictable order we
    // XOR each sender address with the random number generated through the HBBFT
    // protocol, and use the resulting address as sorting key.
    // The random number is guaranteed to be identical for all validators at the
    // time of block creation.
    let mut senders: Vec<_> = txs_by_sender.keys().cloned().collect();
    senders.sort_by_key(|address| address_xor_u256(address, seed));

    // Create the final transaction list by iterating over the randomly shuffled senders.
    let mut final_transactions = Vec::new();
    for sender in senders {
        if let Some(mut sender_txs) = txs_by_sender.remove(&sender) {
            // Each sender's transactions are already sorted by nonce.
            final_transactions.append(&mut sender_txs);
        }
    }

    final_transactions
}

#[cfg(test)]
mod tests {
    use super::*;
    // Convert to bytes in big-endian order.
    fn u64_to_32_bytes_be(n: u64) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[..8].copy_from_slice(&n.to_be_bytes());
        result
    }

    #[test]
    fn test_address_xor_u256() {
        let value_as_bytes = u64_to_32_bytes_be(0x1234567890abcdefu64);
        let address = Address::from_slice(&value_as_bytes[..20]);
        let seed = U256::from_big_endian(&value_as_bytes);
        let result = address_xor_u256(&address, seed);
        assert_eq!(
            result,
            Address::from_slice(&u64_to_32_bytes_be(0x1234567890abcdef ^ 0x1234567890abcdef)[..20])
        );
    }
}
