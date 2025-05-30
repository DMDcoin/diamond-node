use crate::engines::hbbft::test::hbbft_test_client::HbbftTestClient;
use parking_lot::RwLock;
use std::collections::BTreeMap;

pub fn crank_network(clients: &Vec<RwLock<HbbftTestClient>>) {
    // sync blocks
    sync_blocks(clients);

    // sync transactions
    sync_transactions(clients);

    // sync consensus messages
    sync_consensus_messages(clients);
}

fn sync_blocks(clients: &Vec<RwLock<HbbftTestClient>>) {
    // Find client with most blocks.
    let best_client = clients
        .iter()
        .enumerate()
        .fold((0, 0u64), |prev, (index, locked)| {
            let client = locked.read();
            // Get best block.
            let block_height = client.client.chain().best_block_number();
            // Check if best block is higher than current highest block.
            if block_height > prev.1 {
                (index, block_height)
            } else {
                prev
            }
        });

    let best = clients.iter().nth(best_client.0).unwrap().read();

    for c in clients.iter().enumerate() {
        if c.0 != best_client.0 {
            best.sync_blocks_to(&mut c.1.write());
        }
    }
}

fn sync_transactions(clients: &Vec<RwLock<HbbftTestClient>>) {
    for (n1, c1) in clients.iter().enumerate() {
        let sharer = c1.read();
        for (n2, c2) in clients.iter().enumerate() {
            if n1 != n2 {
                let mut target = c2.write();
                sharer.sync_transactions_to(&mut target);
            }
        }
    }
}

fn sync_consensus_messages(clients: &Vec<RwLock<HbbftTestClient>>) {
    let clients_map = clients
        .iter()
        .map(|c| (c.read().keypair.public().clone(), c))
        .collect::<BTreeMap<_, _>>();

    for (from, n) in &clients_map {
        for m in n.read().notify.targeted_messages.write().drain(..) {
            clients_map
                .get(&m.1.expect("The Message target node id must be set"))
                .expect("Message target not found in nodes map")
                .read()
                .client
                .engine()
                .handle_message(&m.0, Some(*from))
                .expect("Message handling to succeed");
        }
    }
}
