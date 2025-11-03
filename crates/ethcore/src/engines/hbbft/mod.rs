mod block_reward_hbbft;
mod contracts;
mod contribution;
mod hbbft_early_epoch_end_manager;
mod hbbft_engine;
mod hbbft_engine_cache;
mod hbbft_message_memorium;
mod hbbft_network_fork_manager;
mod hbbft_peers_handler;
mod hbbft_peers_management;
mod hbbft_state;
mod keygen_transactions;
mod sealing;
#[cfg(test)]
mod test;
mod utils;

pub use self::hbbft_engine::HoneyBadgerBFT;

use crypto::publickey::Public;
use std::fmt;

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NodeId(pub Public);

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:6}", hex_fmt::HexFmt(&self.0))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "NodeId({})", self.0)
    }
}

impl NodeId {
    pub fn as_8_byte_string(&self) -> String {
        std::format!(
            "{:x}{:x}{:x}{:x}{:x}{:x}{:x}{:x}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7]
        )
    }
}
