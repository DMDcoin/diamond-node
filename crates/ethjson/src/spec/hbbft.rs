// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! Hbbft parameter deserialization.

use ethereum_types::Address;
use serde_with::serde_as;

/// Skip block reward parameter.
/// Defines one (potential open) range about skips
/// for reward calls in the hbbft engine.
/// https://github.com/DMDcoin/openethereum-3.x/issues/49
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct HbbftParamsSkipBlockReward {
    /// No block reward calls get executed by the hbbft engine with beginning with this block (inclusive).
    pub from_block: u64,
    /// No block reward calls get executed up to this block (inclusive).
    pub to_block: Option<u64>,
}

#[serde_as]
#[derive(Debug, PartialEq, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct HbbftNetworkFork {
    /// Block number at which the fork starts.
    pub block_number_start: u64,

    /// Forks that became finished, require a definition when the take over of the
    /// specified validators was finished.
    #[serde(default)]
    pub block_number_end: Option<u64>,

    /// Validator set (public keys) of the fork.
    #[serde_as(as = "Vec<serde_with::hex::Hex>")]
    pub validators: Vec<Vec<u8>>,

    #[serde_as(as = "Vec<serde_with::hex::Hex>")]
    pub parts: Vec<Vec<u8>>,

    #[serde_as(as = "Vec<Vec<serde_with::hex::Hex>>")]
    pub acks: Vec<Vec<Vec<u8>>>,
}

impl HbbftNetworkFork {
    /// Returns true if the fork is finished.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("HbbftNetworkFork must convert to JSON")
    }
}

/// Hbbft parameters.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct HbbftParams {
    /// The minimum time duration between blocks, in seconds.
    pub minimum_block_time: u64,
    /// The maximum time duration between blocks, in seconds.
    pub maximum_block_time: u64,
    /// The length of the transaction queue at which block creation should be triggered.
    pub transaction_queue_size_trigger: usize,
    /// Should be true when running unit tests to avoid starting timers.
    pub is_unit_test: Option<bool>,
    /// Block reward contract address.
    pub block_reward_contract_address: Option<Address>,
    /// Block reward skips at different blocks.
    pub block_reward_skips: Option<Vec<HbbftParamsSkipBlockReward>>,
    /// Number of consensus messages to store on the disk. 0 means zero blocks get stored.
    pub blocks_to_keep_on_disk: Option<u64>,
    /// Directory where to store the Hbbft Messages.
    /// Usually only the latest HBBFT messages are interesting for Debug, Analytics or Evidence.
    pub blocks_to_keep_directory: Option<String>,
    /// Hbbft network forks.
    /// A Fork defines a new Validator Set.
    /// This validator set is becomming pending so it can write it's PARTs and ACKS.
    /// From beginning of the fork trigger block until the finality of the key gen transactions,
    /// no block verifications are done.
    #[serde(default)]
    pub forks: Vec<HbbftNetworkFork>,
}

/// Hbbft engine config.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hbbft {
    /// Hbbft parameters.
    pub params: HbbftParams,
}

impl HbbftParams {
    /// Should the reward call get executed.
    /// Returns false if a skip section is defined for this block number.
    pub fn should_do_block_reward_contract_call(&self, block_number: u64) -> bool {
        if let Some(skips) = &self.block_reward_skips {
            for skip in skips {
                if block_number >= skip.from_block {
                    if let Some(end) = skip.to_block {
                        if block_number <= end {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use ethereum_types::Address;

    use super::Hbbft;
    use std::str::FromStr;

    #[test]
    fn hbbft_deserialization_forks() {
        let s = r#"{
			"params": {
                "minimumBlockTime": 0,
				"maximumBlockTime": 600,
				"transactionQueueSizeTrigger": 1,
				"isUnitTest": true,
				"blockRewardContractAddress": "0x2000000000000000000000000000000000000002",
				"forks": [
                    {
                        "blockNumberStart" : 777,
                        "validators": [
                            "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
                        ],
                        "parts": ["19585436b7d97298a751e2a6020c30677497772013001420c0a6aea5790347bdf5531c1387be685a232b01ec614913b18da0a6cbcd1074f1733f902a7eb656e9"],
                        "acks": [["19585436b7d97298a751e2a6020c30677497772013001420c0a6aea5790347bdf5531c1387be685a232b01ec614913b18da0a6cbcd1074f1733f902a7eb656e9"]]
                    }
                ]
			}
		}"#;

        let deserialized: Hbbft = serde_json::from_str(s).unwrap();
        assert_eq!(deserialized.params.forks.len(), 1);
        assert_eq!(
            deserialized
                .params
                .forks
                .get(0)
                .expect("")
                .block_number_start,
            777
        );
        assert_eq!(deserialized.params.forks.get(0).expect("").parts.len(), 1);
        assert_eq!(deserialized.params.forks.get(0).expect("").acks.len(), 1);
        assert_eq!(
            deserialized.params.forks.get(0).expect("").validators.len(),
            1
        );
        assert_eq!(
            deserialized
                .params
                .forks
                .get(0)
                .expect("")
                .validators
                .get(0)
                .expect("")
                .len(),
            64
        );
    }

    #[test]
    fn hbbft_deserialization() {
        let s = r#"{
			"params": {
				"minimumBlockTime": 0,
				"maximumBlockTime": 600,
				"transactionQueueSizeTrigger": 1,
				"isUnitTest": true,
				"blockRewardContractAddress": "0x2000000000000000000000000000000000000002"
			}
		}"#;

        let deserialized: Hbbft = serde_json::from_str(s).unwrap();
        assert_eq!(deserialized.params.minimum_block_time, 0);
        assert_eq!(deserialized.params.maximum_block_time, 600);
        assert_eq!(deserialized.params.transaction_queue_size_trigger, 1);
        assert_eq!(deserialized.params.is_unit_test, Some(true));
        assert_eq!(
            deserialized.params.block_reward_contract_address,
            Address::from_str("2000000000000000000000000000000000000002").ok()
        );
    }

    #[test]
    fn hbbft_deserialization_reward_skips() {
        let s = r#"{
			"params": {
				"minimumBlockTime": 0,
				"maximumBlockTime": 600,
				"transactionQueueSizeTrigger": 1,
				"isUnitTest" : true,
				"blockRewardContractAddress": "0x2000000000000000000000000000000000000002",
				"blockRewardSkips" : [
					{ "fromBlock": 1000, "toBlock": 2000 },
					{ "fromBlock": 3000 }
				]
			}
		}"#;

        let deserialized: Hbbft = serde_json::from_str(s).unwrap();
        assert!(deserialized.params.block_reward_skips.is_some());
        let skips = deserialized.params.block_reward_skips.as_ref().unwrap();
        assert_eq!(skips.len(), 2);
        assert_eq!(
            deserialized.params.should_do_block_reward_contract_call(0),
            true
        );
        assert_eq!(
            deserialized
                .params
                .should_do_block_reward_contract_call(1000),
            false
        );
        assert_eq!(
            deserialized
                .params
                .should_do_block_reward_contract_call(1500),
            false
        );
        assert_eq!(
            deserialized
                .params
                .should_do_block_reward_contract_call(2000),
            false
        );
        assert_eq!(
            deserialized
                .params
                .should_do_block_reward_contract_call(2001),
            true
        );
        assert_eq!(
            deserialized
                .params
                .should_do_block_reward_contract_call(3001),
            false
        );
        assert_eq!(
            deserialized
                .params
                .should_do_block_reward_contract_call(100_000),
            false
        );
    }

    #[test]
    fn test_fork_serialisation() {
        let fork = super::HbbftNetworkFork {
            block_number_start: 10,
            block_number_end: Some(100),
            validators: vec![vec![1, 2, 3, 4]],
            parts: vec![vec![5, 6, 7, 8]],
            acks: vec![vec![vec![9, 10, 11, 12]]],
        };

        let json = fork.to_json();
        let deserialized: super::HbbftNetworkFork = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.block_number_start, 10);
        assert_eq!(deserialized.block_number_end, Some(100));
        assert_eq!(deserialized.validators.len(), 1);
        assert_eq!(deserialized.parts.len(), 1);
        assert_eq!(deserialized.acks.len(), 1);

        assert_eq!(deserialized.parts[0][1], 6);
        assert_eq!(deserialized.acks[0][0][2], 11);
    }
}
