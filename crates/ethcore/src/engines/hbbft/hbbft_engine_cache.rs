use crate::{client::EngineClient, error::Error};
use ethereum_types::Address;
use parking_lot::Mutex;

#[derive(Debug, Clone)]
pub struct HbbftEngineCacheData {
    pub signer_address: Address,

    pub is_staked: bool,

    pub is_available: bool,
}

impl HbbftEngineCacheData {
    pub fn new() -> Self {
        HbbftEngineCacheData {
            signer_address: Address::zero(),
            is_staked: false,
            is_available: false,
        }
    }
}

pub struct HbbftEngineCache {
    data: Mutex<HbbftEngineCacheData>,
}

impl HbbftEngineCache {
    pub fn new() -> Self {
        HbbftEngineCache {
            data: Mutex::new(HbbftEngineCacheData::new()),
        }
    }

    pub fn is_staked(&self) -> bool {
        self.data.lock().is_staked
    }

    // pub fn signer_address(&self) -> Address {
    //     // this is dead code for now, but for further optimization we will use it in the future,
    //     self.data.lock().signer_address
    // }

    pub fn is_available(&self) -> bool {
        self.data.lock().is_available
    }

    /// Refresh the cache values.
    pub fn refresh_cache(
        &mut self,
        signer_address: Address,
        engine_client: &dyn EngineClient,
    ) -> Result<(), Error> {
        //self.is_staked = false;

        let mut new_data = HbbftEngineCacheData::new();
        new_data.signer_address = signer_address;
        let is_available = self.calc_is_available(signer_address, engine_client)?;
        new_data.is_available = is_available;
        new_data.is_staked = self.calc_is_staked(signer_address, engine_client)?;

        self.data.lock().clone_from(&new_data);

        return Ok(());
    }

    fn calc_is_available(
        &mut self,
        signer_address: Address,
        engine_client: &dyn EngineClient,
    ) -> Result<bool, Error> {
        let engine_client = engine_client;

        if signer_address.is_zero() {
            // debug!(target: "consensus", "is_available: not available because mining address is zero: ");
            return Ok(false);
        }

        match super::contracts::validator_set::get_validator_available_since(
            engine_client,
            &signer_address,
        ) {
            Ok(available_since) => {
                trace!(target: "consensus", "available_since: {}", available_since);
                return Ok(!available_since.is_zero());
            }
            Err(err) => {
                warn!(target: "consensus", "Error get get_validator_available_since: ! {:?}", err);
            }
        }
        return Ok(false);
    }

    /// refreshes cache, if node is staked.
    fn calc_is_staked(
        &self,
        mining_address: Address,
        engine_client: &dyn EngineClient,
    ) -> Result<bool, Error> {
        // is the configured validator stacked ??
        match super::contracts::validator_set::staking_by_mining_address(
            engine_client,
            &mining_address,
        ) {
            Ok(staking_address) => {
                // if there is no pool for this validator defined, we know that
                if staking_address.is_zero() {
                    return Ok(false);
                }
                match super::contracts::staking::stake_amount(
                    engine_client,
                    &staking_address,
                    &staking_address,
                ) {
                    Ok(stake_amount) => {
                        trace!(target: "consensus", "stake_amount: {}", stake_amount);

                        // we need to check if the pool stake amount is >= minimum stake
                        match super::contracts::staking::candidate_min_stake(engine_client) {
                            Ok(min_stake) => {
                                trace!(target: "consensus", "min_stake: {}", min_stake);
                                return Ok(stake_amount.ge(&min_stake));
                            }
                            Err(err) => {
                                error!(target: "consensus", "Error get candidate_min_stake: ! {:?}", err);
                                return Ok(false);
                                //return Err(err.into());
                            }
                        }
                    }
                    Err(err) => {
                        warn!(target: "consensus", "Error get stake_amount: ! {:?}", err);
                        return Ok(false);
                    }
                }
            }
            Err(err) => {
                warn!(target: "consensus", "Error get staking_by_mining_address: ! {:?}", err);
                return Ok(false);
            }
        }
    }
}
