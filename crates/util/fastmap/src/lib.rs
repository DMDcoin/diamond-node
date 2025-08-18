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

//! Provides a `H256FastMap` type with H256 keys and fast hashing function.

use ethereum_types;
extern crate lru;
extern crate plain_hasher;

use self::lru::LruCache;
use ethereum_types::H256;
use plain_hasher::PlainHasher;
use std::{
    collections::{HashMap, HashSet},
    hash,
    num::NonZeroUsize,
};

/// Specialized version of `HashMap` with H256 keys and fast hashing function.
pub type H256FastMap<T> = HashMap<H256, T, hash::BuildHasherDefault<PlainHasher>>;
/// Specialized version of HashSet with H256 values and fast hashing function.
pub type H256FastSet = HashSet<H256, hash::BuildHasherDefault<PlainHasher>>;

pub type H256FastLruMap<T> = LruCache<H256, T, hash::BuildHasherDefault<PlainHasher>>;

pub fn new_h256_fast_lru_map<T>(cap: NonZeroUsize) -> H256FastLruMap<T> {
    LruCache::with_hasher(cap, hash::BuildHasherDefault::<PlainHasher>::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_works() {
        let mut h = H256FastMap::default();
        h.insert(H256::from_low_u64_be(123), "abc");
    }
}
