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

//! Helpers and tests for operating on jsontests.

mod chain;
mod difficulty;
mod executive;
mod local;
mod state;
mod test_common;
mod transaction;
mod trie;

/// executor of ethereum/json tests
pub mod runner;

pub use self::{
    executive::json_executive_test,
    test_common::{HookType, debug_include_test, find_json_files_recursive},
};
