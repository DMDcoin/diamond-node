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

//! Nonoperative tracer.

use crate::trace::{
    FlatTrace, Tracer, VMTracer,
    trace::{RewardType, VMTrace},
};
use ethereum_types::{Address, U256};
use vm::{ActionParams, Error as VmError};

/// Nonoperative tracer. Does not trace anything.
pub struct NoopTracer;

impl Tracer for NoopTracer {
    type Output = FlatTrace;

    fn prepare_trace_call(&mut self, _: &ActionParams, _: usize, _: bool) {}
    fn prepare_trace_create(&mut self, _: &ActionParams) {}
    fn done_trace_call(&mut self, _: U256, _: &[u8]) {}
    fn done_trace_create(&mut self, _: U256, _: &[u8], _: Address) {}
    fn done_trace_failed(&mut self, _: &VmError) {}
    fn trace_suicide(&mut self, _: Address, _: U256, _: Address) {}
    fn trace_reward(&mut self, _: Address, _: U256, _: RewardType) {}
    fn drain(self) -> Vec<FlatTrace> {
        vec![]
    }
}

/// Nonoperative VM tracer. Does not trace anything.
pub struct NoopVMTracer;

impl VMTracer for NoopVMTracer {
    type Output = VMTrace;

    fn drain(self) -> Option<VMTrace> {
        None
    }
}
