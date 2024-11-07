// UltraSONIC: transactional execution layer with capability-based memory access for zk-AluVM
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2024 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
// Written in 2024 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
//
// Copyright (C) 2019-2025 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky. 
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use aluvm::isa::ISA_GFA128;
use aluvm::{IsaId, Lib, LibSite, ISA_ALU128};
use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use commit_verify::ReservedBytes;

use crate::{
    Fiel128, Operation, OwnedState, StateData, StatePtr, StateTransition, ISA_ULTRASONIC, LIB_NAME_ULTRASONIC,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct VmConfig {
    #[cfg_attr(feature = "serde", serde(skip))]
    pub reserved: ReservedBytes<1>,
    pub isa: IsaId,
    pub isa_extensions: TinyOrdSet<IsaId>,
    pub core_config: aluvm::CoreConfig,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            reserved: default!(),
            isa: IsaId::from(ISA_ALU128),
            isa_extensions: tiny_bset![IsaId::from(ISA_GFA128), IsaId::from(ISA_ULTRASONIC)],
            core_config: aluvm::CoreConfig {
                halt: true,
                complexity_lim: None,
                field_order: aluvm::gfa::Fq::F1137119,
            },
        }
    }
}

pub type CallId = u16;
pub type AccessId = u16;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Contract {
    pub version: ReservedBytes<2>,

    pub vm_config: VmConfig,
    pub contract_code: TinyOrdSet<Lib>,
    pub calls: TinyOrdMap<CallId, LibSite>,
    pub verifiers: TinyOrdMap<AccessId, LibSite>,

    /// Reserved for the future contract extensions
    pub reserved: ReservedBytes<8>,
}

pub trait ContractState {
    fn free_state(&self, addr: Fiel128) -> StateData;
    fn owned_state(&self, from: StatePtr) -> OwnedState;
    fn apply(&mut self, transition: StateTransition);
}

pub trait LibRepo {}
pub enum CallError {}

impl Contract {
    pub fn call(
        &self,
        state: &impl ContractState,
        operation: &Operation,
        client_locks: &impl LibRepo,
    ) -> Result<StateTransition, CallError> {
        // Check access to the owned state by ensuring
        // - access check via script call
        // - lock script lock conditions are fulfilled, if present
        // Call VM to compute state evolution
        todo!()
    }
}
