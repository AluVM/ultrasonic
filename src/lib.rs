// UltraSONIC: transactional execution layer with capability-based memory access for zk-AluVM
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
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

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// TODO: Activate no_std once StrictEncoding will support it
// #![no_std]

extern crate alloc;

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_verify;
extern crate zkaluvm as aluvm;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;
extern crate core;

mod codex;
mod state;
mod operation;
mod isa;
mod contract;
#[cfg(feature = "stl")]
pub mod stl;
mod util;

pub use codex::{AccessId, CallError, CallId, Codex, CodexId, LibRepo, Memory, VmContext};
pub use contract::{ContractId, ProofOfPubl};
pub use isa::{Instr, UsonicCore, UsonicInstr, ISA_ULTRASONIC};
pub use operation::{CellAddr, Input, Operation, Opid};
pub use state::{StateCell, StateData, StateValue};
pub use util::Identity;

pub const LIB_NAME_ULTRASONIC: &str = "UltraSONIC";
