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

//! **UltraSONIC** is a state machine with capability-based memory access. In simple words, this
//! means <q>state machine with cryptographically protected memory cells</q>.
//!
//! What is capability-based memory access (or capability-addressable memory, **CAM**)? The
//! computers we all used to are random memory access machines (RAM), where software accesses
//! freely addressable global memory. This has opened a door for all the vulnerabilities and
//! hacks happening in computer systems across the world for the past decades... CAM model instead,
//! divides all memory into parts (called *words*) addressable only with some access token (called
//! *capability*). One may think of this as of a memory where each part is "owned" by a certain
//! party and can be accessed or modified only given a proof of ownership.
//!
//! **UltraSONIC** leverages zk-AluVM, so it is (1) zk-STARK-compatible and (2) exception-less, made
//! with category theory in mind.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// TODO: Activate no_std once StrictEncoding will support it
// #![no_std]
#![deny(missing_docs)]

extern crate alloc;

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_verify;
pub extern crate zkaluvm as aluvm;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[macro_use]
mod deser;
mod codex;
mod state;
mod operation;
mod isa;
mod issue;
#[cfg(feature = "stl")]
pub mod stl;
mod util;

pub use codex::{CallError, CallId, Codex, CodexId, LibRepo, Memory};
pub use isa::{Instr, IoCat, UsonicCore, UsonicInstr, VmContext, ISA_ULTRASONIC};
pub use issue::{Consensus, ContractId, ContractMeta, ContractName, Issue};
#[cfg(feature = "baid64")]
pub use operation::ParseAddrError;
pub use operation::{CellAddr, Genesis, Input, Operation, Opid, VerifiedOperation};
pub use state::{AuthToken, RawData, StateCell, StateData, StateValue};
pub use util::Identity;
pub use zkaluvm::fe256;

/// Strict type library name for the types defined in this crate.
pub const LIB_NAME_ULTRASONIC: &str = "UltraSONIC";
