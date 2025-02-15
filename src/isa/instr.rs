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

use aluvm::gfa::FieldInstr;
use aluvm::isa::{CtrlInstr, ReservedInstr};
use aluvm::{Site, SiteId};

pub const ISA_ULTRASONIC: &str = "USONIC";

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display, From)]
#[display(inner)]
#[non_exhaustive]
pub enum Instr<Id: SiteId> {
    /// Control flow instructions.
    #[from]
    Ctrl(CtrlInstr<Id>),

    #[from]
    Gfa(FieldInstr),

    #[from]
    Usonic(UsonicInstr<Id>),

    /// Reserved instruction for future use in core `ALU` ISAs.
    #[from]
    Reserved(ReservedInstr),
}

/// The instruction set uses iterator semantics and not random access semantic to correspond to the
/// RISC type of the machine and not to add assumptions about abilities to access the operation
/// state in a random way. Operation state is always iterated, such that not a single state
/// element can be missed (as long as iterator runs to the end).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(inner)]
#[non_exhaustive]
pub enum UsonicInstr<Id: SiteId> {
    /// Jump to process the next read-only memory cell in the contract state listed in the
    /// operation input.
    #[display("nxi.ro  {0}")]
    NxIRo(Site<Id>),

    /// Jump to process the next immutable memory cell in the contract state listed in the
    /// operation input.
    #[display("nxi.im  {0}")]
    NxIIm(Site<Id>),

    /// Jump to process the next read-only memory cell defined by the operation.
    #[display("nxo.ro  {0}")]
    NxORo(Site<Id>),

    /// Jump to process the next immutable memory cell defined by the operation.
    #[display("nxo.im  {0}")]
    NxOIm(Site<Id>),

    /// Load next field element from the current input read-only memory cell to `EA` register,
    #[display("ldi.ro  EA")]
    LdIRo,

    /// Load next field element from the current input immutable memory cell to `EB` register,
    #[display("ldi.im  EB")]
    LdIIm,

    /// Load next field element from the current input read-only memory cell to `EC` register,
    #[display("ldo.ro  EC")]
    LdORo,

    /// Load next field element from the current input read-only memory cell to `ED` register,
    #[display("ldo.im  ED")]
    LdOIm,
}
