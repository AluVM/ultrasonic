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

use std::ops::RangeInclusive;

use aluvm::alu::SiteId;
use aluvm::gfa::FieldInstr;
use aluvm::isa::{Bytecode, BytecodeRead, BytecodeWrite, CodeEofError, CtrlInstr, ReservedInstr};

use super::UsonicInstr;
use crate::Instr;

impl UsonicInstr {
    const START: u8 = 128;
    const END: u8 = Self::START + Self::LDOAO;

    const CKNXIRO: u8 = 0;
    const CKNXIAO: u8 = 1;
    const CKNXORO: u8 = 2;
    const CKNXOAO: u8 = 3;

    const LDIRO: u8 = 4;
    const LDIAO: u8 = 5;
    const LDORO: u8 = 6;
    const LDOAO: u8 = 7;
}

impl<Id: SiteId> Bytecode<Id> for UsonicInstr {
    fn op_range() -> RangeInclusive<u8> { Self::START..=Self::END }

    fn opcode_byte(&self) -> u8 {
        Self::START
            + match *self {
                UsonicInstr::CkNxIRo => Self::CKNXIRO,
                UsonicInstr::CkNxIAo => Self::CKNXIAO,
                UsonicInstr::CkNxORo => Self::CKNXORO,
                UsonicInstr::CkNxOAo => Self::CKNXOAO,
                UsonicInstr::LdIRo => Self::LDIRO,
                UsonicInstr::LdIAo => Self::LDIAO,
                UsonicInstr::LdORo => Self::LDORO,
                UsonicInstr::LdOAo => Self::LDOAO,
            }
    }

    fn code_byte_len(&self) -> u16 { 1 }

    fn encode_operands<W>(&self, _writer: &mut W) -> Result<(), W::Error>
    where W: BytecodeWrite<Id> {
        match *self {
            UsonicInstr::CkNxIRo
            | UsonicInstr::CkNxIAo
            | UsonicInstr::CkNxORo
            | UsonicInstr::CkNxOAo => Ok(()),
            UsonicInstr::LdIRo | UsonicInstr::LdIAo | UsonicInstr::LdORo | UsonicInstr::LdOAo => {
                Ok(())
            }
        }
    }

    fn decode_operands<R>(_reader: &mut R, opcode: u8) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: BytecodeRead<Id>,
    {
        Ok(match opcode - Self::START {
            Self::CKNXIRO => UsonicInstr::CkNxIRo,
            Self::CKNXIAO => UsonicInstr::CkNxIAo,
            Self::CKNXORO => UsonicInstr::CkNxORo,
            Self::CKNXOAO => UsonicInstr::CkNxOAo,
            Self::LDIRO => UsonicInstr::LdIRo,
            Self::LDIAO => UsonicInstr::LdIAo,
            Self::LDORO => UsonicInstr::LdORo,
            Self::LDOAO => UsonicInstr::LdOAo,
            _ => unreachable!(),
        })
    }
}

impl<Id: SiteId> Bytecode<Id> for Instr<Id> {
    fn op_range() -> RangeInclusive<u8> { 0..=0xFF }

    fn opcode_byte(&self) -> u8 {
        match self {
            Instr::Ctrl(instr) => instr.opcode_byte(),
            Instr::Gfa(instr) => Bytecode::<Id>::opcode_byte(instr),
            Instr::Usonic(instr) => Bytecode::<Id>::opcode_byte(instr),
            Instr::Reserved(instr) => Bytecode::<Id>::opcode_byte(instr),
        }
    }

    fn code_byte_len(&self) -> u16 {
        match self {
            Instr::Ctrl(instr) => instr.code_byte_len(),
            Instr::Gfa(instr) => Bytecode::<Id>::code_byte_len(instr),
            Instr::Usonic(instr) => Bytecode::<Id>::code_byte_len(instr),
            Instr::Reserved(instr) => Bytecode::<Id>::code_byte_len(instr),
        }
    }

    fn encode_operands<W>(&self, writer: &mut W) -> Result<(), W::Error>
    where W: BytecodeWrite<Id> {
        match self {
            Instr::Ctrl(instr) => instr.encode_operands(writer),
            Instr::Gfa(instr) => instr.encode_operands(writer),
            Instr::Usonic(instr) => instr.encode_operands(writer),
            Instr::Reserved(instr) => instr.encode_operands(writer),
        }
    }

    fn decode_operands<R>(reader: &mut R, opcode: u8) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: BytecodeRead<Id>,
    {
        match opcode {
            op if CtrlInstr::<Id>::op_range().contains(&op) => {
                CtrlInstr::<Id>::decode_operands(reader, op).map(Self::Ctrl)
            }
            op if <FieldInstr as Bytecode<Id>>::op_range().contains(&op) => {
                FieldInstr::decode_operands(reader, op).map(Self::Gfa)
            }
            op if <UsonicInstr as Bytecode<Id>>::op_range().contains(&op) => {
                UsonicInstr::decode_operands(reader, op).map(Self::Usonic)
            }
            _ => ReservedInstr::decode_operands(reader, opcode).map(Self::Reserved),
        }
    }
}
