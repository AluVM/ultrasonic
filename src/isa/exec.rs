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

use std::collections::BTreeSet;

use aluvm::alu::{Core, CoreExt, ExecStep, Site, SiteId};
use aluvm::isa::Instruction;
use aluvm::RegE;

use super::{UsonicCore, UsonicInstr, REG_IN_IM, REG_IN_RO, REG_OUT_IM, REG_OUT_RO};
use crate::{Instr, VmContext, ISA_ULTRASONIC};

impl<Id: SiteId> Instruction<Id> for UsonicInstr {
    const ISA_EXT: &'static [&'static str] = &[ISA_ULTRASONIC];
    type Core = UsonicCore;
    type Context<'ctx> = VmContext<'ctx>;

    fn src_regs(&self) -> BTreeSet<RegE> { none!() }

    fn dst_regs(&self) -> BTreeSet<RegE> { none!() }

    fn op_data_bytes(&self) -> u16 {
        match *self {
            UsonicInstr::NxIRo | UsonicInstr::NxIIm | UsonicInstr::NxORo | UsonicInstr::NxOIm => 0,
            UsonicInstr::LdIRo | UsonicInstr::LdIIm | UsonicInstr::LdORo | UsonicInstr::LdOIm => 0,
        }
    }

    fn ext_data_bytes(&self) -> u16 {
        match *self {
            UsonicInstr::NxIRo | UsonicInstr::NxIIm | UsonicInstr::NxORo | UsonicInstr::NxOIm => 0,
            UsonicInstr::LdIRo | UsonicInstr::LdIIm | UsonicInstr::LdORo | UsonicInstr::LdOIm => 0,
        }
    }

    fn exec(
        &self,
        _site: Site<Id>,
        core: &mut Core<Id, Self::Core>,
        context: &Self::Context<'_>,
    ) -> ExecStep<Site<Id>> {
        match *self {
            UsonicInstr::NxIRo => {
                let res = core.cx.next(REG_IN_RO, context);
                core.set_co(res);
                ExecStep::Next
            }
            UsonicInstr::NxIIm => {
                let res = core.cx.next(REG_IN_IM, context);
                core.set_co(res);
                ExecStep::Next
            }
            UsonicInstr::NxORo => {
                let res = core.cx.next(REG_OUT_RO, context);
                core.set_co(res);
                ExecStep::Next
            }
            UsonicInstr::NxOIm => {
                let res = core.cx.next(REG_OUT_IM, context);
                core.set_co(res);
                ExecStep::Next
            }
            UsonicInstr::LdIRo => core.cx.load(REG_IN_RO, context),
            UsonicInstr::LdIIm => core.cx.load(REG_IN_IM, context),
            UsonicInstr::LdORo => core.cx.load(REG_OUT_RO, context),
            UsonicInstr::LdOIm => core.cx.load(REG_OUT_IM, context),
        }
    }
}

impl<Id: SiteId> Instruction<Id> for Instr<Id> {
    const ISA_EXT: &'static [&'static str] = &[ISA_ULTRASONIC];
    type Core = UsonicCore;
    type Context<'ctx> = VmContext<'ctx>;

    fn src_regs(&self) -> BTreeSet<<Self::Core as CoreExt>::Reg> {
        match self {
            Instr::Ctrl(_) => none!(),
            Instr::Gfa(instr) => Instruction::<Id>::src_regs(instr),
            Instr::Usonic(instr) => Instruction::<Id>::src_regs(instr),
            Instr::Reserved(_) => none!(),
        }
    }

    fn dst_regs(&self) -> BTreeSet<<Self::Core as CoreExt>::Reg> {
        match self {
            Instr::Ctrl(_) => none!(),
            Instr::Gfa(instr) => Instruction::<Id>::dst_regs(instr),
            Instr::Usonic(instr) => Instruction::<Id>::src_regs(instr),
            Instr::Reserved(_) => none!(),
        }
    }

    fn op_data_bytes(&self) -> u16 {
        match self {
            Instr::Ctrl(instr) => instr.op_data_bytes(),
            Instr::Gfa(instr) => Instruction::<Id>::op_data_bytes(instr),
            Instr::Usonic(instr) => Instruction::<Id>::op_data_bytes(instr),
            Instr::Reserved(_) => none!(),
        }
    }

    fn ext_data_bytes(&self) -> u16 {
        match self {
            Instr::Ctrl(instr) => instr.ext_data_bytes(),
            Instr::Gfa(instr) => Instruction::<Id>::ext_data_bytes(instr),
            Instr::Usonic(instr) => Instruction::<Id>::ext_data_bytes(instr),
            Instr::Reserved(_) => none!(),
        }
    }

    fn exec(
        &self,
        site: Site<Id>,
        core: &mut Core<Id, Self::Core>,
        context: &Self::Context<'_>,
    ) -> ExecStep<Site<Id>> {
        match self {
            Instr::Ctrl(instr) => {
                let mut subcore = Core::from(core.clone());
                let step = instr.exec(site, &mut subcore, &mut ());
                *core = subcore.extend(core.cx.clone());
                step
            }
            Instr::Gfa(instr) => {
                let mut subcore = Core::from(core.clone());
                let step = instr.exec(site, &mut subcore, &mut ());
                *core = subcore.extend(core.cx.clone());
                step
            }
            Instr::Usonic(instr) => Instruction::<Id>::exec(instr, site, core, context),
            Instr::Reserved(instr) => {
                let mut subcore = Core::from(core.clone());
                let step = instr.exec(site, &mut subcore, &mut ());
                *core = subcore.extend(core.cx.clone());
                step
            }
        }
    }
}
