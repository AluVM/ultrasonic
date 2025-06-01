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

use aluvm::alu::regs::Status;
use aluvm::alu::{Core, CoreExt, ExecStep, Site, SiteId, Supercore};
use aluvm::isa::{GotoTarget, Instruction};
use aluvm::RegE;

use super::{UsonicCore, UsonicInstr};
use crate::{AuthToken, Input, Instr, IoCat, StateCell, StateData, StateValue, ISA_ULTRASONIC};

/// Context object provided to the VM instance, containing references to the operation inputs and
/// outputs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VmContext<'ctx> {
    /// Operation-level witness.
    pub witness: StateValue,
    /// Operation input consisting of the destructible (read-once) memory cells.
    pub destructible_input: &'ctx [(Input, StateCell)],
    /// Operation input consisting of the immutable (read-only) memory cells.
    pub immutable_input: &'ctx [StateValue],
    /// Operation output defining new destructible (read-once) memory cells.
    pub destructible_output: &'ctx [StateCell],
    /// Operation output defining new immutable (append-only) memory cells.
    pub immutable_output: &'ctx [StateData],
}

impl VmContext<'_> {
    /// Returns a state value from the provided category of operation inputs/outputs using the given
    /// `index`.
    ///
    /// If the operation doesn't contain input/output with the index, returns `None`.
    pub fn state_value(&self, cat: IoCat, index: u16) -> Option<StateValue> {
        match cat {
            IoCat::IN_RO => self
                .destructible_input
                .get(index as usize)
                .map(|(_, cell)| cell.data),
            IoCat::IN_AO => self.immutable_input.get(index as usize).copied(),
            IoCat::OUT_RO => self
                .destructible_output
                .get(index as usize)
                .map(|cell| cell.data),
            IoCat::OUT_AO => self
                .immutable_output
                .get(index as usize)
                .map(|cell| cell.value),
        }
    }

    /// Returns a state value from the destructible input previous output auxiliary data.
    pub fn input_lock_aux(&self, index: u16) -> Option<StateValue> {
        self.destructible_input
            .get(index as usize)
            .and_then(|(_, cell)| cell.lock)
            .map(|lock| lock.aux)
    }

    /// Returns a state value from the destructible input witness.
    pub fn input_witness(&self, index: u16) -> Option<StateValue> {
        self.destructible_input
            .get(index as usize)
            .map(|(input, _)| input.witness)
    }

    /// Returns a state value from the destructible input previous output auth token and whether
    ///  it is locked by a script.
    pub fn input_auth_token(&self, index: u16) -> Option<(AuthToken, bool)> {
        self.destructible_input
            .get(index as usize)
            .map(|(_, cell)| (cell.auth, cell.lock.map(|lock| lock.script).is_some()))
    }
}

impl<Id: SiteId> Instruction<Id> for UsonicInstr {
    const ISA_EXT: &'static [&'static str] = &[ISA_ULTRASONIC];
    type Core = UsonicCore;
    type Context<'ctx> = VmContext<'ctx>;

    fn is_goto_target(&self) -> bool { false }

    fn local_goto_pos(&mut self) -> GotoTarget { GotoTarget::None }

    fn remote_goto_pos(&mut self) -> Option<&mut Site<Id>> { None }

    fn src_regs(&self) -> BTreeSet<RegE> { none!() }

    fn dst_regs(&self) -> BTreeSet<RegE> {
        match *self {
            UsonicInstr::CkNxIRo
            | UsonicInstr::CkNxIAo
            | UsonicInstr::CkNxORo
            | UsonicInstr::CkNxOAo => none!(),
            UsonicInstr::LdW
            | UsonicInstr::LdIW
            | UsonicInstr::LdIL
            | UsonicInstr::LdIRo
            | UsonicInstr::LdIAo
            | UsonicInstr::LdORo
            | UsonicInstr::LdOAo => {
                bset![RegE::EA, RegE::EB, RegE::EC, RegE::ED]
            }
            UsonicInstr::LdIT => {
                bset![RegE::EA, RegE::EB]
            }
            UsonicInstr::RstIRo
            | UsonicInstr::RstIAo
            | UsonicInstr::RstORo
            | UsonicInstr::RstOAo => none!(),
        }
    }

    fn op_data_bytes(&self) -> u16 {
        match *self {
            UsonicInstr::CkNxIRo
            | UsonicInstr::CkNxIAo
            | UsonicInstr::CkNxORo
            | UsonicInstr::CkNxOAo => 0,
            UsonicInstr::LdW
            | UsonicInstr::LdIW
            | UsonicInstr::LdIL
            | UsonicInstr::LdIT
            | UsonicInstr::LdIRo
            | UsonicInstr::LdIAo
            | UsonicInstr::LdORo
            | UsonicInstr::LdOAo => 0,
            UsonicInstr::RstIRo
            | UsonicInstr::RstIAo
            | UsonicInstr::RstORo
            | UsonicInstr::RstOAo => 0,
        }
    }

    fn ext_data_bytes(&self) -> u16 {
        match *self {
            UsonicInstr::CkNxIRo
            | UsonicInstr::CkNxIAo
            | UsonicInstr::CkNxORo
            | UsonicInstr::CkNxOAo => 0,
            UsonicInstr::LdW
            | UsonicInstr::LdIW
            | UsonicInstr::LdIL
            | UsonicInstr::LdIT
            | UsonicInstr::LdIRo
            | UsonicInstr::LdIAo
            | UsonicInstr::LdORo
            | UsonicInstr::LdOAo => 0,
            UsonicInstr::RstIRo
            | UsonicInstr::RstIAo
            | UsonicInstr::RstORo
            | UsonicInstr::RstOAo => 0,
        }
    }

    fn exec(
        &self,
        _site: Site<Id>,
        core: &mut Core<Id, Self::Core>,
        context: &Self::Context<'_>,
    ) -> ExecStep<Site<Id>> {
        let res = match *self {
            UsonicInstr::CkNxIRo => core.cx.has_data(IoCat::IN_RO, context),
            UsonicInstr::CkNxIAo => core.cx.has_data(IoCat::IN_AO, context),
            UsonicInstr::CkNxORo => core.cx.has_data(IoCat::OUT_RO, context),
            UsonicInstr::CkNxOAo => core.cx.has_data(IoCat::OUT_AO, context),
            UsonicInstr::LdW => {
                core.cx.set_ea_ed(context.witness);
                return ExecStep::Next;
            }
            UsonicInstr::LdIW => core
                .cx
                .set_ea_ed_opt(context.input_witness(core.cx.get_ui_inro())),
            UsonicInstr::LdIL => core
                .cx
                .set_ea_ed_opt(context.input_lock_aux(core.cx.get_ui_inro())),
            UsonicInstr::LdIT => core
                .cx
                .set_ed_eb(context.input_auth_token(core.cx.get_ui_inro())),
            UsonicInstr::LdIRo => core.cx.load(IoCat::IN_RO, context),
            UsonicInstr::LdIAo => core.cx.load(IoCat::IN_AO, context),
            UsonicInstr::LdORo => core.cx.load(IoCat::OUT_RO, context),
            UsonicInstr::LdOAo => core.cx.load(IoCat::OUT_AO, context),
            UsonicInstr::RstIRo => {
                core.cx.reset(IoCat::IN_RO);
                return ExecStep::Next;
            }
            UsonicInstr::RstIAo => {
                core.cx.reset(IoCat::IN_AO);
                return ExecStep::Next;
            }
            UsonicInstr::RstORo => {
                core.cx.reset(IoCat::OUT_RO);
                return ExecStep::Next;
            }
            UsonicInstr::RstOAo => {
                core.cx.reset(IoCat::OUT_AO);
                return ExecStep::Next;
            }
        };
        core.set_co(if res { Status::Ok } else { Status::Fail });
        ExecStep::Next
    }
}

impl<Id: SiteId> Instruction<Id> for Instr<Id> {
    const ISA_EXT: &'static [&'static str] = &[ISA_ULTRASONIC];
    type Core = UsonicCore;
    type Context<'ctx> = VmContext<'ctx>;

    fn is_goto_target(&self) -> bool {
        match self {
            Instr::Ctrl(instr) => instr.is_goto_target(),
            Instr::Gfa(instr) => Instruction::<Id>::is_goto_target(instr),
            Instr::Usonic(instr) => Instruction::<Id>::is_goto_target(instr),
            Instr::Reserved(instr) => Instruction::<Id>::is_goto_target(instr),
        }
    }

    fn local_goto_pos(&mut self) -> GotoTarget {
        match self {
            Instr::Ctrl(instr) => instr.local_goto_pos(),
            Instr::Gfa(instr) => Instruction::<Id>::local_goto_pos(instr),
            Instr::Usonic(instr) => Instruction::<Id>::local_goto_pos(instr),
            Instr::Reserved(instr) => Instruction::<Id>::local_goto_pos(instr),
        }
    }

    fn remote_goto_pos(&mut self) -> Option<&mut Site<Id>> {
        match self {
            Instr::Ctrl(instr) => instr.remote_goto_pos(),
            Instr::Gfa(instr) => Instruction::<Id>::remote_goto_pos(instr),
            Instr::Usonic(instr) => Instruction::<Id>::remote_goto_pos(instr),
            Instr::Reserved(instr) => Instruction::<Id>::remote_goto_pos(instr),
        }
    }

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
                let mut subcore = core.subcore();
                let step = instr.exec(site, &mut subcore, &());
                core.merge_subcore(subcore);
                step
            }
            Instr::Gfa(instr) => {
                let mut subcore = core.subcore();
                let step = instr.exec(site, &mut subcore, &());
                core.merge_subcore(subcore);
                step
            }
            Instr::Usonic(instr) => Instruction::<Id>::exec(instr, site, core, context),
            Instr::Reserved(instr) => {
                let mut subcore = core.subcore();
                let step = instr.exec(site, &mut subcore, &());
                core.merge_subcore(subcore);
                step
            }
        }
    }
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use aluvm::alu::{CoreConfig, Lib, LibId, LibSite, Vm};
    use aluvm::{fe256, GfaConfig, FIELD_ORDER_SECP};

    use super::*;
    use crate::uasm;

    #[test]
    fn exec() {
        const CHECK: u16 = 77;
        const VALUE: u32 = 1234567890u32;
        let code = uasm! {
            // We check we have at least one element of state
            cknxi   destructible;
            chk     CO;
            cknxi   immutable;
            chk     CO;
            cknxo   destructible;
            chk     CO;
            cknxo   immutable;
            chk     CO;

            //Ensure the check is idempotent
            cknxi   destructible;
            chk     CO;
            cknxi   immutable;
            chk     CO;
            cknxo   destructible;
            chk     CO;
            cknxo   immutable;
            chk     CO;

            // We load the first element of state
            ldi     destructible;
            call    CHECK;
            ldi     immutable;
            call    CHECK;
            ldo     destructible;
            call    CHECK;
            ldo     immutable;
            call    CHECK;

            // We reset the counter
            rsti    destructible;
            rsti    immutable;
            rsto    destructible;
            rsto    immutable;

            // We load the first element of state once more
            ldi     destructible;
            call    CHECK;
            ldi     immutable;
            call    CHECK;
            ldo     destructible;
            call    CHECK;
            ldo     immutable;
            call    CHECK;

            // Now we make sure that there is no second argument
            cknxi   destructible;
            not     CO;
            chk     CO;
            cknxi   immutable;
            not     CO;
            chk     CO;
            cknxo   destructible;
            not     CO;
            chk     CO;
            cknxo   immutable;
            not     CO;
            chk     CO;

            // As well as we can't load the second argument
            ldi     destructible;
            not     CO;
            chk     CO;
            ldi     immutable;
            not     CO;
            chk     CO;
            ldo     destructible;
            not     CO;
            chk     CO;
            ldo     immutable;
            not     CO;
            chk     CO;
            stop;

           routine CHECK:
            put     E2, VALUE;
            chk     CO;
            eq      EA, E2;
            chk     CO;
            test    EB;
            not     CO;
            chk     CO;
            test    EC;
            not     CO;
            chk     CO;
            test    ED;
            not     CO;
            chk     CO;
            clr     EA;
            ret;
        };
        // Use this line to compute offset of the `CHECK` routine when you modify the script above
        //let lib = CompiledLib::compile(code.clone(), &[]).unwrap().into_lib();
        let lib = Lib::assemble(&code).unwrap();
        assert_eq!(lib.disassemble::<Instr<_>>().unwrap(), code);

        let state = StateValue::Single { first: fe256::from(VALUE) };
        let context = VmContext {
            witness: StateValue::None,
            destructible_input: &[(strict_dumb!(), StateCell {
                data: state,
                auth: strict_dumb!(),
                lock: None,
            })],
            immutable_input: &[state],
            destructible_output: &[StateCell { data: state, auth: strict_dumb!(), lock: None }],
            immutable_output: &[StateData { value: state, raw: None }],
        };
        let mut vm_main =
            Vm::<Instr<LibId>>::with(CoreConfig { halt: true, complexity_lim: None }, GfaConfig {
                field_order: FIELD_ORDER_SECP,
            });
        let resolver = |_: LibId| Some(&lib);
        let status = vm_main.exec(LibSite::new(lib.lib_id(), 0), &context, resolver);
        assert_eq!(status, Status::Ok);
    }
}
