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

/// Macro compiler for AluVM assembler.
///
/// # Example
///
/// ```
/// ##![cfg_attr(coverage_nightly, feature(coverage_attribute), coverage(off))]
/// use ultrasonic::{uasm, Instr, StateValue, VmContext};
/// use zkaluvm::alu::regs::Status;
/// use zkaluvm::alu::{Lib, LibId, LibSite, Vm};
///
/// let code = uasm! {
///     nop;
///     chk     CK;
///     test    E1;
///     cknxi   destructible;
///     not     CO;
///     jif     CO, +2;
///     mov     CO, CK;
///     chk     CO;
///     ldi     immutable;
///     clr     EA;
///     put     E2, 0;
///     put     EB, 20;
///     mov     E1, E2;
///     eq      E1, E2;
///     neg     EA, EH;
///     add     EA, EH;
///     mul     EA, EH;
/// };
///
/// let lib = Lib::assemble::<Instr<LibId>>(&code).unwrap();
/// let mut vm = Vm::<Instr<LibId>>::new();
/// let ctx = VmContext {
///     witness: StateValue::None,
///     destructible_input: &[],
///     immutable_input: &[],
///     destructible_output: &[],
///     immutable_output: &[],
/// };
/// match vm.exec(LibSite::new(lib.lib_id(), 0), &ctx, |_| Some(&lib)) {
///     Status::Ok => println!("success"),
///     Status::Fail => println!("failure"),
/// }
/// ```
#[macro_export]
macro_rules! uasm {
    ($( $tt:tt )+) => {{
        use $crate::instr;
        #[cfg(not(feature = "std"))]
        use alloc::vec::Vec;

        let mut code: Vec<$crate::Instr<$crate::aluvm::alu::LibId>> = Default::default();
        #[allow(unreachable_code)] {
            $crate::aluvm::alu::aluasm_inner! { code => $( $tt )+ }
        }
        code
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! instr {
    (cknxi destructible) => {
        $crate::UsonicInstr::CkNxIRo.into()
    };
    (cknxi immutable) => {
        $crate::UsonicInstr::CkNxIAo.into()
    };
    (cknxo destructible) => {
        $crate::UsonicInstr::CkNxORo.into()
    };
    (cknxo immutable) => {
        $crate::UsonicInstr::CkNxOAo.into()
    };

    (ldw) => {
        $crate::UsonicInstr::LdW.into()
    };
    (ldi witness) => {
        $crate::UsonicInstr::LdIW.into()
    };
    (ldi lock) => {
        $crate::UsonicInstr::LdIL.into()
    };
    (ldi auth) => {
        $crate::UsonicInstr::LdIT.into()
    };

    (ldi destructible) => {
        $crate::UsonicInstr::LdIRo.into()
    };
    (ldi immutable) => {
        $crate::UsonicInstr::LdIAo.into()
    };
    (ldo destructible) => {
        $crate::UsonicInstr::LdORo.into()
    };
    (ldo immutable) => {
        $crate::UsonicInstr::LdOAo.into()
    };

    (rsti destructible) => {
        $crate::UsonicInstr::RstIRo.into()
    };
    (rsti immutable) => {
        $crate::UsonicInstr::RstIAo.into()
    };
    (rsto destructible) => {
        $crate::UsonicInstr::RstORo.into()
    };
    (rsto immutable) => {
        $crate::UsonicInstr::RstOAo.into()
    };

    { $($tt:tt)+ } => {
        $crate::aluvm::instr! { $( $tt )+ }
    };
}
