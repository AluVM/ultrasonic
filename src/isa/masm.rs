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
/// use ultrasonic::{uasm, Instr, VmContext};
/// use zkaluvm::alu::regs::Status;
/// use zkaluvm::alu::{Lib, LibId, LibSite, Vm};
///
/// let code = uasm! {
///     nop                 ;
///     chk                 ;
///     test    E1          ;
///     nxti    :readonce   ;
///     not     CO          ;
///     jif     CO, +2      ;
///     put     CK, :fail   ;
///     chk                 ;
///     ldi     EA,:readonce;
///     clr     EA          ;
///     mov     E2, 0       ;
///     mov     EB, 20      ;
///     mov     E1, E2      ;
///     eq      E1, E2      ;
///     neg     EA, EH      ;
///     add     EA, EH      ;
///     mul     EA, EH      ;
/// };
///
/// let lib = Lib::assemble::<Instr<LibId>>(&code).unwrap();
/// let mut vm = Vm::<Instr<LibId>>::new();
/// let ctx = VmContext {
///     read_once_input: &[],
///     immutable_input: &[],
///     read_once_output: &[],
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
    (nxti :readonce) => {
        $crate::UsonicInstr::NxIRo.into()
    };
    (nxti :immutable) => {
        $crate::UsonicInstr::NxIIm.into()
    };
    (nxto :readonce) => {
        $crate::UsonicInstr::NxORo.into()
    };
    (nxto :immutable) => {
        $crate::UsonicInstr::NxOIm.into()
    };

    (ldi EA, :readonce) => {
        $crate::UsonicInstr::LdIRo.into()
    };
    (ldi EB, :immutable) => {
        $crate::UsonicInstr::LdIIm.into()
    };
    (ldo EC, :readonce) => {
        $crate::UsonicInstr::LdORo.into()
    };
    (ldo ED, :immutable) => {
        $crate::UsonicInstr::LdOIm.into()
    };

    { $($tt:tt)+ } => {
        $crate::aluvm::instr! { $( $tt )+ }
    };
}
