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

use core::fmt::{self, Debug, Formatter};

use aluvm::{CoreExt, GfaCore, NoExt, RegE, Register};
use amplify::num::u256;

pub const REG_IN_RO: usize = 0;
pub const REG_IN_IM: usize = 1;
pub const REG_OUT_RO: usize = 2;
pub const REG_OUT_IM: usize = 3;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct UsonicCore {
    /// Iterator counters
    pub(super) ui: [u16; 4],
    /// Field element offsets
    pub(super) ue: [u8; 4],

    pub(super) gfa: GfaCore,
}

impl Debug for UsonicCore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (sect, reg, val, reset) = if f.alternate() {
            ("\x1B[0;4;1m", "\x1B[0;1m", "\x1B[0;32m", "\x1B[0m")
        } else {
            ("", "", "", "")
        };

        writeln!(f)?;
        writeln!(f, "{sect}U-regs:{reset}")?;
        write!(f, "{reg}UI1{reset} {val}{}{reset}  ", self.ui[REG_IN_RO])?;
        write!(f, "{reg}UI2{reset} {val}{}{reset}  ", self.ui[REG_IN_IM])?;
        write!(f, "{reg}UI3{reset} {val}{}{reset}  ", self.ui[REG_OUT_RO])?;
        writeln!(f, "{reg}UI4{reset} {val}{}{reset}  ", self.ui[REG_OUT_IM])?;
        write!(f, "{reg}UE1{reset} {val}{}{reset}  ", self.ue[REG_IN_RO])?;
        write!(f, "{reg}UE2{reset} {val}{}{reset}  ", self.ue[REG_IN_IM])?;
        write!(f, "{reg}UE3{reset} {val}{}{reset}  ", self.ue[REG_OUT_RO])?;
        writeln!(f, "{reg}UE4{reset} {val}{}{reset}  ", self.ue[REG_OUT_IM])?;
        writeln!(f)
    }
}

impl CoreExt for UsonicCore {
    type Reg = RegE;
    type Config = u256;

    fn with(config: Self::Config) -> Self {
        UsonicCore { ui: [0; 4], ue: [0; 4], gfa: GfaCore::with(config) }
    }

    fn get(&self, reg: Self::Reg) -> Option<<Self::Reg as Register>::Value> { self.gfa.get(reg) }

    fn clr(&mut self, reg: Self::Reg) -> Option<<Self::Reg as Register>::Value> {
        self.gfa.clr(reg)
    }

    fn set(
        &mut self,
        reg: Self::Reg,
        val: <Self::Reg as Register>::Value,
    ) -> Option<<Self::Reg as Register>::Value> {
        self.gfa.set(reg, val)
    }

    fn reset(&mut self) {
        self.gfa.reset();
        self.ui = [0; 4];
        self.ue = [0; 4];
    }
}

impl From<UsonicCore> for GfaCore {
    fn from(core: UsonicCore) -> Self { core.gfa }
}

impl From<UsonicCore> for NoExt {
    fn from(_: UsonicCore) -> Self { NoExt }
}
