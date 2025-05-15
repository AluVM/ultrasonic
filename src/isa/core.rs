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

use aluvm::alu::{CoreExt, NoExt, Register, Supercore};
use aluvm::{GfaConfig, GfaCore, RegE};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
enum Io {
    #[display(":in")]
    Input,
    #[display(":out")]
    Output,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
enum Mem {
    #[display(":readonce")]
    ReadOnce,
    #[display(":immutable")]
    AppendOnly,
}

/// Category of operation input or output data.
///
/// See constants for the way to construct specific values.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct IoCat {
    io: Io,
    mem: Mem,
}

impl IoCat {
    /// Operation input pointing to a destructible (read-once) memory cell.
    pub const IN_RO: Self = Self { io: Io::Input, mem: Mem::ReadOnce };
    /// Operation input pointing to an immutable (append-only) memory cell.
    pub const IN_AO: Self = Self { io: Io::Input, mem: Mem::AppendOnly };
    /// Operation output defining a destructible (read-once) memory cell.
    pub const OUT_RO: Self = Self { io: Io::Output, mem: Mem::ReadOnce };
    /// Operation output defining an immutable (append-only) memory cell.
    pub const OUT_AO: Self = Self { io: Io::Output, mem: Mem::AppendOnly };

    pub(crate) const fn index(&self) -> usize {
        match (self.io, self.mem) {
            (Io::Input, Mem::ReadOnce) => 0,
            (Io::Input, Mem::AppendOnly) => 1,
            (Io::Output, Mem::ReadOnce) => 2,
            (Io::Output, Mem::AppendOnly) => 3,
        }
    }
}

/// ALU Core extension for USONIC ISA.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct UsonicCore {
    /// State value iterator positions
    pub(super) ui: [u16; 4],

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
        write!(f, "{reg}UI1{reset} {val}{}{reset}  ", self.ui[IoCat::IN_RO.index()])?;
        write!(f, "{reg}UI2{reset} {val}{}{reset}  ", self.ui[IoCat::IN_AO.index()])?;
        write!(f, "{reg}UI3{reset} {val}{}{reset}  ", self.ui[IoCat::OUT_RO.index()])?;
        writeln!(f, "{reg}UI4{reset} {val}{}{reset}  ", self.ui[IoCat::OUT_AO.index()])?;
        writeln!(f)
    }
}

impl CoreExt for UsonicCore {
    type Reg = RegE;
    type Config = GfaConfig;

    fn with(config: Self::Config) -> Self { UsonicCore { ui: [0; 4], gfa: GfaCore::with(config) } }

    fn get(&self, reg: Self::Reg) -> Option<<Self::Reg as Register>::Value> { self.gfa.get(reg) }

    fn clr(&mut self, reg: Self::Reg) { self.gfa.clr(reg) }

    fn put(&mut self, reg: Self::Reg, val: Option<<Self::Reg as Register>::Value>) {
        self.gfa.put(reg, val)
    }

    fn reset(&mut self) {
        self.gfa.reset();
        self.ui = [0; 4];
    }
}

impl Supercore<GfaCore> for UsonicCore {
    fn subcore(&self) -> GfaCore { self.gfa }

    fn merge_subcore(&mut self, subcore: GfaCore) { self.gfa = subcore; }
}

impl Supercore<NoExt> for UsonicCore {
    fn subcore(&self) -> NoExt { NoExt }

    fn merge_subcore(&mut self, _subcore: NoExt) {}
}
