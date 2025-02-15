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

use aluvm::alu::{CoreExt, ExecStep, Site, SiteId};
use aluvm::RegE;
use amplify::num::u4;

use crate::{UsonicCore, VmContext};

impl UsonicCore {
    pub fn next<Id: SiteId>(
        &mut self,
        jmp: Site<Id>,
        reg: usize,
        context: &VmContext,
    ) -> ExecStep<Site<Id>> {
        if !context.read_once_input.len() <= self.ui[reg] as usize {
            return ExecStep::Next;
        };
        self.ui[reg] += 1;
        self.ue[reg] = 0;
        ExecStep::Call(jmp)
    }

    pub fn load<Id: SiteId>(&mut self, reg: usize, context: &VmContext) -> ExecStep<Site<Id>> {
        let Some(data) = context.read_once_input.get(self.ui[reg] as usize) else {
            return ExecStep::FailHalt;
        };
        let e = RegE::from(u4::with(4 + reg as u8));
        if let Some(el) = data.get(self.ue[reg]) {
            self.gfa.set(e, el);
            self.ue[reg] += 1;
        } else {
            self.gfa.clr(e);
        }
        ExecStep::Next
    }
}
