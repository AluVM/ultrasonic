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

use aluvm::alu::CoreExt;
use aluvm::RegE;

use crate::{IoCat, UsonicCore, VmContext};

impl UsonicCore {
    /// Checks that there is more state values remain in the given category.
    pub fn has_data(&mut self, cat: IoCat, context: &VmContext) -> bool {
        let data = context.state_value(cat, self.ui[cat.index()]);
        data.is_some()
    }

    /// Loads next [`StateValue`] (basing on iterator position from `UI` indexes) of a given
    /// category into the `EA`-`ED` registers, increasing `UI` iterator count.
    pub fn load(&mut self, cat: IoCat, context: &VmContext) -> bool {
        let data = context.state_value(cat, self.ui[cat.index()]);
        let co = data.is_some();
        let data = data.unwrap_or_default();
        self.gfa.put(RegE::EA, data.get(0));
        self.gfa.put(RegE::EB, data.get(1));
        self.gfa.put(RegE::EC, data.get(2));
        self.gfa.put(RegE::ED, data.get(3));
        if co {
            self.ui[cat.index()] += 1;
        }
        co
    }
}
