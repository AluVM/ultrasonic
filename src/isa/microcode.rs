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
use aluvm::{fe256, RegE};

use crate::{AuthToken, IoCat, StateValue, UsonicCore, VmContext};

impl UsonicCore {
    /// Checks are there more state values remain in the given category.
    pub fn has_data(&mut self, cat: IoCat, context: &VmContext) -> bool {
        let data = context.state_value(cat, self.ui[cat.index()]);
        data.is_some()
    }

    /// Get the current index for a destructible input.
    pub fn get_ui_inro(&self) -> u16 { self.ui[IoCat::IN_RO.index()] }

    /// Loads next [`StateValue`] (basing on iterator position from `UI` indexes) of a given
    /// category into the `EA`-`ED` registers, increasing `UI` iterator count.
    pub fn load(&mut self, cat: IoCat, context: &VmContext) -> bool {
        let data = context.state_value(cat, self.ui[cat.index()]);
        self.load_internal(cat, data)
    }

    fn load_internal(&mut self, cat: IoCat, data: Option<StateValue>) -> bool {
        let co = data.is_some();
        let data = data.unwrap_or_default();
        self.set_ea_ed(data);
        if co {
            self.ui[cat.index()] += 1;
        }
        co
    }

    /// Sets `EA` and `EB` registers to the field elements representing the given pair of values.
    pub fn set_ed_eb(&mut self, data: Option<(AuthToken, bool)>) -> bool {
        let co = data.is_some();
        self.gfa.put(RegE::EA, data.map(|(at, _)| at.to_fe256()));
        self.gfa
            .put(RegE::EB, data.map(|(_, s)| if s { fe256::from(1u8) } else { fe256::ZERO }));
        co
    }

    /// Sets `EA`-`ED` registers to the field elements representing the given value.
    pub fn set_ea_ed_opt(&mut self, data: Option<StateValue>) -> bool {
        let co = data.is_some();
        self.set_ea_ed(data.unwrap_or_default());
        co
    }

    /// Sets `EA`-`ED` registers to the field elements representing the given value.
    pub fn set_ea_ed(&mut self, data: StateValue) {
        self.gfa.put(RegE::EA, data.get(0));
        self.gfa.put(RegE::EB, data.get(1));
        self.gfa.put(RegE::EC, data.get(2));
        self.gfa.put(RegE::ED, data.get(3));
    }

    /// Sets `UI` register for the destructible input to point at a specific input index.
    pub fn set_inro_index(&mut self, index: u16) { self.ui[IoCat::IN_RO.index()] = index; }

    /// Reset a value (set to zero) of the `UI` register.
    pub fn reset(&mut self, cat: IoCat) { self.ui[cat.index()] = 0; }
}
