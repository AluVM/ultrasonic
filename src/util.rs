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

use commit_verify::StrictHash;
use strict_encoding::stl::AsciiPrintable;
use strict_encoding::RString;

use crate::LIB_NAME_ULTRASONIC;

/// An ASCII printable string up to 4096 chars representing identity of a developer.
///
/// We deliberately do not define the internal structure of the identity such that it can be updated
/// without changes to the consensus level.
///
/// Contract or schema validity doesn't assume any checks on the identity; these checks must be
/// performed at the application level.
#[derive(Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From, Display)]
#[wrapper(Deref, FromStr)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Identity(RString<AsciiPrintable, AsciiPrintable, 1, 4096>);

impl Default for Identity {
    fn default() -> Self { Self::from("ssi:anonymous") }
}

impl From<&'static str> for Identity {
    fn from(s: &'static str) -> Self { Self(RString::from(s)) }
}

impl Identity {
    pub fn is_empty(&self) -> bool { self.is_anonymous() }
    pub fn is_anonymous(&self) -> bool { self == &default!() }
}
