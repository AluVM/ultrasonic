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

//! Ultrasonic strict types library.

pub use aluvm::alu::stl::aluvm_stl;
pub use aluvm::zkstl::{finite_field_stl, LIB_ID_FINITE_FIELD};
use commit_verify::stl::commit_verify_stl;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::LibBuilder;
use strict_types::{CompileError, TypeLib};

use crate::{ContractId, Issue, Operation, Opid, LIB_NAME_ULTRASONIC};

/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_ULTRASONIC: &str =
    "stl:Gv1vKbrx-JdB52Tc-bJ8vebC-Ol_tGiv-1Je5TSn-1dDGDH4#stuart-memphis-english";

#[allow(clippy::result_large_err)]
fn _usonic_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(libname!(LIB_NAME_ULTRASONIC), [
        std_stl().to_dependency_types(),
        strict_types_stl().to_dependency_types(),
        commit_verify_stl().to_dependency_types(),
        aluvm_stl().to_dependency_types(),
        finite_field_stl().to_dependency_types(),
    ])
    .transpile::<Opid>()
    .transpile::<Operation>()
    .transpile::<ContractId>()
    .transpile::<Issue>()
    .compile()
}

/// Generates a strict type library providing data types for RGB consensus.
pub fn usonic_stl() -> TypeLib { _usonic_stl().expect("invalid strict type Ultrasonic library") }

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use super::*;

    #[test]
    fn lib_id() {
        let lib = usonic_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_ULTRASONIC);
    }
}
