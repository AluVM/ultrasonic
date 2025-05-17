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

#![cfg_attr(coverage_nightly, feature(coverage_attribute), coverage(off))]

use std::fs;
use std::io::Write;

use commit_verify::stl::commit_verify_stl;
use commit_verify::CommitmentLayout;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::{parse_args, SystemBuilder};
use ultrasonic::stl::usonic_stl;
use ultrasonic::{Codex, Issue, Operation};
use zkaluvm::alu::stl::aluvm_stl;
use zkaluvm::zkstl::finite_field_stl;

fn main() {
    let (format, dir) = parse_args();

    let lib = usonic_stl();
    lib.serialize(
        format,
        dir.as_ref(),
        "0.12.0",
        Some(
            "
  Description: Transactional execution layer with capability-based memory access for zk-AluVM
  Author: Dr Maxim Orlovsky <orlovsky@ubideco.org>
  Copyright (C) 2024-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
                          Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
                          All rights reserved.
  License: Apache-2.0",
        ),
    )
    .expect("unable to write to the file");

    let std = std_stl();
    let ff = finite_field_stl();
    let st = strict_types_stl();
    let cv = commit_verify_stl();
    let alu = aluvm_stl();

    let dir = dir.unwrap_or_else(|| ".".to_owned());
    let sys = SystemBuilder::new()
        .import(std)
        .unwrap()
        .import(st)
        .unwrap()
        .import(ff)
        .unwrap()
        .import(cv)
        .unwrap()
        .import(alu)
        .unwrap()
        .import(lib)
        .unwrap()
        .finalize()
        .expect("Not all libraries present");

    let mut file = fs::File::create(format!("{dir}/UltraSONIC.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: Transactional execution layer with capability-based memory access for zk-AluVM
  Author: Dr Maxim Orlovsky <orlovsky@ubideco.org>
  Copyright (C) 2024-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
                          Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
                          All rights reserved.
  License: Apache-2.0
-}}

@@lexicon(types+commitments)
"
    )
    .unwrap();

    writeln!(file, "\n-- Contract Codex\n").unwrap();
    let layout = Codex::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("UltraSONIC.Codex").unwrap();
    writeln!(file, "{tt}").unwrap();

    writeln!(file, "\n-- Contract Issue\n").unwrap();
    let layout = Issue::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("UltraSONIC.Issue").unwrap();
    writeln!(file, "{tt}").unwrap();

    writeln!(file, "\n-- Contract Genesis\n").unwrap();
    let layout = Operation::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("UltraSONIC.Genesis").unwrap();
    writeln!(file, "{tt}").unwrap();

    writeln!(file, "\n-- Contract Operation\n").unwrap();
    let layout = Operation::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("UltraSONIC.Operation").unwrap();
    writeln!(file, "{tt}").unwrap();
}
