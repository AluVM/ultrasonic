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

use std::fs;
use std::io::Write;

use commit_verify::stl::commit_verify_stl;
use commit_verify::CommitmentLayout;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::parse_args;
use strict_types::SystemBuilder;
use ultrasonic::stl::{aluvm_stl, finite_field_stl, usonic_stl};
use ultrasonic::ContractPrivate;

fn main() {
    let (format, dir) = parse_args();

    let rgb_commit = usonic_stl();

    rgb_commit
        .serialize(
            format,
            dir.as_ref(),
            "0.12.0",
            Some(
                "
  Description: UltraSONIC Contract
  Author: Dr Maxim Orlovsky <orlovsky@ubideco.org>
  Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
  Copyright (C) 2024-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
                          Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
  Copyright (C) 2019-2025 Dr Maxim Orlovsky.
  All rights under the above copyrights are reserved.
  License: Apache-2.0
",
            ),
        )
        .expect("unable to write to the file");

    let std = std_stl();
    let cv = commit_verify_stl();
    let st = strict_types_stl();
    let vm = aluvm_stl();
    let ff = finite_field_stl();
    let us = usonic_stl();

    let sys = SystemBuilder::new()
        .import(rgb_commit)
        .unwrap()
        .import(vm)
        .unwrap()
        .import(us)
        .unwrap()
        .import(ff)
        .unwrap()
        .import(cv)
        .unwrap()
        .import(st)
        .unwrap()
        .import(std)
        .unwrap()
        .finalize()
        .expect("not all libraries present");

    let dir = dir.unwrap_or_else(|| ".".to_owned());

    let mut file = fs::File::create(format!("{dir}/Contract.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: UltraSONIC Contract
  Author: Dr Maxim Orlovsky <orlovsky@ubideco.org>
  Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
  Copyright (C) 2024-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
                          Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
  Copyright (C) 2019-2025 Dr Maxim Orlovsky.
  All rights under the above copyrights are reserved.
  License: Apache-2.0
-}}

vesper Contract: types, commitments
"
    )
    .unwrap();
    let layout = ContractPrivate::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("UltraSONIC.ContractPrivate").unwrap();
    writeln!(file, "{tt}").unwrap();
}
