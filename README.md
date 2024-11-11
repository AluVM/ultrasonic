# UltraSONIC: Transactional execution layer with capability-based memory access for zk-AluVM

![Build](https://github.com/AluVM/ultrasonic/workflows/Build/badge.svg)
![Tests](https://github.com/AluVM/ultrasonic/workflows/Tests/badge.svg)
[![codecov](https://codecov.io/gh/AluVM/ultrasonic/branch/master/graph/badge.svg)](https://codecov.io/gh/AluVM/ultrasonic)

[![crates.io](https://img.shields.io/crates/v/ultrasonic)](https://crates.io/crates/ultrasonic)
[![Docs](https://docs.rs/ultrasonic/badge.svg)](https://docs.rs/ultrasonic)
[![License](https://img.shields.io/crates/l/ultrasonic)](./LICENSE)

## What is it

**UltraSONIC** is a state machine with capability-based memory access. In simple words, this means
<q>state machine with cryptographically-protected memory cells</q>.

What is capability-based memory access (or capability-addressable memory, **CAM**)? The computers we
all used to are random memory access machines (RAM), where a software accesses freely-addressable
global memory. This had opened a door for the all the vulnerabilities and hacks happening in
computer systems across the world for the past decades... CAM model instead, divides all memory into
parts (called *words*) addressable only with some access token (called *capability*). You may think
of this as of a memory where each part is "owned" by certain party, and can be accessed or modified
only given a proof of ownership (that is what single-use seals are for).

**UltraSONIC** leverages zk-AluVM, so it is (1) zk-STARK-compatible and (2) exception-less, made
with category theory in mind.

## Ecosystem

SONARE is a part of a larger ecosystem used to build safe distributed software, which includes:
- [Strict types]: strong type system made with [generalized algebraic data types][GADT] (*GADT*) and
  [dependent types];
- [AluVM]: a functional register-based virtual machine with a reduced instruction set (RISC);
  UltraSONIC uses a zk-STARK-compatible subset of its instruction set architecture (called zk-AluVM);
- [SONARE]: runtime environment for UltraSONIC software;
- [Cation]: a general-purpose high-level programming language made with category theory, which
  features strict types, termination analysis and can be formally verified;
- [Contractum]: a domain-specific version of Cation for writing programs for UltraSONIC.

## License

    Designed in 2019-2024 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
    Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
    
    Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
    Copyright (C) 2024-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
                            Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
    Copyright (C) 2019-2025 Dr Maxim Orlovsky.
    All rights under the above copyrights are reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software distributed under the License
is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied. See the License for the specific language governing permissions and limitations under
the License.

[Strict types]: https://strict-types.org
[AluVM]: https://aluvm.org
[SONARE]: https://github.com/AluVM/SONARE
[Cation]: https://cation-lang.org
[Contractum]: https://contractum.org

[GADT]: https://en.wikipedia.org/wiki/Generalized_algebraic_data_type
[dependent types]: https://en.wikipedia.org/wiki/Dependent_type
