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

use aluvm::regs::Status;
use aluvm::{fe256, CoreConfig, CoreExt, Lib, LibId, LibSite, RegE, Vm};
use amplify::confinement::{SmallVec, TinyOrdMap, TinyString};
use amplify::num::u256;
use amplify::Bytes32;
use commit_verify::{CommitId, CommitmentId, DigestExt, ReservedBytes, Sha256};

use crate::{
    CellAddr, ContractId, Identity, Instr, Operation, StateCell, StateData, StateValue,
    LIB_NAME_ULTRASONIC,
};

pub type CallId = u16;
pub type AccessId = u16;

/// Codex is a crucial part of a contract; it provides a set of commitments to the contract terms
/// and conditions expressed as a deterministic program able to run in SONIC computer model.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = CodexId)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Codex {
    pub version: ReservedBytes<2>,
    pub name: TinyString,
    pub developer: Identity,
    pub timestamp: i64,
    pub field_order: u256,
    pub input_config: CoreConfig,
    pub verification_config: CoreConfig,
    pub verifiers: TinyOrdMap<CallId, LibSite>,
    /// Reserved for the future codex extensions
    pub reserved: ReservedBytes<8>,
}

impl Codex {
    pub fn codex_id(&self) -> CodexId { self.commit_id() }

    pub fn verify(
        &self,
        contract_id: ContractId,
        operation: &Operation,
        memory: &impl Memory,
        repo: &impl LibRepo,
    ) -> Result<(), CallError> {
        let resolver = |lib_id: LibId| repo.get_lib(lib_id);

        if operation.contract_id != contract_id {
            return Err(CallError::WrongContract {
                expected: contract_id,
                found: operation.contract_id,
            });
        }

        // Phase one: get inputs, verify access conditions
        let mut vm_inputs =
            Vm::<aluvm::gfa::Instr<LibId>>::with(self.input_config, self.field_order);
        let mut read_once_input = SmallVec::new();
        for input in &operation.destroying {
            let cell = memory
                .read_once(input.addr)
                .ok_or(CallError::NoReadOnceInput(input.addr))?;

            // Verify that the lock script conditions are satisfied
            if let Some(lock) = cell.lock {
                // Put also token of authority into a register
                vm_inputs.core.cx.set(RegE::E1, cell.auth.to_fe256());

                // Put witness into input registers
                for (no, reg) in [RegE::E2, RegE::E3, RegE::E4, RegE::E5]
                    .into_iter()
                    .enumerate()
                {
                    let Some(el) = input.witness.get(no as u8) else {
                        break;
                    };
                    vm_inputs.core.cx.set(reg, el);
                }
                if vm_inputs.exec(lock, &(), resolver) == Status::Fail {
                    // Read error code from output register
                    return Err(CallError::Lock(vm_inputs.core.cx.get(RegE::E8)));
                }
                vm_inputs.reset();
            }

            let _ = read_once_input.push(cell.data);
        }

        let mut immutable_input = SmallVec::new();
        for input in &operation.destroying {
            let data = memory
                .immutable(input.addr)
                .ok_or(CallError::NoImmutableInput(input.addr))?;
            let _ = immutable_input.push(data);
        }

        // Phase 2: Verify operation integrity
        let entry_point = self
            .verifiers
            .get(&operation.call_id)
            .ok_or(CallError::NotFound(operation.call_id))?;
        let context = VmContext {
            read_once_input: read_once_input.as_slice(),
            immutable_input: immutable_input.as_slice(),
            read_once_output: operation.destructible.as_slice(),
            immutable_output: operation.immutable.as_slice(),
        };
        let mut vm_main = Vm::<Instr<LibId>>::with(self.verification_config, self.field_order);
        match vm_main.exec(*entry_point, &context, resolver) {
            Status::Ok => Ok(()),
            Status::Fail => {
                if let Some(err_code) = vm_main.core.cx.get(RegE::E1) {
                    Err(CallError::Script(err_code))
                } else {
                    Err(CallError::ScriptUnspecified)
                }
            }
        }
    }
}

pub trait Memory {
    fn read_once(&self, addr: CellAddr) -> Option<StateCell>;
    fn immutable(&self, addr: CellAddr) -> Option<StateValue>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VmContext<'ctx> {
    pub read_once_input: &'ctx [StateValue],
    pub immutable_input: &'ctx [StateValue],
    pub read_once_output: &'ctx [StateCell],
    pub immutable_output: &'ctx [StateData],
}

pub trait LibRepo {
    fn get_lib(&self, lib_id: LibId) -> Option<&Lib>;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum CallError {
    #[cfg_attr(
        feature = "baid64",
        display = "operation doesn't belong to the current contract {expected} (operation \
                   contract is {found})."
    )]
    #[cfg_attr(
        not(feature = "baid64"),
        display = "operation doesn't belong to the current contract."
    )]
    WrongContract {
        expected: ContractId,
        found: ContractId,
    },

    /// operation verifier {0} is not present in the codex.
    NotFound(CallId),

    #[cfg_attr(
        feature = "baid64",
        display = "operation references read-once memory cell {0} which was not defined."
    )]
    #[cfg_attr(
        not(feature = "baid64"),
        display = "operation references read-once memory cell {0:?} which was not defined."
    )]
    NoReadOnceInput(CellAddr),

    #[cfg_attr(
        feature = "baid64",
        display = "operation references immutable memory cell {0} which was not defined."
    )]
    #[cfg_attr(
        not(feature = "baid64"),
        display = "operation references immutable memory cell {0:?} which was not defined."
    )]

    /// operation references immutable memory cell {0} which was not defined.
    NoImmutableInput(CellAddr),

    /// operation input locking conditions are unsatisfied.
    Lock(Option<fe256>),

    /// verification failure {0}
    Script(fe256),

    /// verification failure (details are unspecified).
    ScriptUnspecified,
}

/// Unique codex identifier - a commitment to all codex data
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(
    all(feature = "serde", not(feature = "baid64")),
    derive(Serialize, Deserialize),
    serde(transparent)
)]
pub struct CodexId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for CodexId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for CodexId {
    const TAG: &'static str = "urn:ubideco:sonic:codex#2024-11-19";
}

#[cfg(feature = "baid64")]
mod _baid4 {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};

    use super::*;

    impl DisplayBaid64 for CodexId {
        const HRI: &'static str = "codex";
        const CHUNKING: bool = true;
        const PREFIX: bool = false;
        const EMBED_CHECKSUM: bool = false;
        const MNEMONIC: bool = true;
        fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
    }
    impl FromBaid64Str for CodexId {}
    impl FromStr for CodexId {
        type Err = Baid64ParseError;
        fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
    }
    impl Display for CodexId {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
    }
}

// TODO: Use Base64 macro
#[cfg(all(feature = "serde", feature = "baid64"))]
mod _serde {
    use core::str::FromStr;

    use amplify::ByteArray;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for CodexId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                self.to_byte_array().serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for CodexId {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(D::Error::custom)
            } else {
                let bytes = <[u8; 32]>::deserialize(deserializer)?;
                Ok(Self::from_byte_array(bytes))
            }
        }
    }
}
