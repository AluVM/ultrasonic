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

use aluvm::alu::regs::Status;
use aluvm::alu::{CoreConfig, CoreExt, Lib, LibId, LibSite, Vm};
use aluvm::{fe256, GfaConfig, RegE};
use amplify::confinement::{SmallVec, TinyOrdMap, TinyString};
use amplify::num::u256;
use amplify::Bytes32;
use commit_verify::{CommitId, CommitmentId, DigestExt, ReservedBytes, Sha256};

use crate::{
    CellAddr, ContractId, Identity, Instr, Operation, StateCell, StateValue, VerifiedOperation,
    VmContext, LIB_NAME_ULTRASONIC,
};

/// Identifier of a contract method call.
pub type CallId = u16;

/// Codex is a crucial part of a contract; it provides a set of commitments to the contract terms
/// and conditions expressed as a deterministic program able to run in SONIC computer model.
///
/// The main (and the only) operation of the codex is verification of contract [`Operation`]s. It is
/// done in [`Self::verify`] method.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = CodexId)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Codex {
    /// Consensus version of the codex.
    ///
    /// # Future use
    ///
    /// For now, the only supported version is one; thus, a `ReservedBytes` is used.
    ///
    /// In the future, with more versions coming, this should be replaced with an enum, where the
    /// first byte will encode (with standard strict encoding) a version number as an enum variant.
    /// For instance,
    ///
    /// ```ignore
    /// pub enum Codex {
    ///     V0(CodexV0),
    ///     V1(CodexV1)
    /// }
    /// pub struct CodexV0 { /*...*/ }
    /// pub struct CodexV1 { /*...*/ }
    /// ```
    pub version: ReservedBytes<1>,
    /// Human-readable name of the codex used in the UI.
    pub name: TinyString,
    /// Identity of the codex developer.
    pub developer: Identity,
    /// Timestamp of the codex creation.
    ///
    /// This field can be also used to "mine" a vanity codex id. While this feature is noa
    /// necessary one, many people will try to do it, and it is better to provide them with a
    /// standard way of doing this, rather to force them into abusing and misusing other fields of
    /// the codex.
    pub timestamp: i64,
    /// The order of the field used by VM for all scripts (operation verification and state access
    /// condition satisfaction).
    pub field_order: u256,
    /// Input config is used by the VM to verify the satisfaction of the lock conditions for
    /// operation inputs.
    pub input_config: CoreConfig,
    /// VM core configuration for the operation verification.
    pub verification_config: CoreConfig,
    /// List of verifiers for each of the calls supported by the codex.
    pub verifiers: TinyOrdMap<CallId, LibSite>,
}

impl Codex {
    /// The codex id holds a commitment to all codex data.
    ///
    /// The codex is encoded using strict encoding into the hasher, which is provided by the
    /// `#[derive(CommitEncode)]` and `#[commit_encode(strategy = strict, id = CodexId)]` macros in
    /// the structure definition.
    ///
    /// It is the same as the result of the [`CommitId::commit_id`] procedure.
    pub fn codex_id(&self) -> CodexId { self.commit_id() }

    /// The main purpose of the codex is to verify the operation under the contract. This is the
    /// implementation of this verification procedure.
    ///
    /// # Arguments
    ///
    /// - `contract_id`: since the contract is external to the codex, this information must be
    ///   provided to the verifier. While operation also commits to the contract id, this id must
    ///   come not from the operation itself, but from the external knowledge of the contract id
    ///   which is being verified; such that operation commitment to the contract is also checked.
    /// - `operation`: the operation to verify.
    /// - `memory`: an object holding an actual contract state (see [`Memory`] trait) and provides a
    ///   read access to it.
    /// - `repo`: a repository holding VM libraries used in the operation verification, calls to
    ///   which are kept in the codex (see [`Codex::verifiers`]) _and_ may be called from by the
    ///   access conditions of the inputs. See [`LibRepo`] for the details.
    ///
    /// # Returns
    ///
    /// On success, returns a operation wrapped as [`VerifiedOperation`] structure, which should be
    /// used (1) for updating the contract state by applying the operation, and (2) for the
    /// persistence of the contract history.
    ///
    /// # Errors
    ///
    /// On any verification failure, the method does not proceed with further certification and
    /// instantly returns with one of [`CallError`] variants.
    ///
    /// # Panics
    ///
    /// Panics if the `repo` (library resolver) returns a library which id doesn't match the
    /// requested one.
    pub fn verify(
        &self,
        contract_id: ContractId,
        operation: Operation,
        memory: &impl Memory,
        repo: &impl LibRepo,
    ) -> Result<VerifiedOperation, CallError> {
        let resolver = |lib_id: LibId| {
            let lib = repo.get_lib(lib_id)?;
            // We must have this verification to avoid hacking from the client libraries.
            if lib.lib_id() != lib_id {
                panic!(
                    "The library returned by the `LibRepo` provided for the contract operation \
                     verification doesn't match the requested library id. This error indicates \
                     that the software using the consensus verification is invalid or compromised."
                )
            }
            Some(lib)
        };

        if operation.contract_id != contract_id {
            return Err(CallError::WrongContract {
                expected: contract_id,
                found: operation.contract_id,
            });
        }

        // Phase 1: get inputs, verify their presence in the memory and access conditions
        let mut vm_inputs = Vm::<aluvm::gfa::Instr<LibId>>::with(self.input_config, GfaConfig {
            field_order: self.field_order,
        });
        let mut read_once_input = SmallVec::new();
        for input in &operation.destroying {
            // Read memory
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

            // We have same-sized arrays, so we happily skip the result returned by the confined
            // collection.
            let _res = read_once_input.push(cell.data);
            debug_assert!(_res.is_ok());
        }

        // Check that all read values are present in the memory.
        let mut immutable_input = SmallVec::new();
        for addr in &operation.reading {
            let data = memory
                .immutable(*addr)
                .ok_or(CallError::NoImmutableInput(*addr))?;
            // We have same-sized arrays, so we happily skip the result returned by the confined
            // collection.
            let _res = immutable_input.push(data);
            debug_assert!(_res.is_ok());
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
        let mut vm_main = Vm::<Instr<LibId>>::with(self.verification_config, GfaConfig {
            field_order: self.field_order,
        });
        match vm_main.exec(*entry_point, &context, resolver) {
            Status::Ok => Ok(VerifiedOperation::new_unchecked(operation.opid(), operation)),
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

/// The trait, which must be implemented by a client library for a structure providing access to the
/// valid and most recent contract state, consisting of two parts: *read-once* (also called
/// *destructible*, or *owned*) and *immutable* (also called *read-only* or *global*).
pub trait Memory {
    /// Read a read-once state created by a specific operation read-once output, which is defined as
    /// a part of [`Operation::destructible`].
    fn read_once(&self, addr: CellAddr) -> Option<StateCell>;
    /// Read a read-once state created by a specific operation immutable output, which is defined as
    /// a part of [`Operation::immutable`].
    fn immutable(&self, addr: CellAddr) -> Option<StateValue>;
}

/// The trait providing access to all the VM code libraries used by the contract, in both operation
/// verification or state access conditions.
pub trait LibRepo {
    /// Get a specific library with the provided id.
    ///
    /// If the library is not known and this method returns `None`, but the library is called by the
    /// operation verification or state access script, the verification will fail with
    /// [`CallError::Script`].
    fn get_lib(&self, lib_id: LibId) -> Option<&Lib>;
}

/// Contract operation verification errors returned by [`Codex::verify`].
///
/// The name of the error type is chose so since the operation "calls" to a contract method, and the
/// codex verification verifies the integrity of the call.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum CallError {
    /// operation doesn't belong to the currecnt contract.
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

    /// operation references read-once memory cell which was not defined.
    #[cfg_attr(
        feature = "baid64",
        display = "operation references read-once memory cell {0} which was not defined."
    )]
    #[cfg_attr(
        not(feature = "baid64"),
        display = "operation references read-once memory cell {0:?} which was not defined."
    )]
    NoReadOnceInput(CellAddr),

    /// operation references immutable memory cell which was not defined.
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

    /// operation input access conditions are unsatisfied.
    Lock(Option<fe256>),

    /// verification script failure with status code {0}.
    Script(fe256),

    /// verification script failure (no status code is returned from the verification script).
    ScriptUnspecified,
}

/// Unique codex identifier - a commitment to all the [`Codex`] data.
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
    const TAG: &'static str = "urn:ubideco:sonic:codex#2025-05-15";
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

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use amplify::ByteArray;
    use commit_verify::Digest;

    use super::*;

    #[test]
    fn codex_id_display() {
        let id = CodexId::from_byte_array(Sha256::digest(b"test"));
        assert_eq!(
            format!("{id}"),
            "n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg#berlin-river-delta"
        );
        assert_eq!(
            format!("{id:-}"),
            "codex:n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg#berlin-river-delta"
        );
        assert_eq!(format!("{id:#}"), "n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg");
    }

    #[test]
    fn codex_id_from_str() {
        let id = CodexId::from_byte_array(Sha256::digest(b"test"));
        assert_eq!(
            CodexId::from_str(
                "n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg#berlin-river-delta"
            )
            .unwrap(),
            id
        );
        assert_eq!(
            CodexId::from_str(
                "codex:n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg#berlin-river-delta"
            )
            .unwrap(),
            id
        );
        assert_eq!(
            CodexId::from_str("codex:n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg").unwrap(),
            id
        );
        assert_eq!(
            CodexId::from_str("n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg").unwrap(),
            id
        );
    }
}
