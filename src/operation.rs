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

use core::cmp::Ordering;

#[cfg(feature = "baid64")]
pub use _baid64::ParseAddrError;
use aluvm::fe256;
use amplify::confinement::SmallVec;
use amplify::{ByteArray, Bytes32};
use commit_verify::{
    CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, MerkleHash, ReservedBytes,
    Sha256,
};

use crate::{CallId, CodexId, ContractId, StateCell, StateData, StateValue, LIB_NAME_ULTRASONIC};

/// Unique operation (genesis, extensions & state transition) identifier
/// equivalent to the commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(AsSlice, Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(
    all(feature = "serde", not(feature = "baid64")),
    derive(Serialize, Deserialize),
    serde(transparent)
)]
pub struct Opid(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Opid> for [u8; 32] {
    fn from(opid: Opid) -> Self { opid.to_byte_array() }
}

impl From<Sha256> for Opid {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for Opid {
    const TAG: &'static str = "urn:ubideco:ultrasonic:operation#2024-11-14";
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
pub struct GenesisId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<GenesisId> for [u8; 32] {
    fn from(id: GenesisId) -> Self { id.to_byte_array() }
}

impl From<Sha256> for GenesisId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for GenesisId {
    const TAG: &'static str = "urn:ubideco:ultrasonic:genesis#2024-11-14";
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(all(feature = "serde", not(feature = "baid64")), derive(Serialize, Deserialize))]
pub struct CellAddr {
    pub opid: Opid,
    pub pos: u16,
}

impl CellAddr {
    pub fn new(opid: Opid, pos: u16) -> Self { Self { opid, pos } }
}

impl From<[u8; 34]> for CellAddr {
    fn from(value: [u8; 34]) -> Self {
        let opid = Opid::from_slice_unsafe(&value[..32]);
        let pos = u16::from_le_bytes(value[32..34].try_into().unwrap());
        Self::new(opid, pos)
    }
}

impl From<CellAddr> for [u8; 34] {
    fn from(value: CellAddr) -> Self {
        let mut bytes = [0u8; 34];
        bytes[..32].copy_from_slice(&value.opid.to_byte_array());
        bytes[32..34].copy_from_slice(&value.pos.to_le_bytes());
        bytes
    }
}

#[cfg(feature = "baid64")]
mod _baid64 {
    use core::fmt::{self, Display, Formatter};
    use core::num::ParseIntError;
    use core::str::FromStr;

    use amplify::FromSliceError;
    use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};

    use super::*;

    impl Display for CellAddr {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}", self.opid, self.pos)
        }
    }

    impl DisplayBaid64 for Opid {
        const HRI: &'static str = "usop";
        const CHUNKING: bool = false;
        const PREFIX: bool = false;
        const EMBED_CHECKSUM: bool = false;
        const MNEMONIC: bool = false;
        fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
    }
    impl FromBaid64Str for Opid {}
    impl FromStr for Opid {
        type Err = Baid64ParseError;
        fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
    }
    impl Display for Opid {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
    }

    impl Opid {
        pub fn copy_from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
            Bytes32::copy_from_slice(slice).map(Self)
        }
    }

    #[derive(Debug, Display, From, Error)]
    #[display(doc_comments)]
    pub enum ParseAddrError {
        /// malformed string representation of cell address '{0}' lacking separator ':'
        MalformedSeparator(String),

        /// malformed output number. Details: {0}
        #[from]
        InvalidOut(ParseIntError),

        /// malformed operation id value. Details: {0}
        #[from]
        InvalidOpid(Baid64ParseError),
    }

    impl FromStr for CellAddr {
        type Err = ParseAddrError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let (opid, pos) = s
                .split_once(":")
                .ok_or_else(|| ParseAddrError::MalformedSeparator(s.to_owned()))?;
            let opid = Opid::from_str(opid)?;
            let pos = u16::from_str(pos)?;
            Ok(CellAddr::new(opid, pos))
        }
    }
}

#[cfg(all(feature = "serde", feature = "baid64"))]
mod _serde {
    use core::str::FromStr;

    use amplify::ByteArray;
    use serde::de::Error;
    use serde::ser::SerializeTuple;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    // TODO: Use Base64 macro
    impl Serialize for Opid {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                self.to_byte_array().serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Opid {
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

    impl Serialize for CellAddr {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                let mut ser = serializer.serialize_tuple(1)?;
                ser.serialize_element(&self.opid)?;
                ser.serialize_element(&self.pos)?;
                ser.end()
            }
        }
    }

    impl<'de> Deserialize<'de> for CellAddr {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                CellAddr::from_str(&s).map_err(D::Error::custom)
            } else {
                <(Opid, u16)>::deserialize(deserializer).map(|(opid, pos)| CellAddr::new(opid, pos))
            }
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Input {
    pub addr: CellAddr,
    pub witness: StateValue,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Genesis {
    pub codex_id: CodexId,
    pub call_id: CallId,
    pub nonce: fe256,

    // We need blanks in order to have Genesis serialized the same way as operaiton
    #[cfg_attr(feature = "serde", serde(skip))]
    pub blank1: ReservedBytes<2>,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub blank2: ReservedBytes<2>,

    /// Memory cells which were created (read-once, access-controlled).
    pub destructible: SmallVec<StateCell>,
    /// Immutable memory data which were created (write-once, readable by all).
    pub immutable: SmallVec<StateData>,
    pub reserved: ReservedBytes<8>,
}

impl CommitEncode for Genesis {
    type CommitmentId = GenesisId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.codex_id);
        e.commit_to_serialized(&self.call_id);
        e.commit_to_serialized(&self.nonce);
        e.commit_to_merkle(&SmallVec::<Input>::default());
        e.commit_to_merkle(&SmallVec::<CellAddr>::default());
        e.commit_to_merkle(&self.destructible);
        e.commit_to_merkle(&self.immutable);
        e.commit_to_serialized(&self.reserved);
    }
}

impl Genesis {
    pub fn to_operation(&self, contract_id: ContractId) -> Operation {
        Operation {
            contract_id,
            call_id: self.call_id,
            nonce: self.nonce,
            destroying: none!(),
            reading: none!(),
            destructible: self.destructible.clone(),
            immutable: self.immutable.clone(),
            reserved: self.reserved,
        }
    }
}

impl Genesis {
    pub fn opid(&self, contract_id: ContractId) -> Opid { self.to_operation(contract_id).opid() }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Operation {
    pub contract_id: ContractId,
    pub call_id: CallId,
    pub nonce: fe256,
    /// Memory cells which were destroyed.
    pub destroying: SmallVec<Input>,
    pub reading: SmallVec<CellAddr>,
    /// Memory cells which were created (read-once, access-controlled).
    pub destructible: SmallVec<StateCell>,
    /// Immutable memory data which were created (write-once, readable by all).
    pub immutable: SmallVec<StateData>,
    pub reserved: ReservedBytes<8>,
}

impl PartialOrd for Operation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for Operation {
    fn cmp(&self, other: &Self) -> Ordering { self.opid().cmp(&other.opid()) }
}

impl CommitEncode for Operation {
    type CommitmentId = Opid;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.contract_id);
        e.commit_to_serialized(&self.call_id);
        e.commit_to_serialized(&self.nonce);
        e.commit_to_merkle(&self.destroying);
        e.commit_to_merkle(&self.reading);
        e.commit_to_merkle(&self.destructible);
        e.commit_to_merkle(&self.immutable);
        e.commit_to_serialized(&self.reserved);
    }
}

impl Operation {
    pub fn opid(&self) -> Opid { self.commit_id() }
}

#[derive(Clone, Eq, Debug)]
pub struct VerifiedOperation(Opid, Operation);

impl PartialEq for VerifiedOperation {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}
impl PartialOrd for VerifiedOperation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for VerifiedOperation {
    fn cmp(&self, other: &Self) -> Ordering { self.0.cmp(&other.0) }
}

impl VerifiedOperation {
    #[doc(hidden)]
    pub(crate) fn new_unchecked(opid: Opid, operation: Operation) -> Self { Self(opid, operation) }

    pub fn opid(&self) -> Opid { self.0 }
    pub fn as_operation(&self) -> &Operation { &self.1 }
    pub fn into_operation(self) -> Operation { self.1 }
}
