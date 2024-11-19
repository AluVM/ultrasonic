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

use core::str::FromStr;

use amplify::confinement::SmallVec;
use amplify::hex::{FromHex, ToHex};
use amplify::{hex, Bytes32, FromSliceError};
use commit_verify::{
    CommitEncode, CommitEngine, CommitmentId, DigestExt, MerkleHash, ReservedBytes, Sha256,
};

use crate::{CallId, ContractId, StateCell, StateData, StateValue, LIB_NAME_ULTRASONIC};

/// Unique operation (genesis, extensions & state transition) identifier
/// equivalent to the commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_hex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Opid(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for Opid {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for Opid {
    const TAG: &'static str = "urn:ubideco:ultrasonic:operation#2024-11-14";
}

impl FromStr for Opid {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

impl Opid {
    pub fn copy_from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display("{opid}:{pos}")]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct CellAddr {
    pub opid: Opid,
    pub pos: u16,
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
pub struct Operation {
    pub contract_id: ContractId,
    pub call_id: CallId,
    /// Memory cells which were destroyed.
    pub destroying: SmallVec<Input>,
    pub reading: SmallVec<CellAddr>,
    /// Memory cells which were created (read-once, access-controlled).
    pub destructible: SmallVec<StateCell>,
    /// Immutable memory data which were created (write-once, readable by all).
    pub immutable: SmallVec<StateData>,
    pub reserved: ReservedBytes<8>,
}

impl CommitEncode for Operation {
    type CommitmentId = Opid;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.contract_id);
        e.commit_to_serialized(&self.call_id);
        e.commit_to_merkle(&self.destroying);
        e.commit_to_merkle(&self.reading);
        e.commit_to_merkle(&self.destructible);
        e.commit_to_merkle(&self.immutable);
        e.commit_to_serialized(&self.reserved);
    }
}
