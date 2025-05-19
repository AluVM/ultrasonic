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

#[cfg(all(feature = "serde", feature = "baid64"))]
impl_serde_str_bin_wrapper!(Opid, Bytes32);

impl From<Opid> for [u8; 32] {
    fn from(opid: Opid) -> Self { opid.to_byte_array() }
}

impl From<Sha256> for Opid {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for Opid {
    const TAG: &'static str = "urn:ubideco:ultrasonic:operation#2024-11-14";
}

/// Address of the memory cell.
///
/// Memory cell address is the output of some operation defining that cell in its output.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(all(feature = "serde", not(feature = "baid64")), derive(Serialize, Deserialize))]
pub struct CellAddr {
    /// Operation identifier where the memory cell is defined.
    pub opid: Opid,

    /// Index of the operation output defining the cell.
    ///
    /// Whether this output is a [`Operation::destructible_out`] or [`Operation::immutable_out`] is
    /// always resolvable from the context in which the memory cell address is used.
    pub pos: u16,
}

impl CellAddr {
    /// Construct a memory cell address from an operation id and output number.
    pub fn new(opid: Opid, pos: u16) -> Self { Self { opid, pos } }
}

impl From<[u8; 34]> for CellAddr {
    fn from(value: [u8; 34]) -> Self {
        let opid = Opid::from_slice_checked(&value[..32]);
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
        /// Create operation id by trying to copy bytes from slice.
        ///
        /// Errors if the number of bytes in the slice is not 32.
        pub fn copy_from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
            Bytes32::copy_from_slice(slice).map(Self)
        }
    }

    /// Errors during parsing [`CellAddr`] from a string representation.
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

    impl Display for CellAddr {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}", self.opid, self.pos)
        }
    }
}

#[cfg(all(feature = "serde", feature = "baid64"))]
mod _serde {
    use core::str::FromStr;

    use serde::de::Error;
    use serde::ser::SerializeTuple;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

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

/// Operation input for a destructible (read-once) state.
///
/// The structure provides the reference to the memory cell and an optional witness data which
/// are used if the memory cell has a defined access condition (see [`StateCell::lock`]).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Input {
    /// Address of the memory cell.
    ///
    /// Memory cell address is the output of some operation defining that cell in its output.
    pub addr: CellAddr,

    /// A witness which provides additional data for satisfying the memory cell access conditions
    /// (see [`StateCell::lock`]).
    pub witness: StateValue,
}

/// Contract genesis.
///
/// Contract always has a single genesis, which can be seen as a form of operation (see
/// [`Genesis::to_operation`]). The difference between genesis and an operation lies in the fact
/// that genesis is guaranteed to have no input. Other operations may also take no input; but
/// genesis is the first contract operation probably having no input (otherwise being invalid),
/// which contributes to the contract id (see [`ContractId`]).
#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Genesis {
    /// Genesis version.
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
    /// pub enum Genesis {
    ///     V0(GenesisV0),
    ///     V1(GenesisV1)
    /// }
    /// pub struct GenesisV0 { /*...*/ }
    /// pub struct GenesisV1 { /*...*/ }
    /// ```
    pub version: ReservedBytes<1>,
    /// Codex id under which this genesis is created.
    ///
    /// A usual operation contains at this place a contract id, which can't be known at the time
    /// genesis is created (since the contract id depends on the genesis data itself).
    ///
    /// This value is being replaced with the proper contract id inside [`Genesis::to_operation`]
    /// conversion.
    pub codex_id: CodexId,
    /// Contract method this operation calls to.
    pub call_id: CallId,
    /// A nonce, which in genesis may be used to "mine" a vanity contract id.
    pub nonce: fe256,

    /// Genesis doesn't contain input, but we have to put these reserved zero bytes (matching zero
    /// length inpyt) in order to have [`Genesis`] serialized the same way as an [`Operation`].
    #[cfg_attr(feature = "serde", serde(skip))]
    pub blank1: ReservedBytes<2>,
    /// Genesis doesn't contain input, but we have to put these reserved zero bytes (matching zero
    /// length inpyt) in order to have [`Genesis`] serialized the same way as an [`Operation`].
    #[cfg_attr(feature = "serde", serde(skip))]
    pub blank2: ReservedBytes<2>,

    /// A list of the state for the new destructible memory cells which are created at the contract
    /// genesis (read-once, access-controlled).
    ///
    /// The list may be empty.
    pub destructible_out: SmallVec<StateCell>,
    /// A list of the state for the new Immutable memory cells, which are created at the contract
    /// genesis (write-once, readable by all).
    ///
    /// The list may be empty.
    pub immutable_out: SmallVec<StateData>,
}

impl Genesis {
    /// Converts genesis into an operation.
    ///
    /// Used for verification when genesis and other operations must have the same form.
    pub fn to_operation(&self, contract_id: ContractId) -> Operation {
        Operation {
            version: self.version,
            contract_id,
            call_id: self.call_id,
            nonce: self.nonce,
            destructible_in: none!(),
            immutable_in: none!(),
            destructible_out: self.destructible_out.clone(),
            immutable_out: self.immutable_out.clone(),
        }
    }

    /// Returns operation id for the genesis.
    ///
    /// The genesis operation id is computed by converting genesis into an operation with
    /// [`Self::to_operation`] method and then computing the [`Opid`] for it.
    ///
    /// The method call re-computed the id by hashing all the operation data, thus it is
    /// computationally-expensive, and the received value should be cached.
    #[inline]
    pub fn opid(&self, contract_id: ContractId) -> Opid { self.to_operation(contract_id).opid() }
}

/// Operation under a contract which may update the contract state.
#[derive(Clone, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Operation {
    /// Operation version.
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
    /// pub enum Operation {
    ///     V0(OperationV0),
    ///     V1(OperationV1)
    /// }
    /// pub struct OperationV0 { /*...*/ }
    /// pub struct OperationV1 { /*...*/ }
    /// ```
    pub version: ReservedBytes<1>,
    /// Contract id for which this operation is performed.
    pub contract_id: ContractId,
    /// Contract method this operation calls to.
    pub call_id: CallId,
    /// A nonce, used to change operation id for subsequent operations using the same arguments.
    pub nonce: fe256,
    /// A list of read-once memory cells which are the inputs to the operation and which state must
    /// be destroyed in the result of operation application.
    ///
    /// The list may be empty; in this case the operation just adds to the state without destroying
    /// any previously existing data.
    pub destructible_in: SmallVec<Input>,
    /// A list of append-only immutable memory cells which this operation may read.
    ///
    /// The list may be empty.
    pub immutable_in: SmallVec<CellAddr>,
    /// A list of the state for the new destructible memory cells which are created by the
    /// operation (read-once, access-controlled).
    ///
    /// The list may be empty.
    pub destructible_out: SmallVec<StateCell>,
    /// A list of the state for the new Immutable memory cells, which are created by the operation
    /// (write-once, readable by all).
    ///
    /// The list may be empty.
    pub immutable_out: SmallVec<StateData>,
}

impl PartialOrd for Operation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for Operation {
    fn cmp(&self, other: &Self) -> Ordering { self.opid().cmp(&other.opid()) }
}
impl PartialEq for Operation {
    fn eq(&self, other: &Self) -> bool { self.opid() == other.opid() }
}

impl CommitEncode for Operation {
    type CommitmentId = Opid;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.version);
        e.commit_to_serialized(&self.contract_id);
        e.commit_to_serialized(&self.call_id);
        e.commit_to_serialized(&self.nonce);
        e.commit_to_merkle(&self.destructible_in);
        e.commit_to_merkle(&self.immutable_in);
        e.commit_to_merkle(&self.destructible_out);
        e.commit_to_merkle(&self.immutable_out);
    }
}

impl Operation {
    /// Compute operation id - a unique hash committing to all the operation data.
    ///
    /// The id is computed using the `CommitEncode` procedure and is equivalent to the value
    /// returned by [`Self::commit_id`].
    #[inline]
    pub fn opid(&self) -> Opid { self.commit_id() }
}

/// Provably verified operation, which can be constructed only by running [`Codex::verify`] method.
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

    /// Get the operation id.
    ///
    /// The method uses cached value, thus running it is inexpensive.
    #[inline]
    pub fn opid(&self) -> Opid { self.0 }

    /// Return a reference for the verified operation data.
    #[inline]
    pub fn as_operation(&self) -> &Operation { &self.1 }

    /// Release the operation, discarding the verification status and cached opid.
    #[inline]
    pub fn into_operation(self) -> Operation { self.1 }
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use core::str::FromStr;

    use amplify::ByteArray;
    use commit_verify::Digest;
    use strict_encoding::StrictDumb;

    use super::*;

    #[test]
    fn opid_display() {
        let id = Opid::from_byte_array(Sha256::digest(b"test"));
        assert_eq!(format!("{id}"), "n4bQgYhMfWWaL_qgxVrQFaO~TxsrC4Is0V1sFbDwCgg");
        assert_eq!(format!("{id:-}"), "usop:n4bQgYhMfWWaL_qgxVrQFaO~TxsrC4Is0V1sFbDwCgg");
        assert_eq!(
            format!("{id:#}"),
            "n4bQgYhMfWWaL_qgxVrQFaO~TxsrC4Is0V1sFbDwCgg#nova-impact-simon"
        );
    }

    #[test]
    fn opid_from_str() {
        let id = Opid::from_byte_array(Sha256::digest(b"test"));
        assert_eq!(Opid::from_str("n4bQgYhMfWWaL_qgxVrQFaO~TxsrC4Is0V1sFbDwCgg").unwrap(), id);
        assert_eq!(Opid::from_str("usop:n4bQgYhMfWWaL_qgxVrQFaO~TxsrC4Is0V1sFbDwCgg").unwrap(), id);
        assert_eq!(
            Opid::from_str("n4bQgYhMfWWaL_qgxVrQFaO~TxsrC4Is0V1sFbDwCgg#nova-impact-simon")
                .unwrap(),
            id
        );
        assert_eq!(
            Opid::from_str("usop:n4bQgYhMfWWaL_qgxVrQFaO~TxsrC4Is0V1sFbDwCgg#nova-impact-simon")
                .unwrap(),
            id
        );
    }

    #[test]
    #[cfg(all(feature = "serde", feature = "baid64"))]
    fn opid_serde() {
        let val = Opid::strict_dumb();
        test_serde_str_bin_wrapper!(val, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]);
    }

    #[test]
    #[cfg(all(feature = "serde", feature = "baid64"))]
    fn cell_addr_serde() {
        use serde_test::{assert_tokens, Configure, Token};
        let val = CellAddr::strict_dumb();
        assert_eq!(bincode::serialize(&val).unwrap(), &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0
        ]);
        assert_eq!(
            bincode::serialize(&val).unwrap(),
            bincode::serialize(&(val.opid, val.pos)).unwrap()
        );
        assert_tokens(&val.readable(), &[Token::Str(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0",
        )]);
    }

    #[test]
    fn genesis_opid() {
        let contract_id = ContractId::strict_dumb();
        let genesis = Genesis::strict_dumb();
        assert_eq!(genesis.opid(contract_id), genesis.to_operation(contract_id).opid());
        let other_contract_id = ContractId::from_byte_array(Sha256::digest(b"test"));
        assert_ne!(genesis.opid(contract_id), genesis.to_operation(other_contract_id).opid())
    }
}
