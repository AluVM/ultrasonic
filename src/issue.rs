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

use core::fmt::Debug;
use core::str::FromStr;

use amplify::{ByteArray, Bytes32, Wrapper};
use commit_verify::{
    CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, ReservedBytes, Sha256,
};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, TypeName};

use crate::{Codex, Genesis, Identity, Opid, LIB_NAME_ULTRASONIC};

/// Information on the issue of the contract.
#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Issue {
    /// Version of the contract.
    pub version: ReservedBytes<1>,
    /// Contract metadata.
    pub meta: ContractMeta,
    /// The codex under which the contract is issued and against which it must be validated.
    pub codex: Codex,
    /// Genesis operation.
    pub genesis: Genesis,
}

impl PartialEq for Issue {
    fn eq(&self, other: &Self) -> bool { self.commit_id() == other.commit_id() }
}

impl CommitEncode for Issue {
    type CommitmentId = ContractId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.version);
        e.commit_to_serialized(&self.meta);
        e.commit_to_serialized(&self.codex.codex_id());
        e.commit_to_serialized(&self.genesis.opid(ContractId::from_byte_array([0xFFu8; 32])));
    }
}

impl Issue {
    /// Computes contract id.
    ///
    /// Contract id is a commitment to the contract issue information, which includes contract
    /// metadata, codex, and genesis operation.
    #[inline]
    pub fn contract_id(&self) -> ContractId { self.commit_id() }

    /// Computes the operation id of the genesis operation.
    ///
    /// Equals to the [`Genesis::opid`] called with [`Self::contract_id`] as an argument.
    #[inline]
    pub fn genesis_opid(&self) -> Opid { self.genesis.opid(self.contract_id()) }
}

/// Consensus (layer 1) which is used by a contract.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
#[repr(u8)]
pub enum Consensus {
    /// No consensus is used.
    ///
    /// This means the contract data are not final and depend on the external consensus between
    /// the contract parties.
    #[strict_type(dumb)]
    None = 0,

    /// Bitcoin PoW consensus.
    Bitcoin = 0x10,

    /// Liquid federation consensus.
    Liquid = 0x11,

    /// Prime consensus.
    Prime = 0x20,
}

impl FromStr for Consensus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Consensus::None),
            "bitcoin" => Ok(Consensus::Bitcoin),
            "liquid" => Ok(Consensus::Liquid),
            "prime" => Ok(Consensus::Prime),
            _ => Err(s.to_owned()),
        }
    }
}

/// Metadata about the contract.
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct ContractMeta {
    /// Indicated whether the contract is a test contract.
    pub testnet: bool,
    /// Consensus layer used by the contract.
    pub consensus: Consensus,
    /// Reserved bytes, providing alignment to the 16-byte edge
    #[cfg_attr(feature = "serde", serde(skip))]
    pub reserved: ReservedBytes<14>,
    /// Timestamp of the moment the contract is issued
    pub timestamp: i64,
    // ^^ above is a fixed-size contract header of 32 bytes
    /// A name of the contract.
    pub name: ContractName,
    /// An identity of the contract issuer.
    ///
    /// If no identity is given, should be set to `ssi:anonymous` ([`Identity::default`]).
    pub issuer: Identity,
}

/// Contract name.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC, tags = custom)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum ContractName {
    /// The contract is unnamed.
    #[strict_type(tag = 0, dumb)]
    #[display("~")]
    Unnamed,

    /// The contract has a specific name.
    #[strict_type(tag = 1)]
    #[display(inner)]
    Named(TypeName),
}

/// Unique contract identifier equivalent to the contract genesis commitment
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(AsSlice, Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(
    all(feature = "serde", not(feature = "baid64")),
    derive(Serialize, Deserialize),
    serde(transparent)
)]
pub struct ContractId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

#[cfg(all(feature = "serde", feature = "baid64"))]
impl_serde_wrapper!(ContractId, Bytes32);

impl From<Sha256> for ContractId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for ContractId {
    const TAG: &'static str = "urn:ubideco:sonic:contract#2024-11-16";
}

#[cfg(feature = "baid64")]
mod _baid4 {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};

    use super::*;

    impl DisplayBaid64 for ContractId {
        const HRI: &'static str = "contract";
        const CHUNKING: bool = true;
        const PREFIX: bool = true;
        const EMBED_CHECKSUM: bool = false;
        const MNEMONIC: bool = false;
        fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
    }
    impl FromBaid64Str for ContractId {}
    impl FromStr for ContractId {
        type Err = Baid64ParseError;
        fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
    }
    impl Display for ContractId {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
    }
}

#[cfg(test)]
mod test {
    use amplify::ByteArray;
    use commit_verify::Digest;

    use super::*;

    #[test]
    fn contract_id_display() {
        let id = ContractId::from_byte_array(Sha256::digest(b"test"));
        assert_eq!(format!("{id}"), "contract:n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg");
        assert_eq!(format!("{id:-}"), "n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg");
        assert_eq!(
            format!("{id:#}"),
            "contract:n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg#fractal-fashion-capsule"
        );
    }

    #[test]
    fn contract_id_from_str() {
        let id = ContractId::from_byte_array(Sha256::digest(b"test"));
        assert_eq!(
            ContractId::from_str("contract:n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg")
                .unwrap(),
            id
        );
        assert_eq!(
            ContractId::from_str("n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg").unwrap(),
            id
        );
        assert_eq!(
            ContractId::from_str(
                "n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg#fractal-fashion-capsule"
            )
            .unwrap(),
            id
        );
        assert_eq!(
            ContractId::from_str(
                "contract:n4bQgYhM-fWWaL_q-gxVrQFa-O~TxsrC-4Is0V1s-FbDwCgg#fractal-fashion-capsule"
            )
            .unwrap(),
            id
        );
    }

    #[test]
    #[cfg(all(feature = "serde", feature = "baid64"))]
    fn contract_id_serde() {
        let val = ContractId::strict_dumb();
        test_serde_wrapper!(val, "contract:AAAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA", &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]);
    }
}
