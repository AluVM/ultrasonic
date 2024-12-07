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

use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::str::FromStr;

use amplify::{Bytes32, Wrapper};
use commit_verify::{CommitId, CommitmentId, DigestExt, ReservedBytes, Sha256};
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictDumb, StrictEncode, TypeName, TypedRead,
};

use crate::{Codex, Genesis, Identity, LIB_NAME_ULTRASONIC};

// TODO: Move to amplify
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictEncode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize), serde(rename_all = "camelCase"))]
pub struct ConstU32<const CONST: u32>(u32);

impl<const CONST: u32> Default for ConstU32<CONST> {
    fn default() -> Self { ConstU32(CONST) }
}

impl<const CONST: u32> ConstU32<CONST> {
    pub fn new() -> Self { ConstU32(CONST) }
}

impl<const CONST: u32> StrictDecode for ConstU32<CONST> {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let val = r.read_field::<u32>()?;
            if val != CONST {
                return Err(DecodeError::DataIntegrityError(s!("ConstU32 mismatch")));
            }
            Ok(ConstU32(CONST))
        })
    }
}

pub type ContractPrivate = Contract<0>;

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = ContractId)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Contract<const CAPS: u32> {
    pub version: ReservedBytes<2>,
    pub meta: ContractMeta<CAPS>,
    pub codex: Codex,
    pub genesis: Genesis,
}

impl<const CAPS: u32> Contract<CAPS> {
    pub fn contract_id(&self) -> ContractId { self.commit_id() }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct ContractMeta<const CAPS: u32> {
    pub capabilities: ConstU32<CAPS>,
    // aligning to 16 byte edge
    #[cfg_attr(feature = "serde", serde(skip))]
    pub reserved: ReservedBytes<10>,
    pub timestamp: i64,
    // ^^ above is a fixed-size contract header of 32 bytes
    pub name: ContractName,
    pub issuer: Identity,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC, tags = custom)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum ContractName {
    #[strict_type(tag = 0, dumb)]
    #[display("~")]
    Unnamed,

    #[strict_type(tag = 1)]
    #[display(inner)]
    Named(TypeName),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display(inner)]
pub enum ContractRef {
    Id(ContractId),
    Name(TypeName),
    // Mnemonic(),
}

/// Unique contract identifier equivalent to the contract genesis commitment
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
pub struct ContractId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

#[cfg(feature = "baid64")]
mod _baid4 {
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

    impl From<Sha256> for ContractId {
        fn from(hasher: Sha256) -> Self { hasher.finish().into() }
    }

    impl CommitmentId for ContractId {
        const TAG: &'static str = "urn:ubideco:sonic:contract#2024-11-16";
    }
}

// TODO: Use Base64 macro
#[cfg(feature = "serde")]
mod _serde {
    use amplify::ByteArray;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for ContractId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                self.to_byte_array().serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for ContractId {
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

    impl<'de, const CONST: u32> Deserialize<'de> for ConstU32<CONST> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let val = u32::deserialize(deserializer)?;
            if val != CONST {
                return Err(D::Error::custom("Invalid constant value"));
            }
            Ok(ConstU32(CONST))
        }
    }
}
