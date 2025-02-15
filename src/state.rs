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
use core::str::FromStr;

use aluvm::alu::LibSite;
use aluvm::fe256;
use amplify::confinement::SmallBlob;
use amplify::hex::FromHex;
use amplify::num::u256;
use amplify::{hex, Bytes};
use commit_verify::{CommitEncode, CommitEngine, MerkleHash, StrictHash};

use crate::LIB_NAME_ULTRASONIC;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(
    all(feature = "serde", not(feature = "baid64")),
    derive(Serialize, Deserialize),
    serde(transparent)
)]
pub struct AuthToken(#[from] fe256);

// Types in ultrasonic must not be ordered, since zk-STARK proofs are really inefficient in applying
// ordering to field elements. However, upstream we need to put `AuthToken` into `BTreeMap`, thus we
// need `Ord` implementation for pure rust reasons. It must not be used anywhere in the consensus
// layer.
impl PartialOrd for AuthToken {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for AuthToken {
    fn cmp(&self, other: &Self) -> Ordering { self.0.to_u256().cmp(&other.0.to_u256()) }
}

impl From<[u8; 30]> for AuthToken {
    fn from(value: [u8; 30]) -> Self { Self::from_byte_array(value) }
}
impl From<Bytes<30>> for AuthToken {
    fn from(value: Bytes<30>) -> Self { Self::from_byte_array(value.to_byte_array()) }
}

impl AuthToken {
    pub const fn to_fe256(&self) -> fe256 { self.0 }

    pub fn from_byte_array(bytes: [u8; 30]) -> Self {
        let mut buf = [0u8; 32];
        buf[..30].copy_from_slice(&bytes);
        let val = fe256::from(buf);
        Self(val)
    }

    pub fn to_byte_array(&self) -> [u8; 30] {
        let bytes = self.0.to_u256().to_le_bytes();
        debug_assert_eq!(&bytes[30..], &[0, 0]);

        let mut buf = [0u8; 30];
        buf.copy_from_slice(&bytes[..30]);
        buf
    }

    pub fn to_bytes30(&self) -> Bytes<30> {
        let bytes = self.to_byte_array();
        Bytes::from(bytes)
    }
}

#[cfg(feature = "baid64")]
mod _baid64 {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};

    use super::*;

    impl DisplayBaid64<30> for AuthToken {
        const HRI: &'static str = "at";
        const CHUNKING: bool = true;
        const CHUNK_FIRST: usize = 8;
        const CHUNK_LEN: usize = 8;
        const PREFIX: bool = true;
        const EMBED_CHECKSUM: bool = true;
        const MNEMONIC: bool = false;
        fn to_baid64_payload(&self) -> [u8; 30] { self.to_byte_array() }
    }
    impl FromBaid64Str<30> for AuthToken {}
    impl FromStr for AuthToken {
        type Err = Baid64ParseError;
        fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
    }
    impl Display for AuthToken {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(tag = "type", rename_all = "camelCase")
)]
pub enum StateValue {
    #[default]
    #[strict_type(tag = 0x00)]
    None,
    #[strict_type(tag = 0x01)]
    Single { first: fe256 },
    #[strict_type(tag = 0x02)]
    Double { first: fe256, second: fe256 },
    #[strict_type(tag = 0x03)]
    Three {
        first: fe256,
        second: fe256,
        third: fe256,
    },
    #[strict_type(tag = 0x04)]
    Four {
        first: fe256,
        second: fe256,
        third: fe256,
        fourth: fe256,
    },
}

impl StateValue {
    pub fn from<I: IntoIterator<Item = u256>>(iter: I) -> Self
    where I::IntoIter: ExactSizeIterator {
        let mut iter = iter.into_iter();
        let len = iter.len();
        let first = iter.next().map(fe256::from);
        let second = iter.next().map(fe256::from);
        let third = iter.next().map(fe256::from);
        let fourth = iter.next().map(fe256::from);
        match len {
            0 => StateValue::None,
            1 => StateValue::Single { first: first.unwrap() },
            2 => StateValue::Double { first: first.unwrap(), second: second.unwrap() },
            3 => StateValue::Three {
                first: first.unwrap(),
                second: second.unwrap(),
                third: third.unwrap(),
            },
            4 => StateValue::Four {
                first: first.unwrap(),
                second: second.unwrap(),
                third: third.unwrap(),
                fourth: fourth.unwrap(),
            },
            _ => panic!("state value can't use more than 4 elements"),
        }
    }

    pub fn get(&self, pos: u8) -> Option<fe256> {
        match (*self, pos) {
            (Self::Single { first }, 0)
            | (Self::Double { first, .. }, 0)
            | (Self::Three { first, .. }, 0)
            | (Self::Four { first, .. }, 0) => Some(first),

            (Self::Double { second, .. }, 1)
            | (Self::Three { second, .. }, 1)
            | (Self::Four { second, .. }, 1) => Some(second),

            (Self::Three { third, .. }, 2) | (Self::Four { third, .. }, 2) => Some(third),

            (Self::Four { fourth, .. }, 3) => Some(fourth),

            _ => None,
        }
    }
}

/// Read-once access-controlled memory cell.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct StateCell {
    pub data: StateValue,
    /// Token of authority
    pub auth: AuthToken,
    pub lock: Option<LibSite>,
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Debug, Display, From)]
#[wrapper(AsSlice, BorrowSlice, Hex, RangeOps)]
#[wrapper_mut(BorrowSliceMut, RangeMut)]
#[display("0x{0:X}")]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
pub struct RawData(#[from] SmallBlob);

impl FromStr for RawData {
    type Err = hex::Error;
    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        s = s.strip_prefix("0x").unwrap_or(s);
        Self::from_hex(s)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct StateData {
    pub value: StateValue,
    pub raw: Option<RawData>,
}

impl CommitEncode for StateData {
    type CommitmentId = MerkleHash;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.value);
        match &self.raw {
            None => e.commit_to_option(&Option::<RawData>::None),
            Some(raw) => e.commit_to_hash(raw),
        }
    }
}

#[cfg(all(feature = "serde", feature = "baid64"))]
mod _serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for AuthToken {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_string())
            } else {
                self.0.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for AuthToken {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(D::Error::custom)
            } else {
                fe256::deserialize(deserializer).map(Self)
            }
        }
    }
}

#[cfg(feature = "serde")]
mod _serde2 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;
    impl Serialize for RawData {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_string())
            } else {
                self.0.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for RawData {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(D::Error::custom)
            } else {
                SmallBlob::deserialize(deserializer).map(Self)
            }
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "baid64")]
    use super::*;

    #[test]
    #[cfg(feature = "baid64")]
    fn auth_baid64() {
        use baid64::DisplayBaid64;
        let auth = AuthToken::from_byte_array([0xAD; 30]);

        let baid64 = "at:ra2tra2t-ra2tra2t-ra2tra2t-ra2tra2t-ra2tra2t-HURE_w";
        assert_eq!(baid64, auth.to_string());
        assert_eq!(auth.to_string(), auth.to_baid64_string());

        let auth2: AuthToken = baid64.parse().unwrap();
        assert_eq!(auth, auth2);

        let reconstructed = AuthToken::from_str(&baid64.replace('-', "")).unwrap();
        assert_eq!(reconstructed, auth);
    }
}
