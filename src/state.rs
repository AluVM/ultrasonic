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

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use aluvm::{fe256, LibSite};
use amplify::confinement::SmallBlob;
use amplify::hex::FromHex;
use amplify::num::u256;
use amplify::{hex, Bytes};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use commit_verify::{CommitEncode, CommitEngine, MerkleHash, StrictHash};

use crate::LIB_NAME_ULTRASONIC;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC)]
pub struct AuthToken(#[from] fe256);

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

impl DisplayBaid64<30> for AuthToken {
    const HRI: &'static str = "auth";
    const CHUNKING: bool = true;
    const CHUNK_FIRST: usize = 8;
    const CHUNK_LEN: usize = 8;
    const PREFIX: bool = false;
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

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_ULTRASONIC, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(untagged, rename_all = "camelCase")
)]
pub enum StateValue {
    #[default]
    #[strict_type(tag = 0x00)]
    None,
    #[strict_type(tag = 0x01)]
    Single(fe256),
    #[strict_type(tag = 0x02)]
    Double(fe256, fe256),
    #[strict_type(tag = 0x03)]
    Three(fe256, fe256, fe256),
    #[strict_type(tag = 0x04)]
    Four(fe256, fe256, fe256, fe256),
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
            1 => StateValue::Single(first.unwrap()),
            2 => StateValue::Double(first.unwrap(), second.unwrap()),
            3 => StateValue::Three(first.unwrap(), second.unwrap(), third.unwrap()),
            4 => StateValue::Four(first.unwrap(), second.unwrap(), third.unwrap(), fourth.unwrap()),
            _ => panic!("state value can't use more than 4 elements"),
        }
    }

    pub fn get(&self, pos: u8) -> Option<fe256> {
        match (*self, pos) {
            (Self::Single(el), 0)
            | (Self::Double(el, _), 0)
            | (Self::Three(el, _, _), 0)
            | (Self::Four(el, _, _, _), 0) => Some(el),

            (Self::Double(_, el), 1)
            | (Self::Three(_, el, _), 1)
            | (Self::Four(_, el, _, _), 1) => Some(el),

            (Self::Three(_, _, el), 2) | (Self::Four(_, _, el, _), 2) => Some(el),

            (Self::Four(_, _, _, el), 3) => Some(el),

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
    use super::*;

    #[test]
    fn auth_baid64() {
        let auth = AuthToken::from_byte_array([0xAD; 30]);

        let baid64 = "ra2tra2t-ra2tra2t-ra2tra2t-ra2tra2t-ra2tra2t-WsPD8w";
        assert_eq!(baid64, auth.to_string());
        assert_eq!(auth.to_string(), auth.to_baid64_string());

        let auth2: AuthToken = baid64.parse().unwrap();
        assert_eq!(auth, auth2);

        let reconstructed = AuthToken::from_str(&baid64.replace('-', "")).unwrap();
        assert_eq!(reconstructed, auth);
    }
}
