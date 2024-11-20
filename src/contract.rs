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
use commit_verify::{CommitmentId, DigestExt, Sha256};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::LIB_NAME_ULTRASONIC;

pub trait ProofOfPubl:
    Copy + Eq + StrictDumb + StrictEncode + StrictDecode + Debug + Display + Into<[u8; 4]>
{
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
}
