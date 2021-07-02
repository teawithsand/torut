//! onion module contains utils for working with Tor's onion services

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "serialize")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::utils::BASE32_ALPHA;

// use crate::onion::TorPublicKeyV2;

pub const TORV2_ONION_ADDRESS_LENGTH_BYTES: usize = 10;

/// OnionAddressV2 contains public part of Tor's onion service address version 2.
/// It can't contain invalid onion address(
///
/// # Public key
/// Unlike onion address V3 onion address V2 does not contain public key which has to be fetched from relay.
/// This means that public key can't be extracted from this representation.
/// Creating address from key is one way function.
///
/// # Note
/// Onion address V2 does not contain checksum so any combination of random ten bytes satisfies requirements.
/// Since it may be valid SHA1 bytes.
///
/// # Docs
/// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v2.txt#n530
#[derive(Clone, Copy)]
pub struct OnionAddressV2([u8; TORV2_ONION_ADDRESS_LENGTH_BYTES]);

// looks like Shallot does this
// https://github.com/katmagic/Shallot/blob/master/src/thread.c
/*
impl From<&TorPublicKeyV2> for OnionAddressV2 {
    fn from(pk: &TorPublicKeyV2) -> Self {
        /
    }
}
*/

impl PartialEq for OnionAddressV2 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        &self.0[..] == &other.0[..]
    }
}

impl Eq for OnionAddressV2 {}

impl std::fmt::Debug for OnionAddressV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "OnionAddressV2({})",
            base32::encode(BASE32_ALPHA, &(self.get_raw_bytes())[..]).to_ascii_lowercase(),
        )
    }
}

impl std::fmt::Display for OnionAddressV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}.onion",
            base32::encode(BASE32_ALPHA, &(self.get_raw_bytes())[..]).to_ascii_lowercase()
        )
    }
}

impl OnionAddressV2 {
    #[inline]
    pub fn get_address_without_dot_onion(&self) -> String {
        base32::encode(BASE32_ALPHA, &(self.get_raw_bytes())[..]).to_ascii_lowercase()
    }

    #[inline]
    pub fn get_raw_bytes(&self) -> [u8; 10] {
        self.0
    }

    /*
    #[inline]
    pub fn get_public_key(&self) -> TorPublicKeyV3 {
        let mut buf = [0u8; 32];
        buf[..].clone_from_slice(&self.0[..32]);
        TorPublicKeyV3(buf)
    }
    */
}

#[derive(Debug)]
pub enum OnionAddressV2ParseError {
    InvalidLength,
    Base32Error,
    InvalidChecksum,
    InvalidVersion,
}

impl Display for OnionAddressV2ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Filed to parse OnionAddressV2")
    }
}

impl Error for OnionAddressV2ParseError {}


impl FromStr for OnionAddressV2 {
    type Err = OnionAddressV2ParseError;

    fn from_str(raw_onion_address: &str) -> Result<Self, Self::Err> {
        if raw_onion_address.len() != 16 {
            return Err(OnionAddressV2ParseError::InvalidLength);
        }
        let mut buf = [0u8; 10];
        let d = base32::decode(BASE32_ALPHA, raw_onion_address);
        let d = match d {
            Some(v) => v,
            None => {
                return Err(OnionAddressV2ParseError::Base32Error);
            }
        };
        if d.len() != buf.len() {
            return Err(OnionAddressV2ParseError::InvalidLength);
        }
        buf.clone_from_slice(&d[..]);
        Ok(Self(buf))
    }
}

#[cfg(feature = "serialize")]
impl Serialize for OnionAddressV2 {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let res = self.get_address_without_dot_onion();
        serializer.serialize_str(&res)
    }
}

#[cfg(feature = "serialize")]
impl<'de> Deserialize<'de> for OnionAddressV2 {
    //noinspection SpellCheckingInspection
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        let raw_onion_addr = <&str>::deserialize(deserializer)?;
        Ok(Self::from_str(raw_onion_addr).map_err(de::Error::custom)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // noinspection SpellCheckingInspection
    #[test]
    fn test_can_parse_onion_address() {
        let oa = "duskgytldkxiuqc6";
        assert_eq!(
            OnionAddressV2::from_str(oa).unwrap().to_string(),
            "duskgytldkxiuqc6.onion"
        );
    }
}