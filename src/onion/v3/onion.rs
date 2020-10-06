//! onion module contains utils for working with Tor's onion services

use std::str::FromStr;

#[cfg(feature = "serialize")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha3::Digest;

use crate::onion::v3::TorPublicKeyV3;
use crate::utils::BASE32_ALPHA;

/// 32 public key bytes + 2 bytes of checksum = 34
/// (in onion address v3 there is one more byte - version eq to 3)
/// Checksum is embbeded in order not to recompute it.
///
/// This variable denotates byte length of OnionAddressV3.
pub const TORV3_ONION_ADDRESS_LENGTH_BYTES: usize = 34;

/// OnionAddressV3 contains public part of Tor's onion service address version 3.,
/// It can't contain invalid onion address
#[derive(Clone, Copy)]
pub struct OnionAddressV3([u8; TORV3_ONION_ADDRESS_LENGTH_BYTES]);

impl PartialEq for OnionAddressV3 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        &self.0[..] == &other.0[..]
    }
}

impl Eq for OnionAddressV3 {}

impl From<&TorPublicKeyV3> for OnionAddressV3 {
    fn from(tpk: &TorPublicKeyV3) -> Self {
        let mut buf = [0u8; 34];
        tpk.0.iter().copied().enumerate().for_each(|(i, b)| {
            buf[i] = b;
        });

        let mut h = sha3::Sha3_256::new();
        h.input(b".onion checksum");
        h.input(&tpk.0);
        h.input(b"\x03");

        let res_vec = h.result().to_vec();
        buf[32] = res_vec[0];
        buf[33] = res_vec[1];
        Self(buf)
    }
}

impl std::fmt::Debug for OnionAddressV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "OnionAddress({})",
            base32::encode(BASE32_ALPHA, &(self.get_raw_bytes())[..]).to_ascii_lowercase(),
        )
    }
}

impl std::fmt::Display for OnionAddressV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}.onion",
            base32::encode(BASE32_ALPHA, &(self.get_raw_bytes())[..]).to_ascii_lowercase()
        )
    }
}

impl OnionAddressV3 {
    #[inline]
    pub fn get_address_without_dot_onion(&self) -> String {
        base32::encode(BASE32_ALPHA, &(self.get_raw_bytes())[..]).to_ascii_lowercase()
    }

    #[inline]
    pub fn get_raw_bytes(&self) -> [u8; 35] {
        let mut buf = [0u8; 35];
        buf[..34].clone_from_slice(&self.0);
        buf[34] = 3;
        buf
    }

    #[inline]
    pub fn get_public_key(&self) -> TorPublicKeyV3 {
        let mut buf = [0u8; 32];
        buf[..].clone_from_slice(&self.0[..32]);
        TorPublicKeyV3(buf)
    }
}

#[derive(Debug)]
pub enum OnionAddressParseError {
    InvalidLength,
    Base32Error,
    InvalidChecksum,
    InvalidVersion,
}

impl std::fmt::Display for OnionAddressParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "OnionAddressParseError occurred")
    }
}

impl FromStr for OnionAddressV3 {
    type Err = OnionAddressParseError;

    /// from_str parses OnionAddressV3 from string.
    ///
    /// Please note that it accepts address *without* .onion only.
    fn from_str(raw_onion_address: &str) -> Result<Self, Self::Err> {
        if raw_onion_address.as_bytes().len() != 56 {
            return Err(OnionAddressParseError::InvalidLength);
        }
        let mut buf = [0u8; 56];
        raw_onion_address.as_bytes().iter().copied().enumerate().for_each(|(i, b)| {
            buf[i] = b;
        });

        let res = match base32::decode(BASE32_ALPHA, raw_onion_address) {
            None => return Err(OnionAddressParseError::Base32Error),
            Some(data) => data,
        };

        // panic!("Out deserialized length: {}", )

        // is this even possible?
        if res.len() != 32 + 2 + 1 {
            return Err(OnionAddressParseError::InvalidLength);
        }

        if res[34] != 3 {
            return Err(OnionAddressParseError::InvalidVersion);
        }

        // Onion address v3 structure:
        // p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion
        // 1. public key for ed25519 (32 bytes)
        // 2. two first bytes of sha3_256 of checksum (two bytes)
        // 3. binary three(0x03) (one byte)
        // above things are base32 encoded and .onion is appended

        // onion service checksum = H(".onion checksum" || pubkey || version)[..2]
        //  where H is sha3_256

        let mut h = sha3::Sha3_256::new();
        h.input(b".onion checksum");
        h.input(&res[..32]);
        h.input(b"\x03");

        let res_vec = h.result().to_vec();
        if res_vec[0] != res[32] || res_vec[1] != res[33] {
            return Err(OnionAddressParseError::InvalidChecksum);
        }

        let mut buf = [0u8; 34];
        for i in 0..32 {
            buf[i] = res[i];
        }
        buf[32] = res_vec[0];
        buf[33] = res_vec[1];

        Ok(Self(buf))
    }
}

#[cfg(feature = "serialize")]
impl Serialize for OnionAddressV3 {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let res = self.get_address_without_dot_onion();
        serializer.serialize_str(&res)
    }
}

#[cfg(feature = "serialize")]
impl<'de> Deserialize<'de> for OnionAddressV3 {
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

    //noinspection SpellCheckingInspection
    #[test]
    fn test_can_parse_onion_address() {
        let oa = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd";
        assert_eq!(
            OnionAddressV3::from_str(oa).unwrap().to_string(),
            "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"
        );
    }

    #[test]
    fn test_can_convert_to_public_key_and_vice_versa() {
        let oa = OnionAddressV3::from_str("p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd").unwrap();
        let pk = oa.get_public_key();
        let oa2 = pk.get_onion_address();
        assert_eq!(oa, oa2);
    }
}
