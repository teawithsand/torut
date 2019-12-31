use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::onion::v3::{TorPublicKeyV3, TorSecretKeyV3};

impl Serialize for TorSecretKeyV3 {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_str(&base64::encode(&self.as_bytes()[..]))
    }
}

impl Serialize for TorPublicKeyV3 {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        serializer.serialize_str(&base64::encode(&self.0[..]))
    }
}

impl<'de> Deserialize<'de> for TorSecretKeyV3 {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        let text = <&str>::deserialize(deserializer)?;
        let raw = base64::decode(text).map_err(serde::de::Error::custom)?;
        if raw.len() != 64 {
            return Err(serde::de::Error::custom("Invalid secret key length"));
        }
        let mut buf = [0u8; 64];
        buf.clone_from_slice(&raw[..]);
        Ok(Self::from(buf))
    }
}

impl<'de> Deserialize<'de> for TorPublicKeyV3 {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        let text = <&str>::deserialize(deserializer)?;
        let raw = base64::decode(text).map_err(serde::de::Error::custom)?;
        if raw.len() != 32 {
            return Err(serde::de::Error::custom("Invalid secret key length"));
        }
        let mut buf = [0u8; 32];
        for i in 0..32 {
            buf[i] = raw[i];
        }
        Ok(Self(buf))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_can_serialize_and_deserialize_secret_key() {
        let sk = TorSecretKeyV3::generate();
        let data = serde_json::to_vec(&sk).unwrap();
        let rsk: TorSecretKeyV3 = serde_json::from_slice(&data).unwrap();

        assert_eq!(sk, rsk);
    }

    #[test]
    fn test_can_serialize_and_deserialize_public_key() {
        let sk = TorSecretKeyV3::generate().public();
        let data = serde_json::to_vec(&sk).unwrap();
        let rsk: TorPublicKeyV3 = serde_json::from_slice(&data).unwrap();

        assert_eq!(sk, rsk);
    }
}