use rsa::{RSAPrivateKey, RSAPublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::onion::v2::key::{TorPublicKeyV2, TorSecretKeyV2};

impl Serialize for TorSecretKeyV2 {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let v = self.0.private_key_to_pem().map_err(serde::ser::Error::custom)?;

        serializer.serialize_str(
            std::str::from_utf8(&v).map_err(serde::ser::Error::custom)?
        )
    }
}


impl Serialize for TorPublicKeyV2 {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let v = self.0.public_key_to_pem_pkcs1().map_err(serde::ser::Error::custom)?;

        serializer.serialize_str(
            std::str::from_utf8(&v).map_err(serde::ser::Error::custom)?
        )
    }
}


impl<'de> Deserialize<'de> for TorSecretKeyV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        // String deserialization note: take a look at deserialization of `TorPublicKeyV2`
        let text = <String>::deserialize(deserializer)?;
        let raw = RSAPrivateKey::from_pkcs1(text.as_bytes())
            .or_else(|_| RSAPrivateKey::from_pkcs8(text.as_bytes()))
            .map_err(serde::de::Error::custom)?;
        if !raw.check_key().map_err(serde::de::Error::custom)? {
            return Err(serde::de::Error::custom("RSA key invalid"));
        }
        Ok(TorSecretKeyV2(raw))
    }
}


impl<'de> Deserialize<'de> for TorPublicKeyV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        // there can't be &str as openssl puts "\n"(note: given two chars not 0x10 char)
        // and it can't be borrowed from source! It has to be copied and decoded thus String has to be used!

        // Wow I didn't expected that to happen! Serde has surprised me.

        let text = <String>::deserialize(deserializer)?;
        let raw = RSAPublicKey::from_pkcs1(text.as_bytes())
            .map_err(serde::de::Error::custom)?;
        // Note on checking key here:
        // Should keys with really small e(like 3) be allowed?
        // It makes some attack possible on RSA.
        // Anyway tor or openssl should filter that(?).
        Ok(TorPublicKeyV2(raw))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_can_serialize_and_deserialize_secret_key() {
        let sk = TorSecretKeyV2::generate();
        let data = serde_json::to_vec(&sk).unwrap();
        let rsk: TorSecretKeyV2 = serde_json::from_slice(&data).unwrap();

        assert_eq!(sk, rsk);
    }

    #[test]
    fn test_can_serialize_and_deserialize_public_key() {
        let sk = TorSecretKeyV2::generate().public();
        let data = serde_json::to_vec(&sk).unwrap();
        let rsk: TorPublicKeyV2 = serde_json::from_slice(&data).unwrap();

        assert_eq!(sk, rsk);
    }
}