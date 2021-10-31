use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::onion::OnionAddressV3;

impl Serialize for OnionAddressV3 {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let res = self.get_address_without_dot_onion();
        serializer.serialize_str(&res)
    }
}

impl<'de> Deserialize<'de> for OnionAddressV3 {
    //noinspection SpellCheckingInspection
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        let raw_onion_addr = <&str>::deserialize(deserializer)?;
        Ok(Self::from_str(raw_onion_addr).map_err(de::Error::custom)?)
    }
}

// TODO(teawithsand): testing for these