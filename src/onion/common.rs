use std::fmt::Display;


#[cfg(feature = "v3")]
use crate::onion::{OnionAddressV3, TorPublicKeyV3, TorSecretKeyV3};

#[derive(Debug, Clone, PartialEq, Eq, From, TryInto)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum TorSecretKey {
    // leave this type, since some day tor may introduce v4 addresses
    // for instance quantum secure one

    #[cfg(feature = "v3")]
    V3(TorSecretKeyV3),
}

#[derive(Debug, Clone, PartialEq, Eq, From, TryInto)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum OnionAddress {
    // leave this type, since some day tor may introduce v4 addresses
    // for instance quantum secure one

    #[cfg(feature = "v3")]
    V3(OnionAddressV3),
}

impl Display for OnionAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "v3")]
            OnionAddress::V3(a) => a.fmt(f),
        }
    }
}

impl OnionAddress {
    pub fn get_address_without_dot_onion(&self) -> String {
        match self {
            #[cfg(feature = "v3")]
            OnionAddress::V3(a) => a.get_address_without_dot_onion(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, From, TryInto)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum TorPublicKey {
    #[cfg(feature = "v3")]
    V3(TorPublicKeyV3),
}