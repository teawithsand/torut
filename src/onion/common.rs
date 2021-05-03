use std::fmt::Display;

#[cfg(feature = "v2")]
use crate::onion::{OnionAddressV2, TorPublicKeyV2, TorSecretKeyV2};
#[cfg(feature = "v3")]
use crate::onion::{OnionAddressV3, TorPublicKeyV3, TorSecretKeyV3};

#[derive(Debug, Clone, PartialEq, Eq, From, TryInto)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum TorSecretKey {
    #[cfg(feature = "v2")]
    V2(TorSecretKeyV2),
    #[cfg(feature = "v3")]
    V3(TorSecretKeyV3),
}

#[derive(Debug, Clone, PartialEq, Eq, From, TryInto)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum OnionAddress {
    #[cfg(feature = "v2")]
    V2(OnionAddressV2),
    #[cfg(feature = "v3")]
    V3(OnionAddressV3),
}

impl Display for OnionAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "v2")]
            OnionAddress::V2(a) => a.fmt(f),
            #[cfg(feature = "v3")]
            OnionAddress::V3(a) => a.fmt(f),
        }
    }
}

impl OnionAddress {
    pub fn get_address_without_dot_onion(&self) -> String {
        match self {
            #[cfg(feature = "v2")]
            OnionAddress::V2(a) => a.get_address_without_dot_onion(),
            #[cfg(feature = "v3")]
            OnionAddress::V3(a) => a.get_address_without_dot_onion(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, From, TryInto)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum TorPublicKey {
    #[cfg(feature = "v2")]
    V2(TorPublicKeyV2),
    #[cfg(feature = "v3")]
    V3(TorPublicKeyV3),
}