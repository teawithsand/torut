use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey};
use rand::thread_rng;

use crate::utils::BASE32_ALPHA;

/// TorPublicKeyV3 describes onion service's public key(use to connect to onion service)
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TorPublicKeyV3(pub(crate) [u8; 32]);

impl std::fmt::Debug for TorPublicKeyV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "TorPublicKey({})", base32::encode(BASE32_ALPHA, &self.0))
    }
}

impl std::fmt::Display for TorPublicKeyV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "TorPublicKey({})", base32::encode(BASE32_ALPHA, &self.0))
    }
}

// TODO(teawithsand): Add memory zeroing on drop
/// TorSecretKeyV3 describes onion service's secret key(used to host onion service)
/// In fact it can be treated as keypair because public key may be derived from secret one quite easily.
///
/// It uses expanded secret key in order to support importing existing keys from tor.
#[derive(Clone)]
#[repr(transparent)]
#[derive(From, Into)]
pub struct TorSecretKeyV3([u8; 64]);

impl Eq for TorSecretKeyV3 {}

impl PartialEq for TorSecretKeyV3 {
    // is non constant time eq fine here?
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(other.0.iter()).all(|(b1, b2)| *b1 == *b2)
    }
}

impl TorSecretKeyV3 {
    /// generate generates new `TorSecretKeyV3`
    pub fn generate() -> Self {
        let sk: SecretKey = SecretKey::generate(&mut thread_rng());
        let esk = ExpandedSecretKey::from(&sk);
        TorSecretKeyV3(esk.to_bytes())
    }

    /// creates `TorPublicKeyV3` from this secret key
    pub fn public(&self) -> TorPublicKeyV3 {
        let esk = ExpandedSecretKey::from_bytes(&self.0).expect("Invalid secret key contained");
        TorPublicKeyV3(PublicKey::from(&esk).to_bytes())
    }

    pub fn as_bytes(&self) -> [u8; 64] {
        self.0.clone()
    }

    pub fn into_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl std::fmt::Display for TorSecretKeyV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "TorSecretKey(****)")
    }
}

impl std::fmt::Debug for TorSecretKeyV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "TorSecretKey(****)")
    }
}

/*
impl Drop for TorSecretKeyV3 {
    fn drop(&mut self) {
        zero_memory(&mut self.0[..]);
    }
}
*/