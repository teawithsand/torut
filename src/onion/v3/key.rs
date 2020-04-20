use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, SignatureError};
use rand::thread_rng;

use crate::utils::BASE32_ALPHA;

/// Standardises usage of Tor V3 public keys, which is 32 bytes
/// (equal to Ed25519 public key length)
pub const TORV3_PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Standardises usage of Tor V3 secret keys, which is 65 bytes
/// (equal to Ed25519 extended secret key length)
pub const TORV3_SECRET_KEY_LENGTH: usize = ed25519_dalek::EXPANDED_SECRET_KEY_LENGTH;

/// TorPublicKeyV3 describes onion service's public key(use to connect to onion service)
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TorPublicKeyV3(pub(crate) [u8; TORV3_PUBLIC_KEY_LENGTH]);

impl TorPublicKeyV3 {
    /// Convert this Tor public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; TORV3_PUBLIC_KEY_LENGTH] {
        self.0
    }

    /// View this Tor public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; TORV3_PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// Constructs Tor public key from a byte sequence, checking the validity
    /// of the byte sequence as Ed25519 public key, and returning appropriate
    /// error if the sequence does not represent a valid key.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate torut;
    /// #
    /// use torut::onion::TorPublicKeyV3;
    /// use ed25519_dalek::SignatureError;
    ///
    /// # fn doctest() -> Result<TorPublicKeyV3, SignatureError> {
    /// let public_key_bytes: [u8; 32] = [
    ///    215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
    ///     14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
    ///
    /// let public_key = TorPublicKeyV3::from_bytes(&public_key_bytes)?;
    /// #
    /// # Ok(public_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     doctest();
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is a valid `TorPublicKeyV3` or whose error
    /// value is a `ed25519_dalek::SignatureError` describing the error that
    /// occurred. It will be either:
    /// * `InternalError::BytesLengthError`
    /// * `InternalError::PointDecompressionError`
    #[inline]
    pub fn from_bytes(bytes: &[u8; TORV3_PUBLIC_KEY_LENGTH]) -> Result<TorPublicKeyV3, SignatureError> {
        PublicKey::from_bytes(bytes).map(|_pk| TorPublicKeyV3(bytes.clone()))
    }
}

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
pub struct TorSecretKeyV3([u8; TORV3_SECRET_KEY_LENGTH]);

impl Eq for TorSecretKeyV3 {}

impl PartialEq for TorSecretKeyV3 {
    // is non constant time eq fine here?
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(other.0.iter()).all(|(b1, b2)| *b1 == *b2)
    }
}

impl TorSecretKeyV3 {
    pub(crate) fn as_tor_proto_encoded(&self) -> String {
        base64::encode(&self.0[..])
    }

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