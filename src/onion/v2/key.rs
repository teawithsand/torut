use openssl::pkey::{Private, Public};

/// TorPublicKey describes onion service's public key V2(use to connect to onion service V2)
///
/// It can be used to derive `OnionAddressV2` but not vice versa.
///
/// # Key correctness
/// Key contained here is guaranteed to be valid RSA key according to
/// `openssl::rsa::RSA::check_key` fn
#[derive(Debug, Clone)]
#[derive(Into)]
pub struct TorPublicKeyV2(pub(crate) openssl::rsa::Rsa<Public>);

impl PartialEq for TorPublicKeyV2 {
    fn eq(&self, other: &Self) -> bool {
        // here it may not be constant time but we are comparing public keys
        // we may leak public key value(Note: It may compromise anonymity sometimes)
        self.0.e() == other.0.e() && self.0.n() == other.0.n()
    }
}

impl Eq for TorPublicKeyV2 {}

impl std::fmt::Display for TorPublicKeyV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let v = match self.0.public_key_to_pem() {
            Ok(v) => v,
            Err(_) => {
                return Err(std::fmt::Error {});
            }
        };

        debug_assert!(std::str::from_utf8(&v).is_ok(), "Failed to represent openssl's RSA key as PEM as utf8 string");

        write!(f, "TorPublicKeyV2({})", String::from_utf8_lossy(&v))
    }
}

/// TorSecretKey describes onion service's secret key v2(used to host onion service v2)
///
/// Underlying implementation uses openssl to represent it
///
/// # Key correctness
/// Key contained here is guaranteed to be valid RSA key according to
/// `openssl::rsa::RSA::check_key` fn
#[derive(Clone)]
pub struct TorSecretKeyV2(pub(crate) openssl::rsa::Rsa<Private>);

impl Eq for TorSecretKeyV2 {}

impl PartialEq for TorSecretKeyV2 {
    fn eq(&self, other: &Self) -> bool {
        // TODO it probably is not constant-time eq so may be unsafe under some circumstances
        // if rsa keys share same e and d they are same key
        // p and q influence d so no need to check them
        self.0.e() == other.0.e() && self.0.d() == other.0.d()
    }
}

impl TorSecretKeyV2 {
    pub fn generate() -> TorSecretKeyV2 {
        TorSecretKeyV2(openssl::rsa::Rsa::generate(1024).expect("Filed to generate RSA key with openssl"))
    }

    pub(crate) fn as_tor_proto_encoded(&self) -> String {
        base64::encode(
            &self.0.private_key_to_der()
                .expect("Filed to serialize TorSecretKeyV2 into private key der blob")
        )
    }

    pub fn public(&self) -> TorPublicKeyV2 {
        let mut n = openssl::bn::BigNum::new().expect("Filed to create big num");
        let mut e = openssl::bn::BigNum::new().expect("Filed to create big num");
        n = (&n) + self.0.n();
        e = (&e) + self.0.e();
        let key = <openssl::rsa::Rsa<Public>>::from_public_components(
            n,
            e,
        ).expect("Filed to construct RSA public key from private key's components");
        TorPublicKeyV2(key)
    }
}

impl std::fmt::Display for TorSecretKeyV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "TorSecretKeyV2(****)")
    }
}

impl std::fmt::Debug for TorSecretKeyV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "TorSecretKeyV2(****)")
    }
}