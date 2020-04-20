use std::borrow::Cow;
use std::collections::HashSet;
use std::str::FromStr;
use std::io::Read;

/// TorAuthMethod describes method which tor accepts as authentication method
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum TorAuthMethod {
    /// Null - no authentication. Just issue authenticate command to be authenticated
    Null,

    /// In order to authenticate password is required
    HashedPassword,

    /// Cookie file has to be read in order to authenticate
    Cookie,

    /// CookieFile has to be read and hashes with both server's and client's nonce has to match on server side.
    /// This way evil server won't be able to copy response and act as an evil proxy
    SafeCookie,
}

impl FromStr for TorAuthMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let val = match s {
            "NULL" => TorAuthMethod::Null,
            "HASHEDPASSWORD" => TorAuthMethod::HashedPassword,
            "COOKIE" => TorAuthMethod::Cookie,
            "SAFECOOKIE" => TorAuthMethod::SafeCookie,
            _ => {
                return Err(());
            }
        };
        Ok(val)
    }
}

/// Length of tor cookie in bytes.
/// Tor cookies have fixed length
pub const COOKIE_LENGTH: usize = 32;

/// TorPreAuthInfo contains info which can be received from tor process before authentication
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct TorPreAuthInfo<'a> {
    pub tor_version: Cow<'a, str>,
    pub auth_methods: HashSet<TorAuthMethod>,
    // for any modern os path is valid string. No need for base64-decode it or something like that.
    pub cookie_file: Option<Cow<'a, str>>,
}

impl<'a> TorPreAuthInfo<'a> {
    /// make_auth_data is best-intent function which tries to create authentication data for given tor instance using data contained in 
    /// TorPreAuthInfo. 
    /// 
    /// For most usages it's the one which should be used rather than constructing data manually.
    /// Exception here is password auth.
    /// 
    /// # Reading files
    /// If `Cookie` or `SafeCookie` auth is allowed this function may read cookie file(depending on availability of null auth).
    /// It reads cookie from random path specified by `cookie_file`.
    /// It reads exactly `COOKIE_LENGTH` bytes always.
    /// 
    /// # Returns
    /// It returns `Ok(None)` when make_auth_data is not able to use any authentication method which does not require any additional programmer care.
    /// Example of such method which requires care is HashedPassword. It can't be automated by design.
    /// 
    /// It returns `std::io::Error` when reading cookiefile fails.
    pub fn make_auth_data(&self) -> Result<Option<TorAuthData<'static>>, std::io::Error> {
        if self.auth_methods.contains(&TorAuthMethod::Null) {
            Ok(Some(TorAuthData::Null))
        } else if self.auth_methods.contains(&TorAuthMethod::SafeCookie) && self.cookie_file.is_some() {
            let mut f = std::fs::File::open(self.cookie_file.as_ref().unwrap().as_ref())?;
            let mut buffer = Vec::new();
            buffer.resize(COOKIE_LENGTH, 0u8);
            f.read_exact(&mut buffer[..])?;

            Ok(Some(TorAuthData::Cookie(Cow::Owned(buffer))))
        } else if self.auth_methods.contains(&TorAuthMethod::Cookie) && self.cookie_file.is_some() {
            let mut f = std::fs::File::open(self.cookie_file.as_ref().unwrap().as_ref())?;
            let mut buffer = Vec::new();
            buffer.resize(COOKIE_LENGTH, 0u8);
            f.read_exact(&mut buffer[..])?;

            Ok(Some(TorAuthData::Cookie(Cow::Owned(buffer))))
        } else {
            Ok(None)
        }
    }
}

// TODO(teawithsand): test make_auth_data without tor

/// TorAuthData contains all data required to authenticate single `UnauthenticatedConn`
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum TorAuthData<'a> {
    /// null auth in fact does not require any data.
    /// # Security note
    /// Please note that in some cases this may cause secirity issue.
    /// It should be NEVER used.
    Null,

    /// Password auth requires password
    HashedPassword(Cow<'a, str>),

    /// Cookie authentication requires contents of cookie
    Cookie(Cow<'a, [u8]>),

    /// In fact it requires the same input as cookie but the procedure is different.
    /// Note: It should be preferred over cookie when possible.
    SafeCookie(Cow<'a, [u8]>),
}

impl<'a> TorAuthData<'a> {
    pub fn get_method(&self) -> TorAuthMethod {
        match self {
            TorAuthData::Null => TorAuthMethod::Null,
            TorAuthData::HashedPassword(_) => TorAuthMethod::HashedPassword,
            TorAuthData::Cookie(_) => TorAuthMethod::Cookie,
            TorAuthData::SafeCookie(_) => TorAuthMethod::SafeCookie,
        }
    }
}

// testing is in unauthenticated conn rs