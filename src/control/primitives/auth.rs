use std::borrow::Cow;
use std::collections::HashSet;

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