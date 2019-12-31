//! Onion module implements all utilities required to work with onion addresses both version two and three
//! Support for these may be enabled using cargo features.
//!
//! Note: right now it uses openssl for `v2` key generation and serialization
//! If there would be a library mature capable of both RSA 1024 key generation and (de)serialization.

// TODO(teawithsand): move common and builder stuff to require not both v2 and v3 but one of v2 and v3

#[cfg(all(feature = "v2", feature = "v3"))]
pub use builder::*;
#[cfg(any(feature = "v2", feature = "v3"))]
pub use common::*;
#[cfg(feature = "v2")]
pub use v2::*;
#[cfg(feature = "v3")]
pub use v3::*;

#[cfg(feature = "v2")]
mod v2;

#[cfg(feature = "v3")]
mod v3;


#[cfg(all(feature = "v2", feature = "v3"))]
mod builder;

#[cfg(any(feature = "v2", feature = "v3"))]
mod common;

