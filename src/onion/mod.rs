//! Onion module implements all utilities required to work with onion addresses both version two and three
//! Support for these may be enabled using cargo features.
//!
//! Note: right now it uses openssl for `v2` key generation and serialization
//! If there would be a library mature capable of both RSA 1024 key generation and (de)serialization.

// #[cfg(all(feature = "v2", feature = "v3"))]
// pub use builder::*;

#[cfg(any(feature = "v2", feature = "v3"))]
pub use common::*;
#[cfg(feature = "v2")]
pub use v2::*;
#[cfg(feature = "v3")]
pub use v3::*;

#[cfg(feature = "v2")]
#[deprecated(
    since = "0.1.10",
    note = "V2 onion services are deprecated by tor and soon will stop working; It will be removed in next release"
)]
mod v2;

#[cfg(feature = "v3")]
mod v3;


/*
#[cfg(all(feature = "v2", feature = "v3"))]
mod builder;
*/

#[cfg(any(feature = "v2", feature = "v3"))]
mod common;

