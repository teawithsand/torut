//! Onion module implements all utilities required to work with onion addresses version three
//! Support for these may be enabled using cargo features.

#[cfg(any(feature = "v3"))]
pub use common::*;
#[cfg(feature = "v3")]
pub use v3::*;
#[cfg(feature = "v3")]
mod v3;

#[cfg(feature = "v3")]
mod common;

