//! Torut implements tor control protocol [described here](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)
//!
//! Right now torut does not implement all methods but it gives access to raw calls so you can use it.
//! If something does not work or you would like to see some functionality implemented by design open an issue or PR.
//!
//! # Usage security
//! Take a look at security considerations section of `README.MD`

#![forbid(unsafe_code)]

#[macro_use]
extern crate derive_more;
#[cfg(feature = "serialize")]
#[macro_use]
extern crate serde_derive;

pub mod onion;

#[cfg(feature = "control")]
pub mod control;

pub mod utils;

#[cfg(fuzzing)]
pub mod fuzz;