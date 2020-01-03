//! Control module implements all the utilities required to talk to tor instance
//! and to give it some orders or get some info form it.

pub use conn::*;
pub use primitives::*;

mod primitives;
mod conn;
