pub use key::*;
pub use onion::*;

mod key;
mod onion;

#[cfg(feature = "serialize")]
mod serde;

// TODO(teawithsand): implement fuzz for parsers for key and onion address