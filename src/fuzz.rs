use std::io::Cursor;

use crate::control::conn::Conn;
use crate::utils::{block_on, unquote_string};

pub fn fuzz_unquote_string(data: &[u8]) {
    if let Ok(data) = std::str::from_utf8(data) {
        let (offset, _res) = unquote_string(data);
        if let Some(offset) = offset {
            assert_eq!(data.as_bytes()[offset], b'"');
        }
    }
}

/// Note: in order to run this fuzz fn modify cargo.toml to include full tokio(with runtime)
/// Right now rufuzz.py does not fetches dev dependencies for fuzzing
pub fn fuzz_conn_parse_response(data: &[u8]) {
    block_on(async move {
        let mut s = Cursor::new(data);
        let mut c = Conn::new(s);
        if let Ok((code, data)) = c.receive_data().await {
            assert!(code >= 0 && code <= 999);
        }
    });
}