use std::io::Cursor;
use std::str::FromStr;

use crate::control::conn::Conn;
#[cfg(feature = "v2")]
use crate::onion::OnionAddressV2;
#[cfg(feature = "v3")]
use crate::onion::OnionAddressV3;
use crate::utils::{BASE32_ALPHA, block_on, unquote_string};

pub fn fuzz_unquote_string(data: &[u8]) {
    if let Ok(data) = std::str::from_utf8(data) {
        let (offset, _res) = unquote_string(data);
        if let Some(offset) = offset {
            assert_eq!(data.as_bytes()[offset], b'"');
        }
    }
}

#[cfg(feature = "control")]
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

#[cfg(feature = "v2")]
pub fn fuzz_deserialize_onion_address_v2_from_text(data: &[u8]) {
    if let Ok(data) = std::str::from_utf8(data) {
        let _ = OnionAddressV2::from_str(data);
    }
}

#[cfg(feature = "v3")]
pub fn fuzz_deserialize_onion_address_v3_from_text(data: &[u8]) {
    if let Ok(data) = std::str::from_utf8(data) {
        let _ = OnionAddressV3::from_str(data);
    }
}

#[cfg(feature = "v2")]
pub fn fuzz_base32_decode(data: &[u8]) {
    if let Ok(data) = std::str::from_utf8(data) {
        let _ = base32::decode(BASE32_ALPHA, data);
    }
}

#[cfg(feature = "v2")]
pub fn fuzz_base64_decode(data: &[u8]) {
    let _ = base64::decode(data);
}

// TODO(teawithsand): get some deserialization crate which is easy for fuzzer(bincode?) and fuzz deserialization of onion services
//  from serde
/*
pub fn fuzz_deserialize_onion_service_v2(data: &[u8]) {
}
*/