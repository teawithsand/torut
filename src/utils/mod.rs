use std::future::Future;

pub use key_value::*;
pub use quoted::*;
#[cfg(testtor)]
pub use testing::*;

/// block_on creates tokio runtime for testing
#[cfg(any(test, fuzzing))]
pub(crate) fn block_on<F, O>(f: F) -> O
    where F: Future<Output=O>
{
    use tokio::*;
    let mut rt = runtime::Builder::new()
        .basic_scheduler() // single threaded one
        .build()
        .unwrap();
    rt.block_on(f)
}


#[cfg(any(test, fuzzing))]
pub(crate) fn block_on_with_env<F, O>(f: F) -> O
    where F: Future<Output=O>
{
    use tokio::*;
    let mut rt = runtime::Builder::new()
        .enable_all()
        .basic_scheduler() // single threaded one
        .build()
        .unwrap();
    rt.block_on(f)
}

/// is_valid_keyword checks if given text is valid tor keyword for functions like `GETCONF` or `SETCONF`
///
/// Note: this function was not tested against torCP but it's simple and robust and should work.
pub(crate) fn is_valid_keyword(config_option: &str) -> bool {
    if config_option.is_empty() {
        return false;
    }
    for c in config_option.chars() {
        if !c.is_ascii_uppercase() && c != '_' {
            return false;
        }
    }
    true
}

/// BASE32_ALPHA to use when encoding base32 stuff
pub(crate) const BASE32_ALPHA: base32::Alphabet = base32::Alphabet::RFC4648 {
    padding: false,
};

/// octal_ascii_triple_to_byte converts three octal ascii chars to single byte
/// `None` is returned if any char is not valid octal byte OR value is greater than byte
pub(crate) fn octal_ascii_triple_to_byte(data: [u8; 3]) -> Option<u8> {
    // be more permissive. Allow non-ascii digits AFTER ascii digit sequence
    /*
    if data.iter().copied().any(|c| c < b'0' || c > b'7') {
        return None;
    }
    */
    let mut res = 0;
    let mut pow = 1;
    let mut used_any = false;

    for b in data.iter().copied().rev() {
        if b < b'0' || b > b'7' {
            break;
        }
        used_any = true;
        let b = b as u16;
        res += (b - ('0' as u16)) * pow;
        pow *= 8;
    }

    if !used_any || res > std::u8::MAX as u16 {
        return None;
    }
    return Some(res as u8);
}

mod quoted;
mod key_value;
#[cfg(testtor)]
mod testing;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_can_decode_octal_ascii_triple() {
        for (i, o) in [
            (b"\0\00", Some(0)),
            (b"123", Some(83)),
            (&[0u8, 0, 48], Some(0)),
            (&[50u8, 49, 51], Some(139)),
        ].iter().cloned() {
            assert_eq!(octal_ascii_triple_to_byte(*i), o);
        }
    }
}
