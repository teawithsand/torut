/// BASE32_ALPHA to use when encoding base32 stuff
pub const BASE32_ALPHA: base32::Alphabet = base32::Alphabet::RFC4648 {
    padding: false,
};