use std::borrow::Cow;
use std::iter;
use std::string::FromUtf8Error;

use crate::utils::octal_ascii_triple_to_byte;

#[derive(Debug, From)]
pub struct UnquoteStringError {
    pub error: FromUtf8Error
}

impl Into<Vec<u8>> for UnquoteStringError {
    fn into(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl UnquoteStringError {
    pub fn into_bytes(self) -> Vec<u8> {
        self.error.into_bytes()
    }
}

/// unquote_string performs string unquoting
/// According to torCP docs it parses `QuotedString` token.
///
/// # Note
/// In order to be quoted text MUST start with '"' char(no white chars allowed).
///
/// # When quoted?
/// String is considered quoted when it starts with quote and contains at least one unescaped quote after first one.
/// Please note that above implies that first 3 chars out of 100 char string may be used to construct it.
///
/// # Return value
/// If string is not quoted or no escape sequences are in use borrowed cow is returned.
/// If quoted string does not use any escape sequences borrowed cow is returned.
/// If string uses escape sequences which give valid utf8 string owned cow is returned.
/// If quoted string is longer than entire text
/// Otherwise error is returned
/// This function does not if content of quotes is valid utf8/is single line or if it does contains any sequence considered as
/// invalid when looking at standard this implies that return value MAY
/// contain non-ascii chars OR zero bytes. It's caller responsibility to filter them if needed.
///
/// Second returned offset(first returned one) value is `Some` only when string is quoted. It returns byte offset of last char consumed in string unquoting.
/// Using `text.as_bytes()[idx]` where idx is given value should yield '"' char.
pub fn unquote_string(text: &str) -> (Option<usize>, Result<Cow<str>, UnquoteStringError>) {
    // as the docs says:
    // The format is:
    // RFC 2822(not all ofc. Some random things needed to interpret the specification)
    // -----
    // qtext           =       NO-WS-CTL /     ; Non white space controls
    //
    //                         %d33 /          ; The rest of the US-ASCII
    //                         %d35-91 /       ;  characters not including "\"
    //                         %d93-126        ;  or the quote character
    //
    // qcontent        =       qtext / quoted-pair
    // quoted-pair     =       ("\" text) / obs-qp
    // obs-qp          =       "\" (%d0-127)
    // -----
    // (Note: I guess text is a-zA-Z0-9)
    // And from torCP spec:
    // DQUOTE is this thing in the middle: ---> " <---
    // QuotedString = DQUOTE *qcontent DQUOTE
    //
    //
    // "All 8-bit characters are permitted unless explicitly disallowed. In QuotedStrings,
    // backslashes and quotes must be escaped; other characters need not be
    // escaped."

    // quoted printable rules are simple:
    //  "For future-proofing, controller implementors MAY use the following
    //  rules to be compatible with buggy Tor implementations and with
    //  future ones that implement the spec as intended:
    //    Read \n \t \r and \0 ... \377 as C escapes.
    //    Treat a backslash followed by any other character as that character."
    if text.len() == 0 {
        return (None, Ok(Cow::Borrowed(&text[..0])));
    }
    if text.len() >= 2 {
        let end_of_quoted_string = {
            let mut is_ignored = false;
            let mut idx = 0;
            let mut found = false;
            // first one is our first quote(at least potentially) anyway - it can't be last quote
            for c in text.chars().skip(1) {
                if !is_ignored {
                    if c == '\\' {
                        is_ignored = true;
                    } else if c == '"' {
                        // we found it! first unquoted quote!
                        idx += c.len_utf8();
                        found = true;
                        break;
                    }
                } else {
                    is_ignored = false;
                }
                idx += c.len_utf8();
            }
            if found {
                debug_assert!(text.as_bytes()[idx] == b'"');
                Some(idx)
            } else {
                None
            }
        };
        return if text.as_bytes()[0] == b'\"' && end_of_quoted_string.is_some() {
            let end_of_quoted_string = end_of_quoted_string.unwrap();

            let text = &text[1..end_of_quoted_string];
            if text.chars().all(|c| c != '\\') {
                // no escape sequences!
                // just return value
                return (Some(end_of_quoted_string), Ok(Cow::Borrowed(&text[..])));
            }
            // just put escape seqs to vec and then create string
            let mut res = Vec::new();
            let mut is_escaped = false;

            let mut escaped_char_buf = [0u8; 3];
            let mut escaped_char_buf_sz = 0;
            // eprintln!("Unquoting: {:?}", text);
            for c in text.chars() {
                let mut char_to_process = Some(c);
                while let Some(c) = char_to_process.take() {
                    // eprintln!("Got char: {:?}", c);

                    if is_escaped {
                        if escaped_char_buf_sz == 0 {
                            match c {
                                'n' => res.push(b'\n'),
                                't' => res.push(b'\t'),
                                'r' => res.push(b'\r'),
                                '"' => res.push(b'\"'),
                                '\\' => res.push(b'\\'),
                                c if c.is_ascii_digit() => {
                                    // put char into escaped buffer and go to another iteration of loop
                                    escaped_char_buf[0] = c as u8;
                                    escaped_char_buf_sz += 1;
                                    continue;
                                }
                                c => {
                                    // put char as-is
                                    res.extend(iter::repeat(0).take(c.len_utf8()));
                                    let len = res.len();
                                    c.encode_utf8(&mut res[len - c.len_utf8()..]);
                                }
                            }
                        } else {

                            // another octal digit
                            if c.is_ascii_digit() && /*is valid octal digit*/ (c as u8 - b'0') <= 7 && escaped_char_buf_sz < 3 {
                                escaped_char_buf[escaped_char_buf_sz] = c as u8;
                                escaped_char_buf_sz += 1;
                                continue;
                            } else {
                                // current char was not processed
                                // reschedule it to process
                                char_to_process = Some(c);

                                // note: this code is copy pasted below
                                // consider fixing it as well when fixing this part

                                // rotate buf in case there is less than required amount of chars
                                // so [1 0 0] sz = 1 becomes [0 0 1]
                                let len = escaped_char_buf.len();
                                escaped_char_buf.rotate_right(len - escaped_char_buf_sz);
                                // eprintln!("Triple to byte: {:?}", escaped_char_buf);
                                if let Some(v) = octal_ascii_triple_to_byte(escaped_char_buf) {
                                    // eprintln!("success: {}", v);

                                    res.push(v);
                                } else {
                                    // eprintln!("failed: {:?}", escaped_char_buf);

                                    // push it as raw(not decoded) value without first char
                                    // as if backslash was ignored
                                    res.extend_from_slice(&escaped_char_buf[..escaped_char_buf_sz]);
                                }
                            }
                        }
                        escaped_char_buf = [0u8; 3];
                        escaped_char_buf_sz = 0;
                        is_escaped = false;
                    } else {
                        if c == '\\' {
                            is_escaped = true;
                        }
                        // we have handled all quotes before
                        /* else if c == '\"' {
                            // apparently end of quoted string!
                            break;
                        } */ else {
                            res.extend(iter::repeat(0).take(c.len_utf8()));
                            let len = res.len();
                            c.encode_utf8(&mut res[len - c.len_utf8()..]);
                        }
                    }
                }
            }
            if escaped_char_buf_sz > 0 {
                // eprintln!("Found one more octet(at least potential) to process!");

                // TODO(teawithsand): clean it up. This is copy paste from above code processing octets.
                let len = escaped_char_buf.len();
                escaped_char_buf.rotate_right(len - escaped_char_buf_sz);
                // eprintln!("Triple to byte: {:?}", escaped_char_buf);
                if let Some(v) = octal_ascii_triple_to_byte(escaped_char_buf) {
                    // eprintln!("success: {}", v);

                    res.push(v);
                } else {
                    // eprintln!("failed: {:?}", escaped_char_buf);

                    // push it as raw(not decoded) value without first char
                    // as if backslash was ignored
                    res.extend_from_slice(&escaped_char_buf[..escaped_char_buf_sz]);
                }
            }
            // eprintln!("RES: {:?}", res);
            let res = String::from_utf8(res)
                .map(|v| Cow::Owned(v))
                .map_err(|e| UnquoteStringError::from(e));
            (Some(end_of_quoted_string), res)
        } else {
            (None, Ok(Cow::Borrowed(&text[..])))
        };
    }
    // ofc single char text can't be quoted string
    (None, Ok(Cow::Borrowed(&text[..])))
}

/// quote_string takes arbitrary binary data and encodes it using octal encoding.
/// For \n \t and \r it uses these backslash notation rather than octal encoding.
///
/// It's reverse function to `unquote_string`.
/// According to torCP docs it creates `QuotedString` token.
///
/// # Example
/// ```
/// use torut::utils::quote_string;
/// assert_eq!(quote_string(b"asdf"), r#""asdf""#);
/// assert_eq!(quote_string("ŁŁ".as_bytes()), r#""\305\201\305\201""#);
/// assert_eq!(quote_string("\n\r\t".as_bytes()), r#""\n\r\t""#);
/// assert_eq!(quote_string("\0\0\0".as_bytes()), r#""\0\0\0""#);
/// ```
pub fn quote_string(text: &[u8]) -> String {
    // res won't be shorter than text ever
    let mut res = String::with_capacity(text.len());
    res.push('\"');
    for b in text.iter().copied() {
        match b {
            b'\n' => res.push_str("\\n"),
            b'\r' => res.push_str("\\r"),
            b'\t' => res.push_str("\\t"),
            b'\\' => res.push_str("\\\\"),
            b'"' => res.push_str("\\\""),
            b if b.is_ascii_alphanumeric() || b.is_ascii_punctuation() => {
                res.push(b as char);
            }
            b => {
                res.push('\\');
                // oct encode given char
                let mut b = b;
                let mut digit_count = 0;
                let mut digits = [0u8; 3];
                if b > 0 {
                    while b > 0 {
                        digits[digit_count] = b % 8;
                        b = b / 8;
                        digit_count += 1;
                    }
                } else {
                    // null byte is \0 but above algo won't find it out
                    digit_count = 1;
                }
                debug_assert!(digit_count >= 1);
                for d in digits.iter().take(digit_count).rev() {
                    res.push((*d + b'0') as char);
                }
            }
        }
    }
    res.push('\"');
    res
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_can_quote_and_unquote_string() {
        for input in [
            "asdf",
            "\0\0\0\0",
            "ŁŁŁ",
            r#"""""#,
            "\n\t\r",
        ].iter().cloned() {
            assert_eq!(
                input,
                unquote_string(&quote_string(input.as_bytes())).1.unwrap().as_ref()
            )
        }
    }

    #[test]
    fn test_can_unquote_string() {
        for (input, output) in [
            ("not quoted string", (None, Ok("not quoted string"))),
            ("\"and a quoted one\"", (Some(17), Ok("and a quoted one"))),
            ("\"esc backslash \\\\ \"", (Some(18), Ok("esc backslash \\ "))),
            (r#""\0\0\0\0\213\321\3\123\312\31\221\312""#, (
                Some(38),
                Err(&[0u8, 0, 0, 0, 0o213, 0o321, 0o3, 0o123, 0o312, 0o31, 0o221, 0o312] as &[u8])
            )),
            (r#""\0\0\0\0\213\321\3\123\312\31\221\31""#, (
                Some(37),
                Err(&[0u8, 0, 0, 0, 0o213, 0o321, 0o3, 0o123, 0o312, 0o31, 0o221, 0o31] as &[u8])
            )),
            (r#""\0\0\0\0\213\321\3\123\312\31\221\3""#, (
                Some(36),
                Err(&[0u8, 0, 0, 0, 0o213, 0o321, 0o3, 0o123, 0o312, 0o31, 0o221, 0o3] as &[u8])
            )),
            ("\"q\\\"q\"", (Some(5), Ok("q\"q"))),
            ("\"first\"\"second\"", (Some(6), Ok("first"))),
        ].iter().cloned() {
            let (expected_offset, expected_value) = output;
            let (offset, value) = unquote_string(input);
            let value = value.map_err(|e| e.into_bytes());
            assert_eq!(offset, expected_offset);
            assert_eq!(
                value
                    .as_ref()
                    .map(|v| v.as_ref())
                    .map_err(|e| e.as_ref()),
                expected_value
            );
        }
    }
}