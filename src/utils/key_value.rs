/*
in fact this function is sequence of calls to `parse_single_key_value`
/// parse_key_value parses response in following format:
/// ```text
/// KEYWORD1=VALUE1
/// KEYWORD2=VALUE2
/// ...
/// ```
/// where keywords are A-Z ascii letters and value is either quoted string or just string.
pub fn parse_key_value() {}
*/

/// parse_single_key_value parses response in following format:
/// ```text
/// KEYWORD=VALUE
/// ...
/// ```
///
/// # Params
/// if `must_be_quoted` flag is set an error will be returned when string after equal sign is not quoted string
///
/// # Error
/// It returns an error:
/// - if there is no equal sign
/// - if data before equal sign is not `A-Za-z0-9_ -/$` ascii chars(notice space character)
/// - if value as quoted string enclosing quote is not last character of text
///
/// It *does not* return an error when key value is empty string so format is: `="asdf"`
///
/// # Example
/// ```
/// use torut::utils::parse_single_key_value;
/// assert_eq!(parse_single_key_value("KEY=VALUE"), Ok(("KEY", "VALUE")));
/// assert_eq!(parse_single_key_value("INVALID"), Err(()));
/// assert_eq!(parse_single_key_value("VALID="), Ok(("VALID", "")));
/// assert_eq!(parse_single_key_value("KEY=\"QUOTED VALUE\""), Ok(("KEY", "\"QUOTED VALUE\"")));
/// ```
pub fn parse_single_key_value(text: &str) -> Result<(&str, &str), ()>
{
    assert!(text.len() <= std::usize::MAX - 1, "too long string provided to `parse_single_key_value`"); // notice this `+ 1` next to key offset

    let mut key_offset = 0;
    for c in text.chars() {
        if c == '=' {
            break;
        }
        if c != ' ' && c != '-' && c != '_' && c != '/' && c != '$' && !c.is_ascii_alphanumeric() {
            return Err(());
        }
        key_offset += c.len_utf8();
    }
    if key_offset >= text.len() {
        return Err(()); // there is no equal sign
    }
    let key = &text[..key_offset];
    let value = &text[key_offset + 1..];
    /*

    let (offset, res) = unquote_string(&text[key_offset + 1..]);
    if must_be_quoted && offset.is_none() {
        return Err(());
    }
    if let Some(offset) = offset {
        if key_offset + 1 + offset != text.len() - 1 {
            return Err(()); // end quote is not last char of input text
        }
    }*/

    Ok((key, value))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_can_parse_single_key_value() {
        for (i, o) in [
            (
                "KEY=VALUE",
                Some(("KEY", "VALUE"))
            ),
            (
                "KEY=\"VALUE\"",
                Some(("KEY", "\"VALUE\""))
            ),
            (
                "KEY=Some\nMultiline\nValue\nIt\nHappens\nSometimes",
                Some(("KEY", "Some\nMultiline\nValue\nIt\nHappens\nSometimes")),
            )
        ].iter().cloned() {
            if let Some(o) = o {
                let (k, v) = o;
                let (key, res) = parse_single_key_value(i).unwrap();
                assert_eq!(key, k);
                assert_eq!(res, v);
            } else {
                let _ = parse_single_key_value(i).unwrap_err();
            }
        }
    }
}