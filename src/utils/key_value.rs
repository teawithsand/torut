/// parse_single_key_value parses response in following format:
/// ```text
/// KEYWORD=VALUE
/// ...
/// ```
///
/// # Error
/// It returns an error:
/// - if there is no equal sign
/// - if data before equal sign is not `A-Za-z0-9_ -/$` ascii chars(notice space character)
/// - if value is quoted string and enclosing quote is not last character of text
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
                "$KE$Y=VALUE",
                Some(("$KE$Y", "VALUE"))
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