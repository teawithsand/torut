use std::io;
use std::num::ParseIntError;
use std::str::{FromStr, Utf8Error};
use std::string::FromUtf8Error;

use tokio::prelude::*;

/// ConnError is able to wrap any error that a connection may return
#[derive(Debug, From)]
pub enum ConnError {
    IOError(io::Error),
    Utf8Error(Utf8Error),
    FromUtf8Error(FromUtf8Error),
    ParseIntError(ParseIntError),

    InvalidFormat,
    InvalidCharacterFound,
    NonAsciiByteFound,
    ResponseCodeMismatch,

    TooManyBytesRead,
}

/// Conn wraps any `AsyncRead + AsyncWrite` stream and implements parsing responses from tor and sending data to it.
///
/// It's stateless component. It does not contain any information about connection like authentication state.
///
/// # Note
/// This is fairly low-level connection which does only basic parsing.
/// Unless you need it you should use higher level apis.
pub struct Conn<S> {
    stream: S
}

impl<S> Conn<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

/// MAX_SINGLE_RECV_BYTES describes how many bytes may be received during single call to `receive_data`
/// It's used to prevent DoS(OOM allocating).
const MAX_SINGLE_RECV_BYTES: usize = 1024 * 1024 * 1;// 1MB

impl<S> Conn<S>
    where S: AsyncRead + Unpin
{
    /// receive_data receives single response from tor
    ///
    /// # Response format
    /// Rather than grouping response by lines sent on proto it groups it on "lines" returned by tor.
    /// Take a look at tests to see what's going on. Basically all multiline mode data is put into one string despite
    /// the fact that it may contain multiple lines.
    ///
    /// # Performance considerations
    /// This function allocates all stuff and does not allow writing to any preallocated buffer.
    /// It neither does not allow for any kind of borrowing from one big buffer.
    ///
    /// Personally I think it's not needed. It's tor api how many data you want receive from it?
    /// Anyway this won't be ran on any embedded device(because it has to be able to run tor, it has to run at least some
    /// linux so I probably can allocate a few strings on it...)
    ///
    /// # Possible performance issues
    /// It uses byte-by-byte reading. Thanks to this feature there is no state in `Conn` struct.
    /// Use some sort of buffered reader in order to minimize overhead.
    pub async fn receive_data(&mut self) -> Result<(u16, Vec<String>), ConnError> {
        // ok. let's first think about the format.
        // it's rather simple
        // docs: https://gitweb.torproject.org/torspec.git/tree/control-spec.txt
        // 1. Each line consists of code and data(unless in "multiline read mode")
        // 2. Code in each line is same.
        // 3. Response is done after reaching line with `XXX DDD...` where XXX is code and DDD is arbitrary data
        // 4. Multiline responses are created with `XXX-DDD` where XXX is code and DDD is arbitrary data
        // 5. So called(at least I call it) "multiline mode" can be enabled with `XXX+DDD[\r\nDDD]..\r\n.\r\n`
        //    where XXX is code and DDD are arbitrary data blocks. It's done once single blank line with dot is found.

        let mut lines = Vec::new();
        let mut response_code = None;

        let mut state = 0;

        let mut current_line_buffer = Vec::new();
        let mut bytes_read = 0;
        loop {
            if bytes_read >= MAX_SINGLE_RECV_BYTES {
                return Err(ConnError::TooManyBytesRead);
            }
            let b = {
                let mut buf = [0u8; 1];
                self.stream.read_exact(&mut buf[..]).await?;
                buf[0]
            };

            bytes_read += 1;

            // is this check valid?
            // is all data valid ascii?
            if !b.is_ascii() {
                return Err(ConnError::NonAsciiByteFound);
            }

            if state == 0 {
                if !b.is_ascii_digit() {
                    return Err(ConnError::InvalidCharacterFound);
                }
                current_line_buffer.push(b);

                // we found response code!
                if current_line_buffer.len() == 3 {
                    let text = std::str::from_utf8(&current_line_buffer)?;
                    let parsed_response_code = u16::from_str(text)?;
                    if let Some(response_code) = response_code {
                        if response_code != parsed_response_code {
                            return Err(ConnError::ResponseCodeMismatch);
                        }
                    } else {
                        response_code = Some(parsed_response_code);
                    }
                    state = 1;
                    current_line_buffer.clear();
                }
            } else if state == 1 {
                debug_assert!(current_line_buffer.is_empty());
                debug_assert!(response_code.is_some());
                match b {
                    // last line
                    b' ' => {
                        state = 2;
                    }
                    // some of many lines
                    b'-' => {
                        state = 3;
                    }
                    // multiline mode trigger
                    b'+' => {
                        state = 4;
                    }
                    // other characters are not allowed
                    b @ _ => {
                        return Err(ConnError::InvalidCharacterFound);
                    }
                }
            } else if state == 2 || state == 3 {
                // as the docs says:
                // Tor, however, MUST NOT generate LF instead of CRLF.
                current_line_buffer.push(b);
                if current_line_buffer.len() >= 2 &&
                    current_line_buffer[current_line_buffer.len() - 2] == b'\r' &&
                    current_line_buffer[current_line_buffer.len() - 1] == b'\n'
                {
                    current_line_buffer.truncate(current_line_buffer.len() - 2);

                    let res = {
                        let mut line_buffer = Vec::new();
                        std::mem::swap(&mut current_line_buffer, &mut line_buffer);
                        String::from_utf8(line_buffer)
                    };
                    // only valid ascii remember?
                    // if so it's valid utf8
                    debug_assert!(res.is_ok());
                    let text = res?;
                    lines.push(text);

                    // if it's last line break loop
                    if state == 2 {
                        break;
                    } else {
                        state = 0;
                    }
                }
            } else if state == 4 {
                // multiline read mode reads lines until it eventually found \r\n.\r\n sequence
                current_line_buffer.push(b);
                if current_line_buffer.len() >= 5 &&
                    current_line_buffer[current_line_buffer.len() - 5] == b'\r' &&
                    current_line_buffer[current_line_buffer.len() - 4] == b'\n' &&
                    current_line_buffer[current_line_buffer.len() - 3] == b'.' &&
                    current_line_buffer[current_line_buffer.len() - 2] == b'\r' &&
                    current_line_buffer[current_line_buffer.len() - 1] == b'\n'
                {
                    current_line_buffer.truncate(current_line_buffer.len() - 5);

                    let res = {
                        let mut line_buffer = Vec::new();
                        std::mem::swap(&mut current_line_buffer, &mut line_buffer);
                        String::from_utf8(line_buffer)
                    };

                    // only valid ascii remember?
                    // if so it's valid utf8
                    debug_assert!(res.is_ok());
                    let text = res?;
                    lines.push(text);

                    // there may be more lines incoming after this one
                    state = 0;
                }
            } else {
                unreachable!("Invalid state!");
            }
        }
        if response_code.is_none() {
            return Err(ConnError::InvalidFormat);
        }
        return Ok((response_code.unwrap(), lines));
    }
}

impl<S> Conn<S> where S: AsyncWrite + Unpin {
    /// write_data writes *RAW* data into tor controller and flushes stream
    pub async fn write_data(&mut self, data: &[u8]) -> Result<(), ConnError> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use crate::utils::block_on;

    use super::*;

    #[test]
    fn test_conn_can_read_response() {
        for (input, output) in [
            ("250 Ok line one\r\n", Some((250u16, vec!["Ok line one"]))),
            ("250-L1\r\n250 L2\r\n", Some((250, vec!["L1", "L2"]))),
            ("250-LANDER=MAAR\r\n250 L2\r\n", Some((250, vec!["LANDER=MAAR", "L2"]))),
            ("250-default\r\n250 key=value\r\n", Some((250, vec!["default", "key=value"]))),
            ("250-abc\r\n250+abcd\r\n second line\r\n.\r\n250 OK\r\n", Some((250, vec!["abc", "abcd\r\n second line", "OK"]))),
            ("250-abc\r\n250+abcd\r\n second line\r\n.\r\n250 OK", None),
            ("250-abc\r\n250+abcd\r\n second line\r\n.\r\n", None),
            ("250-abc\r\n250+abcd\r\n second line", None),
        ].iter().cloned() {
            // eprintln!("{:?} -> {:?}", input, output);
            block_on(async move {
                let mut cursor = Cursor::new(Vec::from(input));
                let mut conn = Conn::new(&mut cursor);
                if let Some((valid_code, valid_res)) = output {
                    let (given_code, given_res) = conn.receive_data().await.unwrap();
                    assert_eq!(valid_code, given_code);
                    let res2_ref = given_res.iter().map(|s| s as &str).collect::<Vec<_>>();
                    assert_eq!(valid_res, res2_ref);
                } else {
                    conn.receive_data().await.unwrap_err();
                }
            });
        }
    }
}