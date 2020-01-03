use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;

use tokio::prelude::*;

use crate::control::conn::{AuthenticatedConnError, Conn, ConnError};
use crate::control::primitives::AsyncEvent;
use crate::utils::{is_valid_keyword, parse_single_key_value, quote_string, unquote_string};

/// AuthenticatedConn represents connection to TorCP after it has been authenticated so one may
/// perform various operations on it.
///
/// This connection is aware of asynchronous events which may occur sometimes.
///
/// It wraps `Conn`.
///
/// # Async event handling
/// AuthenticatedConn automatically recognises and treats differently response for given request and asynchronous
/// event response.
/// If it receives an asynchronous event it will invoke async event handler(if some).
/// Asynchronous handler will be awaited in current thread(no calls to `tokio::spawn` or stuff like that).
/// Make sure that async handlers won't take long time to execute as this may cause latencies in handling other functions.
///
/// Please also note that this connection won't do anything in background to handle events.
/// In order to trigger event handling(if any) use `noop` function.
///
/// # Performance considerations
/// Come on it's tor controller.
/// Performance does not really matters.
/// I believe that simplicity and readability are more important(no zero-copy magic here).
pub struct AuthenticatedConn<S, H> {
    async_event_handler: Option<H>,
    conn: Conn<S>,
}

impl<S, H> From<Conn<S>> for AuthenticatedConn<S, H> {
    fn from(conn: Conn<S>) -> Self {
        Self {
            async_event_handler: None,
            conn,
        }
    }
}

impl<S, H> AuthenticatedConn<S, H> {
    /// set_async_event_handler sets handler used to process asynchronous events
    pub fn set_async_event_handler(&mut self, handler: Option<H>) {
        self.async_event_handler = handler;
    }
}

// parsing stuff here(read only for test + fuzzing purposes)
impl<S, H, F> AuthenticatedConn<S, H>
    where
        S: AsyncRead + Unpin,
    // there fns make use of event handler so it's needed
        H: Fn(AsyncEvent<'static>) -> F,
        F: Future<Output=Result<(), ConnError>>,
{
    async fn handle_async_event(&self, event: AsyncEvent<'static>) -> Result<(), ConnError> {
        if let Some(handler) = &self.async_event_handler {
            (handler)(event).await?;
        }
        Ok(())
    }

    // recv response + handle async event until there are some
    async fn recv_response(&mut self) -> Result<(u16, Vec<String>), ConnError> {
        loop {
            let (code, lines) = self.conn.receive_data().await?;
            if code == 650 { // it's async response
                self.handle_async_event(AsyncEvent {
                    code,
                    lines: lines.into_iter().map(|v| Cow::Owned(v)).collect(),
                }).await?;
            } else {
                return Ok((code, lines));
            }
        }
    }

    async fn read_get_conf_response(&mut self) -> Result<HashMap<String, Vec<Option<String>>>, ConnError> {
        let (code, res) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        let mut result: HashMap<String, Vec<Option<String>>> = HashMap::new();
        for line in res {
            let mut is_default = true;
            for c in line.as_bytes() {
                if *c == b'=' {
                    is_default = false;
                }
            }
            if is_default {
                if let Some(v) = result.get_mut(&line) {
                    v.push(None);
                } else {
                    result.insert(line, vec![None]);
                }
            } else {
                let (k, v) = parse_single_key_value(&line)
                    .map_err(|_| ConnError::InvalidFormat)?;
                // TODO(teawithsand): Apply some restrictions on what is key?
                //  ensure unique keys?
                /*
                    According to torCP docs:
                    ```
                    Value may be a raw value or a quoted string.  Tor will try to use unquoted
                    values except when the value could be misinterpreted through not being
                    quoted. (Right now, Tor supports no such misinterpretable values for
                    configuration options.)
                    ```
                */
                let v = match unquote_string(v) {
                    (Some(offset), Ok(unquoted)) if offset == v.len() - 1 => {
                        unquoted.into_owned()
                    }
                    (None, Ok(unquoted)) => {
                        unquoted.into_owned()
                    }
                    _ => {
                        return Err(ConnError::InvalidFormat);
                    }
                };
                if let Some(result_list) = result.get_mut(k) {
                    result_list.push(Some(v));
                } else {
                    result.insert(k.to_string(), vec![Some(v)]);
                }
            }
        }
        Ok(result)
    }
}

impl<S, F, H> AuthenticatedConn<S, H>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        H: Fn(AsyncEvent<'static>) -> F,
        F: Future<Output=Result<(), ConnError>>,
{
    /// set_conf_multiple sends `SETCONF` command to remote tor instance
    /// which sets one or more configuration values in tor
    ///
    /// # Notes
    /// `new_value` should not be a quoted string as it will be quoted during this function call before send.
    /// If `new_value` is `None` default value will be set for given configuration option.
    ///
    /// # Error
    /// It returns error when `config_option` variable is not valid tor keyword.
    /// It returns error when tor instance returns an error.
    pub async fn set_conf_multiple(&mut self, mut options: &mut impl Iterator<Item=(&str, Option<&str>)>) -> Result<(), ConnError>
    {
        let mut call = String::new();
        call.push_str("SETCONF");
        let mut is_first = true;
        for (k, value) in options {
            if !is_valid_keyword(k) {
                return Err(ConnError::AuthenticatedConnError(AuthenticatedConnError::InvalidKeywordValue));
            }

            if !is_first {
                call.push(' ');
                is_first = false;
            }

            call.push_str(k);
            if let Some(value) = value {
                let value = quote_string(value.as_bytes());
                call.push('=');
                call.push_str(&value);
            }
        }
        call.push_str("\r\n");
        self.conn.write_data(call.as_bytes()).await?;

        // response parsing is simple
        // no need for separate fn
        let (code, _lines) = self.conn.receive_data().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    /// set_conf is just like `set_conf_multiple` but is simpler for single config options
    pub async fn set_conf(&mut self, option: &str, value: Option<&str>) -> Result<(), ConnError> {
        self.set_conf_multiple(&mut std::iter::once((option, value))).await
    }

    /// get_conf sends `GETCONF` command to remote tor instance
    /// which gets one(or more but it's not implemented, use sequence of calls to this function)
    /// configuration value from tor.
    ///
    /// # Return value
    /// As torCP docs says:
    /// ```text
    /// If an option appears multiple times in the configuration, all of its
    /// key-value pairs are returned in order.
    /// ```
    /// If option is default one value is represented as `None`
    ///
    /// # Error
    /// It returns error when `config_option` variable is not valid tor keyword.
    /// - Valid keyword is considered as ascii letters and digits. String must not be empty as well.
    /// It returns an error if tor considers given value an error for instance because it does not exist.
    /// If this happens `522` response code is returned from tor according to torCP docs.
    ///
    /// # TorCP docs
    /// Ctrl+F `3.3. GETCONF`
    pub async fn get_conf(&mut self, config_option: &str) -> Result<Vec<Option<String>>, ConnError> {
        if !is_valid_keyword(config_option) {
            return Err(ConnError::AuthenticatedConnError(AuthenticatedConnError::InvalidKeywordValue));
        }

        self.conn.write_data(&format!("GETCONF {}\r\n", config_option).as_bytes()).await?;
        let mut res = self.read_get_conf_response().await?;

        return if let Some(res) = res.remove(config_option) {
            Ok(res)
        } else {
            // no given config option in response! Even if default it would be visible in hashmap.
            Err(ConnError::InvalidFormat)
        };
    }

    /// noop implements no-operation call to tor process despite the fact that torCP does not implement it.
    /// It's used to poll any async event without blocking.
    pub async fn noop(&mut self) -> Result<(), ConnError> {
        unimplemented!("NIY");
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use crate::utils::block_on;

    use super::*;

    #[test]
    fn test_can_parse_getconf_response() {
        for (i, o) in [
            (
                b"250 SOCKSPORT=1234\r\n" as &[u8],
                Some({
                    let mut res: HashMap<String, Vec<Option<String>>> = HashMap::new();
                    res.insert("SOCKSPORT".to_string(), vec![
                        Some("1234".to_string())
                    ]);
                    res
                })
            ),
            (
                b"250 SOCKSPORT\r\n",
                Some({
                    let mut res: HashMap<String, Vec<Option<String>>> = HashMap::new();
                    res.insert("SOCKSPORT".to_string(), vec![
                        None
                    ]);
                    res
                })
            ),
            (
                concat!(
                "250-SOCKSPORT=1234\r\n",
                "250 SOCKSPORT=5678\r\n"
                ).as_bytes(),
                Some({
                    let mut res: HashMap<String, Vec<Option<String>>> = HashMap::new();
                    res.insert("SOCKSPORT".to_string(), vec![
                        Some("1234".to_string()),
                        Some("5678".to_string()),
                    ]);
                    res
                })
            ),
            (
                concat!(
                "250-SOCKSPORT=5678\r\n",
                "250 SOCKSPORT=1234\r\n"
                ).as_bytes(),
                Some({
                    let mut res: HashMap<String, Vec<Option<String>>> = HashMap::new();
                    res.insert("SOCKSPORT".to_string(), vec![
                        Some("5678".to_string()),
                        Some("1234".to_string()),
                    ]);
                    res
                })
            ),
        ].iter().cloned() {
            block_on(async move {
                let mut input = Cursor::new(i);
                let conn = Conn::new(&mut input);
                let mut conn = AuthenticatedConn::from(conn);
                conn.set_async_event_handler(
                    Some(|_| async move { Ok(()) })
                );
                if let Some(o) = o {
                    let res = conn.read_get_conf_response().await.unwrap();
                    assert_eq!(res, o);
                } else {
                    conn.read_get_conf_response().await.unwrap_err();
                }
            })
        }
    }
}

#[cfg(testtor)]
mod test_with_tor {
    // TODO(teawithsand): tests for getopt setopt on live tor instance
}