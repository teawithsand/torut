use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::prelude::*;

use crate::control::conn::{AuthenticatedConnError, Conn, ConnError};
use crate::control::primitives::AsyncEvent;
use crate::utils::{is_valid_event, is_valid_hostname, is_valid_keyword, is_valid_option, parse_single_key_value, quote_string, unquote_string};

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

    // according to docs:
    // ```
    // On success,
    // one ReplyLine is sent for each requested value, followed by a final 250 OK
    // ReplyLine.
    // ```
    async fn read_get_info_response(&mut self) -> Result<HashMap<String, Vec<String>>, ConnError> {
        let (code, res) = self.recv_response().await?;
        let res_len = res.len();

        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        // ... followed by a final 250 OK
        if &res[res.len() - 1] != "OK" {
            return Err(ConnError::InvalidFormat);
        }
        let mut result: HashMap<String, Vec<String>> = HashMap::new();

        for l in res.into_iter().take(res_len - 1) {
            let (k, v) = parse_single_key_value(&l)
                .map_err(|_| ConnError::InvalidFormat)?;
            if let Some(res_vec) = result.get_mut(k) {
                res_vec.push(v.to_string());
            } else {
                result.insert(k.to_string(), vec![v.to_string()]);
            }
        }
        Ok(result)
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
    pub async fn set_conf_multiple(&mut self, options: &mut impl Iterator<Item=(&str, Option<&str>)>) -> Result<(), ConnError>
    {
        let mut call = String::new();
        call.push_str("SETCONF");
        let mut has_any_option = false;
        for (k, value) in options {
            has_any_option = true;
            if !is_valid_keyword(k) {
                return Err(ConnError::AuthenticatedConnError(AuthenticatedConnError::InvalidKeywordValue));
            }
            call.push(' ');
            call.push_str(k);
            if let Some(value) = value {
                // string quoting makes value safe to use in context of connection
                let value = quote_string(value.as_bytes());
                call.push('=');
                call.push_str(&value);
            }
        }
        if !has_any_option {
            return Ok(());
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

    // TODO(teawithsand): multiple versions of get_conf for specifiic stuff
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
        let res = self.read_get_conf_response().await?;

        /*
        // note: for instance query for DISABLENETWORK may be returned as DisableNetwork=0
        return if let Some(res) = res.remove(config_option) {
            Ok(res)
        } else {
            // no given config option in response! Even if default it would be visible in hashmap.
            Err(ConnError::InvalidFormat)
        };
        */
        if res.len() != 1 {
            return Err(ConnError::InvalidFormat);
        }
        for (k, v) in res {
            if k.len() == config_option.len() &&
                k.as_bytes().iter().cloned().map(|c| c.to_ascii_uppercase())
                    .zip(config_option.as_bytes().iter().cloned().map(|c| c.to_ascii_uppercase()))
                    .all(|(c1, c2)| c1 == c2)
            {
                return Ok(v);
            }
        }
        return Err(ConnError::InvalidFormat);
    }

    /// get_info_multiple sends `GETINFO` command to remote tor controller.
    /// Unlike `GETCONF` it may get values which are not part of tor's configuration.
    ///
    /// # Return value
    /// Result hash map is guaranteed to value for all options provided in request.
    /// Each one is interpreted as string without unquoting(if tor spec requires to do so for given value it has to be done manually)
    ///
    /// If same key was provided twice or more times it's value will occur in result these amount of times.
    /// Values are fetched directly from tor so they probably are same but take a look at torCP docs to be sure about that.
    ///
    /// # Error
    /// `AuthenticatedConnError::InvalidKeywordValue` is returned if one of provided options is invalid option value and may
    /// break control flow integrity of transmission.
    pub async fn get_info_multiple(&mut self, options: &mut impl Iterator<Item=&str>) -> Result<HashMap<String, Vec<String>>, ConnError> {
        let mut call = String::new();
        call.push_str("GETINFO");
        let mut keys = HashMap::new();
        for option in options {
            if !is_valid_option(option) {
                return Err(ConnError::AuthenticatedConnError(AuthenticatedConnError::InvalidKeywordValue));
            }
            if let Some(counter) = keys.get_mut(option) {
                *counter += 1;
            } else {
                keys.insert(option, 1usize);
            }
            call.push(' ');
            call.push_str(option);
        }
        call.push_str("\r\n");
        if keys.len() == 0 {
            return Ok(HashMap::new());
        }
        self.conn.write_data(call.as_bytes()).await?;

        let res = self.read_get_info_response().await?;
        if res.len() != keys.len() {
            return Err(ConnError::InvalidFormat);
        }
        // res has to contain all the provided keys
        for (key, count) in keys {
            match res.get(key) {
                Some(v) if v.len() == count => {}
                _ => {
                    return Err(ConnError::InvalidFormat);
                }
            }
        }
        return Ok(res);
    }

    /// get_info is just like `get_info_multiple` but accepts only one parameter and returns only one value
    pub async fn get_info(&mut self, option: &str) -> Result<String, ConnError> {
        let res = self.get_info_multiple(&mut std::iter::once(option)).await?;
        if res.len() != 1 {
            return Err(ConnError::InvalidFormat);
        }

        let v = res.into_iter().map(|(_k, v)| v).nth(0).unwrap();
        if v.len() != 1 {
            return Err(ConnError::InvalidFormat);
        }
        Ok(v.into_iter().nth(0).unwrap())
    }

    /// drop_guards invokes `DROPGUARDS` which(according to torCP docs):
    ///
    /// ```text
    /// Tells the server to drop all guard nodes. Do not invoke this command
    /// lightly; it can increase vulnerability to tracking attacks over time.
    /// ```
    pub async fn drop_guards(&mut self) -> Result<(), ConnError> {
        self.conn.write_data(b"DROPGUARDS\r\n").await?;
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    /// take_ownership invokes `TAKEOWNERSHIP` which(according to torCP docs):
    ///
    /// ```text
    /// This command instructs Tor to shut down when this control
    /// connection is closed. This command affects each control connection
    /// that sends it independently; if multiple control connections send
    /// the TAKEOWNERSHIP command to a Tor instance, Tor will shut down when
    /// any of those connections closes.
    /// ```
    pub async fn take_ownership(&mut self) -> Result<(), ConnError> {
        self.conn.write_data(b"TAKEOWNERSHIP\r\n").await?;
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    /// drop_ownership invokes `DROPOWNERSHIP` which(according to torCP docs):
    ///
    /// ```text
    /// This command instructs Tor to relinquish ownership of its control
    /// connection. As such tor will not shut down when this control
    /// connection is closed.
    /// ```
    pub async fn drop_ownership(&mut self) -> Result<(), ConnError> {
        self.conn.write_data(b"DROPOWNERSHIP\r\n").await?;
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    // TODO(teawithsand): make async resolve with custom future with tokio which parses async event
    //  and then notifies caller using waker 
    //  same for reverse_resolve

    /// resolve performs dns lookup over tor. It invokes `RESOLVE` command which(according to torCP docs):
    /// ```text
    /// This command launches a remote hostname lookup request for every specified
    /// request (or reverse lookup if "mode=reverse" is specified).
    /// ```
    /// Note: there is separate function for reverse requests.
    ///
    /// # Result
    /// Result is passed as `ADDRMAP` event so one should setup event listener to use it.
    /// It's `NewAddressMapping` event.
    pub async fn resolve(&mut self, hostname: &str) -> Result<(), ConnError> {
        if is_valid_hostname(hostname) {
            return Err(ConnError::AuthenticatedConnError(AuthenticatedConnError::InvalidHostnameValue));
        }

        self.conn.write_data(&format!("RESOLVE {}\r\n", hostname).as_bytes()).await?;
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    /// resolve performs reverse dns lookup over tor. It invokes `RESOLVE` command which(according to torCP docs):
    /// ```text
    /// This command launches a remote hostname lookup request for every specified
    /// request (or reverse lookup if "mode=reverse" is specified).
    /// ```
    /// Note: this function always set reverse mode
    /// # Ipv6
    /// TorCP doc says: `a hostname or IPv4 address`. In reverse case it may be only ipv4 address.
    ///
    /// # Result
    /// Result is passed as `ADDRMAP` event so one should setup event listener to use it.
    /// It's `NewAddressMapping` event.
    pub async fn reverse_resolve(&mut self, address: Ipv4Addr) -> Result<(), ConnError> {
        // assumption: ip can't provide any malicious contents
        self.conn.write_data(&format!("RESOLVE mode=reverse {}\r\n", address.to_string()).as_bytes()).await?;
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    // note: there is no \r\n at the end
    fn setup_onion_service_call<'a>(
        is_rsa: bool,
        key_blob: &str,
        detach: bool,
        non_anonymous: bool,
        max_streams_close_circuit: bool,
        max_num_streams: Option<u16>,
        listeners: &mut impl Iterator<Item=&'a (u16, SocketAddr)>,
    ) -> Result<String, AuthenticatedConnError> {
        let mut res = String::new();
        res.push_str("ADD_ONION ");
        if is_rsa {
            res.push_str("RSA1024");
        } else {
            res.push_str("ED25519-V3");
        }
        res.push(':');
        res.push_str(key_blob);
        res.push(' ');

        {
            let mut flags = Vec::new();
            flags.push("DiscardPK");
            if detach {
                flags.push("Detach");
            }
            if non_anonymous {
                flags.push("NonAnonymous");
            }
            if max_streams_close_circuit {
                flags.push("MaxStreamsCloseCircuit");
            }
            if !flags.is_empty() {
                res.push_str("Flags=");
                res.push_str(&flags.join(" "));
                res.push(' ');
            }
        }

        {
            if let Some(max_num_streams) = max_num_streams {
                res.push_str(&format!("MaxStreams={} ", max_num_streams));
                res.push_str(" ");
            }
        }

        {
            let mut is_first = true;
            let mut ports = HashSet::new();
            for (port, address) in listeners {
                if !is_first {
                    res.push(' ');
                }
                if ports.contains(port) {
                    return Err(AuthenticatedConnError::InvalidListenerSpecification);
                }
                ports.insert(port);
                is_first = false;
                res.push_str(&format!("Port={},{}", port, address));
            }
            // zero iterations of above loop has ran
            if is_first {
                return Err(AuthenticatedConnError::InvalidListenerSpecification);
            }
            res.push(' ');
        }

        Ok(res)
    }

    #[cfg(any(feature = "v2"))]
    /// add_onion sends `ADD_ONION` command which spins up new onion service.
    /// Using given tor secret key and some configuration values.
    ///
    /// For onion service v3 take a look at `add_onion_v3`
    ///
    /// # Parameters
    /// `key` - key to use to start onion service
    /// `detach` - if set to `false` it makes onion service disappear once control connection is closed
    /// `non_anonymous` - if set to `true` it runs special single hop onion service. It can't be done on default compilation of tor.
    /// `max_streams_close_circuit` - if set to `true` closes circuit if max streams is reached
    /// `max_num_streams` - maximum amount of streams which may be attached to RP point. Zero is unlimited.
    ///   `None` is default and may vary depending on tor version being used.
    /// `listeners` - set of pairs of ports and addresses to which connections should be redirected to.
    /// Must contain at least one entry. Otherwise error is returned.
    ///
    /// It does not support basic auth yet.
    /// It does not support tor-side generated keys yet.
    pub async fn add_onion_v2(
        &mut self,
        key: &crate::onion::TorSecretKeyV2,
        detach: bool,
        non_anonymous: bool,
        max_streams_close_circuit: bool,
        max_num_streams: Option<u16>,
        listeners: &mut impl Iterator<Item=&(u16, SocketAddr)>,
    ) -> Result<(), ConnError> {
        let mut res = Self::setup_onion_service_call(
            true,
            &key.as_tor_proto_encoded(),
            detach,
            non_anonymous,
            max_streams_close_circuit,
            max_num_streams,
            listeners,
        )?;
        res.push_str("\r\n");
        self.conn.write_data(res.as_bytes()).await?;

        // we do not really care about contents of response
        // we can derive all the data from tor's objects at the torut level
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    #[cfg(any(feature = "v3"))]
    /// add_onion sends `ADD_ONION` command which spins up new onion service
    /// using given tor secret key and some configuration values.
    ///
    /// For onion service v2 take a look at `add_onion_v2`
    ///
    /// # Parameters
    /// Take a look at `add_onion_v2`. This function accepts same parameters.
    ///
    /// It does not support tor-side generated keys yet.
    pub async fn add_onion_v3(
        &mut self,
        key: &crate::onion::TorSecretKeyV3,
        detach: bool,
        non_anonymous: bool,
        max_streams_close_circuit: bool,
        max_num_streams: Option<u16>,
        listeners: &mut impl Iterator<Item=&(u16, SocketAddr)>,
    ) -> Result<(), ConnError> {
        let mut res = Self::setup_onion_service_call(
            false,
            &key.as_tor_proto_encoded(),
            detach,
            non_anonymous,
            max_streams_close_circuit,
            max_num_streams,
            listeners,
        )?;
        res.push_str("\r\n");

        self.conn.write_data(res.as_bytes()).await?;

        // we do not really care about contents of response
        // we can derive all the data from tor's objects at the torut level
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    /// del_onion sends `DEL_ONION` command which stops onion service.
    ///
    /// It returns an error if identifier is not valid.
    pub async fn del_onion(&mut self, identifier_without_dot_onion: &str) -> Result<(), ConnError> {
        for c in identifier_without_dot_onion.chars() { // limit to safe chars, so there is no injection
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '=' => {}
                _ => {
                    return Err(ConnError::AuthenticatedConnError(AuthenticatedConnError::InvalidOnionServiceIdentifier));
                }
            }
        }
        self.conn.write_data(&format!("DEL_ONION {}\r\n", identifier_without_dot_onion).as_bytes()).await?;
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    /// set_events sends `SETEVENTS` command which instructs tor process to report controller all the events
    /// of given kind that occur to this controller.
    ///
    /// # Note
    /// Call to `set_events` unsets all previously set event listeners.
    /// For instance in order to clear event all listeners use `set_events` with empty iterator.
    /// To listen for `CIRC` event pass iterator with single `CIRC` entry.
    /// To listen for `WARN` and `ERR` log messages but no more to `CIRC` event pass iterator with two entries: `WARN` and `CIRC`
    ///
    /// # Notes on using options
    /// Extended parameter is ignored in tor newer than `0.2.2.1-alpha` and it's always switched on.
    /// It should default to false.
    pub async fn set_events(&mut self, extended: bool, kinds: &mut impl Iterator<Item=&str>) -> Result<(), ConnError> {
        let mut req = String::from("SETEVENTS");
        if extended {
            req.push_str(" EXTENDED");
        }
        for k in kinds {
            if !is_valid_event(k) {
                return Err(ConnError::AuthenticatedConnError(AuthenticatedConnError::InvalidEventName));
            }
            req.push(' ');
            req.push_str(k);
        }
        req.push_str("\r\n");
        self.conn.write_data(req.as_bytes()).await?;
        let (code, _) = self.recv_response().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    /// noop implements no-operation call to tor process despite the fact that torCP does not implement it.
    /// It's used to poll any async event without blocking.
    pub async fn noop(&mut self) -> Result<(), ConnError> {
        // right now noop is getting tor's version
        // it should do
        self.get_info("version").await?;
        Ok(())
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

    #[test]
    fn test_can_parse_getinfo_response() {
        for (i, o) in [
            (
                b"250-version=1.2.3.4\r\n250 OK\r\n" as &[u8],
                Some({
                    let mut res: HashMap<String, Vec<String>> = HashMap::new();
                    res.insert("version".to_string(), vec![
                        "1.2.3.4".to_string()
                    ]);
                    res
                })
            ),
            (
                // no terminating `250 OK` line
                b"250 version=1.2.3.4\r\n" as &[u8],
                None,
            ),
            (
                // multiple responses for same key
                b"250-version=1.2.3.4\r\n250-version=4.3.2.1\r\n250 OK\r\n" as &[u8],
                Some({
                    let mut res: HashMap<String, Vec<String>> = HashMap::new();
                    res.insert("version".to_string(), vec![
                        "1.2.3.4".to_string(),
                        "4.3.2.1".to_string()
                    ]);
                    res
                })
            ),
            (
                // multiple responses for multiple keys
                b"250-aversion=1.2.3.4\r\n250-reversion=4.3.2.1\r\n250 OK\r\n" as &[u8],
                Some({
                    let mut res: HashMap<String, Vec<String>> = HashMap::new();
                    res.insert("aversion".to_string(), vec![
                        "1.2.3.4".to_string(),
                    ]);
                    res.insert("reversion".to_string(), vec![
                        "4.3.2.1".to_string(),
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
                    let res = conn.read_get_info_response().await.unwrap();
                    assert_eq!(res, o);
                } else {
                    conn.read_get_info_response().await.unwrap_err();
                }
            })
        }
    }
}

// TODO(teawithsand): cleanup testing initialization
#[cfg(all(test, testtor))]
mod test_with_tor {
    use std::thread::sleep;
    use std::time::Duration;
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::fs::File;
    use tokio::net::{TcpStream};
    use tokio::prelude::*;

    use crate::control::{COOKIE_LENGTH, TorAuthData, TorAuthMethod, UnauthenticatedConn};
    use crate::utils::{block_on_with_env, run_testing_tor_instance, TOR_TESTING_PORT};

    use super::*;

    #[test]
    fn test_can_get_configuration_value_set_it_and_get_it_again() {
        let c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();

            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap();
            let mut ac = utc.into_authenticated().await;
            ac.set_async_event_handler(Some(|_| {
                async move { Ok(()) }
            }));

            // socks port is default now
            {
                let res = ac.get_conf("SocksPort").await.unwrap();
                assert_eq!(res.len(), 1);
                assert_eq!(res[0].as_ref().map(|r| r as &str), None);
            }

            // socks port is default now
            {
                ac.set_conf("SocksPort", Some("17539")).await.unwrap();

                {
                    let res = ac.get_conf("SocksPort").await.unwrap();
                    assert_eq!(res.len(), 1);
                    assert_eq!(res[0].as_ref().map(|r| r as &str), Some("17539"));
                }
            }

            {
                ac.set_conf("SocksPort", Some("17539")).await.unwrap();

                {
                    let res = ac.get_conf("SocksPort").await.unwrap();
                    assert_eq!(res.len(), 1);
                    assert_eq!(res[0].as_ref().map(|r| r as &str), Some("17539"));
                }
            }

            {
                ac.set_conf("SocksPort", None).await.unwrap();

                {
                    let res = ac.get_conf("SocksPort").await.unwrap();
                    assert_eq!(res.len(), 1);
                    assert_eq!(res[0].as_ref().map(|r| r as &str), None);
                }
            }
        });
    }

    #[test]
    fn test_can_get_information_from_tor() {
        let c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();

            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap();
            let mut ac = utc.into_authenticated().await;
            ac.set_async_event_handler(Some(|_| {
                async move { Ok(()) }
            }));

            {
                ac.set_conf("SocksPort", Some("17245")).await.unwrap();
                ac.set_conf("DisableNetwork", Some("0")).await.unwrap();
                let res = ac.get_info("net/listeners/socks").await.unwrap();
                let (_, v) = unquote_string(&res);
                let v = v.unwrap();
                assert_eq!(v.as_ref(), "127.0.0.1:17245");
            }
        });
    }

    #[test]
    fn test_can_listen_to_events_on_tor() {
        let c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();

            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap();
            let mut ac = utc.into_authenticated().await;
            ac.set_async_event_handler(Some(|_| {
                async move { Ok(()) }
            }));

            let _ = ac.set_events(false, &mut [
                "CIRC", "ADDRMAP"
            ].iter().map(|v| *v)).await.unwrap();
        });
    }

    #[test]
    fn test_can_take_ownership() {
        let mut c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();

            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap();
            let mut ac = utc.into_authenticated().await;
            ac.set_async_event_handler(Some(|_| {
                async move { Ok(()) }
            }));

            ac.take_ownership().await.unwrap();
            drop(ac);
            assert_eq!(c.wait().unwrap().code().unwrap(), 0);
        });
    }

    #[test]
    fn test_can_take_and_drop_ownership() {
        let mut c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();

            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap();
            let mut ac = utc.into_authenticated().await;
            ac.set_async_event_handler(Some(|_| {
                async move { Ok(()) }
            }));

            ac.take_ownership().await.unwrap();
            ac.drop_ownership().await.unwrap();
            drop(ac);
            sleep(Duration::from_millis(2000));
            assert!(c.try_wait().unwrap().is_none());
        });
    }

    #[test]
    fn test_can_create_onion_service_v3() {
        let mut c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();

            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap();
            let mut ac = utc.into_authenticated().await;
            ac.set_async_event_handler(Some(|_| {
                async move { Ok(()) }
            }));

            let key = crate::onion::TorSecretKeyV3::generate();

            ac.add_onion_v3(&key, false, false, false, None, &mut [
                (15787, SocketAddr::new(IpAddr::from(Ipv4Addr::new(127,0,0,1)), 15787)),
            ].iter()).await.unwrap();

            // additional actions to check if connection is in corrupted state
            ac.take_ownership().await.unwrap();
            ac.drop_ownership().await.unwrap();

            // delete onion service so it works no more
            ac.del_onion(&key.public().get_onion_address().get_address_without_dot_onion()).await.unwrap();
        });
    }

    #[test]
    fn test_can_create_onion_service_v2() {
        let mut c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();

            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap();
            let mut ac = utc.into_authenticated().await;
            ac.set_async_event_handler(Some(|_| {
                async move { Ok(()) }
            }));

            let key = crate::onion::TorSecretKeyV2::generate();

            ac.add_onion_v2(&key, false, false, false, None, &mut [
                (15787, SocketAddr::new(IpAddr::from(Ipv4Addr::new(127,0,0,1)), 15787)),
            ].iter()).await.unwrap();

            // additional actions to check if connection is in corrupted state
            ac.take_ownership().await.unwrap();
            ac.drop_ownership().await.unwrap();

            // delete onion service so it works no more
            // TOOD(teawithsand): implement get_onion_address for TorPublicKeyV2
            // ac.del_onion(&key.public().get_onion_address().get_address_without_dot_onion()).await.unwrap();
        });
    }
}

#[cfg(fuzzing)]
mod fuzzing {
    // TODO(teawithsand): fuzz functions receiving data from tor here
}