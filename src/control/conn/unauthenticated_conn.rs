use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use hmac::{Hmac, Mac};
use rand::{RngCore, thread_rng};
use sha2::Sha256;
use tokio::io::AsyncRead;
use tokio::prelude::AsyncWrite;

use crate::control::conn::{AuthenticatedConn, Conn, ConnError, UnauthenticatedConnError};
use crate::control::primitives::{TorAuthData, TorAuthMethod, TorPreAuthInfo};
use crate::utils::{parse_single_key_value, quote_string, unquote_string};

// note: unlike authenticated conn, unauthenticated conn does not do any asynchronous event handling
/// UnauthenticatedConn represents connection to torCP which is not authenticated yet
/// and for this reason only limited amount of operations may be performed on it.
///
/// It wraps `Conn`
pub struct UnauthenticatedConn<S> {
    conn: Conn<S>,
    was_protocol_info_loaded: bool,
    protocol_info: Option<TorPreAuthInfo<'static>>,
}

impl<S> From<Conn<S>> for UnauthenticatedConn<S> {
    fn from(conn: Conn<S>) -> Self {
        Self {
            conn,
            protocol_info: None,
            was_protocol_info_loaded: false,
        }
    }
}

impl<S> UnauthenticatedConn<S> {
    pub fn new(stream: S) -> Self {
        Self::from(Conn::new(stream))
    }

    /// get_protocol_info returns tor protocol info reference if one was loaded before
    /// with `load_protocol_info`
    ///
    /// In order to get owned version of `TorPreAuthInfo` use `own_protocol_info`.
    pub fn get_protocol_info(&self) -> Option<&TorPreAuthInfo<'static>> {
        self.protocol_info.as_ref()
    }

    /// take_protocol_info returns tor protocol info value if one was loaded before
    /// with `load_protocol_info`
    pub fn take_protocol_info(&mut self) -> Option<TorPreAuthInfo<'static>> {
        self.protocol_info.take()
    }
}

/// TOR_SAFECOOKIE_CONSTANT is passed to HMAC for `SAFECOOKIE` auth procedure
const TOR_SAFECOOKIE_CONSTANT: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// AuthChallengeResponse is container for response returned by server after executing
/// `AUTHCHALLENGE` command
// pub crate required due to read_auth_challenge_response pub crate read visibility for fuzzing
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthChallengeResponse {
    /// according to TorCP docs it's 32 bytes long always
    /// because it's 64 hexadecimal digits
    pub server_hash: [u8; 32],

    /// according to TorCP docs it's 32 bytes long always
    pub server_nonce: [u8; 32],
}

impl<S> UnauthenticatedConn<S>
    where S: AsyncRead + Unpin
{
    // exposed for testing and fuzzing
    pub(crate) async fn read_protocol_info<'a>(&'a mut self) -> Result<&'a TorPreAuthInfo<'static>, ConnError> {
        let (code, lines) = self.conn.receive_data().await?;

        // 250 code is hardcoded at spec right now
        // we do not expect async events yet
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        if lines.len() < 3 {
            return Err(ConnError::InvalidFormat);
        }
        if lines[0] != "PROTOCOLINFO 1" {
            return Err(ConnError::InvalidFormat);
        }
        let mut res = HashMap::new();
        for l in &lines[1..lines.len() - 1] {
            match parse_single_key_value(l) {
                Ok((key, value)) => {
                    if res.contains_key(key) {
                        // may keys ve duplicated?
                        return Err(ConnError::InvalidFormat);
                    }
                    res.insert(key, value);
                }
                Err(_) => {
                    return Err(ConnError::InvalidFormat);
                }
            }
        }

        if &lines[lines.len() - 1] != "OK" {
            return Err(ConnError::InvalidFormat);
        }

        let (auth_methods, cookie_path) = if let Some(auth_methods) = res.get("AUTH METHODS")
            .or_else(|| res.get("METHODS"))
        {
            let mut auth_methods_res = HashSet::new();

            let mut end_methods_idx = 0;
            for c in auth_methods.chars() {
                if c == ' ' {
                    break;
                }
                end_methods_idx += c.len_utf8();
            }
            for m in auth_methods[..end_methods_idx]
                .split(',')
                {
                    if let Ok(v) = TorAuthMethod::from_str(m) {
                        if auth_methods_res.contains(&v) {
                            return Err(ConnError::InvalidFormat);
                        }
                        auth_methods_res.insert(v);
                    } else {
                        return Err(ConnError::InvalidFormat);
                    }
                }

            let maybe_cookie_str = auth_methods[end_methods_idx..].trim();
            let cookie_path = if maybe_cookie_str.len() > 0 {
                let (k, encoded_path) = parse_single_key_value(maybe_cookie_str)
                    .map_err(|_| ConnError::InvalidFormat)?;
                if k != "COOKIEFILE" {
                    return Err(ConnError::InvalidFormat);
                }
                match unquote_string(encoded_path) {
                    // quoted string which is valid utf-8
                    // and ends with string
                    (Some(offset), Ok(path)) if offset == encoded_path.len() - 1 => {
                        Some(path.into_owned())
                    }
                    _ => {
                        return Err(ConnError::InvalidFormat);
                    }
                }
            } else {
                None
            };
            // in fact there should be some auth method even null one
            if auth_methods_res.len() == 0 {
                return Err(ConnError::InvalidFormat);
            }
            (auth_methods_res, cookie_path)
        } else {
            return Err(ConnError::InvalidFormat);
        };


        let version = res.get("VERSION Tor")
            .map(|v| unquote_string(v));
        let version = match version {
            Some((Some(_), Ok(v))) => {
                v.into_owned()
            }
            // no tor version supplied
            _ => {
                return Err(ConnError::InvalidFormat);
            }
        };

        self.was_protocol_info_loaded = true;
        {
            self.protocol_info = Some(TorPreAuthInfo {
                auth_methods,
                cookie_file: cookie_path.map(|v| Cow::Owned(v)),
                tor_version: Cow::Owned(version),
            });
        }
        Ok(self.protocol_info.as_ref().unwrap())
    }

    //noinspection SpellCheckingInspection
    // example line:
    // Note: '\' at the end is soft line break
    // Note #2: part in the round brackets is not in line variable.
    // (250 )AUTHCHALLENGE SERVERHASH=3AB21C1D4E7337F2CC4460C9973B13EE42944E6455131A8CA0CF10628BCBACF2 \
    // SERVERNONCE=DB3B06356534DE8732C8C858F543D0E55B8D44A2353F913B5F36E23A61537D86
    pub(crate) async fn read_auth_challenge_response(&mut self) -> Result<AuthChallengeResponse, ConnError> {
        let (code, mut lines) = self.conn.receive_data().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        if lines.len() != 1 {
            return Err(ConnError::InvalidFormat);
        }
        let line = lines.swap_remove(0);

        // right now line has fixed length of some letters + 2x 64 hex chars + two spacebars
        if line.len() != "AUTHCHALLENGE".len() + "SERVERHASH=".len() + "SERVERNONCE=".len() + 64 * 2 + 2 {
            return Err(ConnError::InvalidFormat);
        }
        // even more! data is at the fixed offsets which allows us to write simple (and robust ofc) parser
        let server_hash_text = &line[25..25 + 64];
        let server_nonce_text = &line[90 + 12..90 + 12 + 64];
        let mut res = AuthChallengeResponse {
            server_hash: [0u8; 32],
            server_nonce: [0u8; 32],
        };
        hex::decode_to_slice(server_hash_text, &mut res.server_hash)
            .map_err(|_| ConnError::InvalidFormat)?;
        hex::decode_to_slice(server_nonce_text, &mut res.server_nonce)
            .map_err(|_| ConnError::InvalidFormat)?;
        return Ok(res);
    }
}

impl<S> UnauthenticatedConn<S>
    where S: AsyncRead + AsyncWrite + Unpin
{
    /// This function issues `PROTOCOLINFO` command on remote tor instance.
    /// Because this command may be executed only once it automatically prevents programmer from getting data twice.
    ///
    /// # TorCP docs
    /// Ctrl+F in document: `3.21. PROTOCOLINFO`
    pub async fn load_protocol_info<'a>(&'a mut self) -> Result<&'a TorPreAuthInfo<'static>, ConnError> {
        // rust borrow checker seems to fail once this code is uncommented
        /*
        {
            if let Some(val) = &self.protocol_info {
                return Ok(val);
            }
        }
        */

        if self.was_protocol_info_loaded {
            return Err(ConnError::UnauthenticatedConnError(UnauthenticatedConnError::InfoFetchedTwice));
        }

        self.conn.write_data(b"PROTOCOLINFO 1\r\n").await?;
        self.read_protocol_info().await
    }

    /// authenticate performs authentication of given connection BUT does not create `AuthenticatedConn`
    /// from this one.
    ///
    /// # Note
    /// It does not check if provided auth method associated with given tor auth data is valid.
    /// It trusts programmer to do so.
    /// In worst case it won't work(tor won't let us in)
    pub async fn authenticate(&mut self, data: &TorAuthData<'_>) -> Result<(), ConnError> {
        match data {
            TorAuthData::Null => {
                // this one is easy
                self.conn.write_data(b"AUTHENTICATE\r\n").await?;
            }
            TorAuthData::HashedPassword(password) => {
                let password = quote_string(password.as_bytes());
                let mut buf = Vec::new();
                buf.extend_from_slice(b"AUTHENTICATE ");
                buf.extend_from_slice(password.as_ref());
                buf.extend_from_slice(b"\r\n");
                self.conn.write_data(&buf).await?;
            }
            TorAuthData::Cookie(cookie) => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"AUTHENTICATE ");
                buf.extend_from_slice(hex::encode_upper(cookie.as_ref()).as_bytes());
                buf.extend_from_slice(b"\r\n");
                self.conn.write_data(&buf).await?;
            }
            TorAuthData::SafeCookie(cookie) => {
                // for safe cookie we need sha256 hmac
                // so controller requires sha2 and rand for nonces

                let mut client_nonce = [0u8; 64];
                thread_rng().fill_bytes(&mut client_nonce);

                let cookie_string = hex::encode_upper(&client_nonce[..]);
                self.conn.write_data(
                    format!(
                        "AUTHCHALLENGE SAFECOOKIE {}\r\n",
                        cookie_string
                    ).as_bytes()
                ).await?;
                let res = self.read_auth_challenge_response().await?;
                // panic!("Got ACR: {:#?}", res);

                // TODO(teawithsand): check server hash procedure here.
                //  Note: it probably requires constant time compare procedure which means more dependencies probably
                //  or some wild hacks like comparing sha256 hashes of both values(which leaks hashes values but not values itself)

                let client_hash = {
                    let mut hmac = <Hmac<Sha256>>::new_varkey(TOR_SAFECOOKIE_CONSTANT)
                        .expect("Any key len for hmac should be valid. If it's not then rehash data. Right?");
                    hmac.input(cookie.as_ref());
                    hmac.input(&client_nonce[..]);
                    hmac.input(&res.server_nonce[..]);


                    let res = hmac.result();
                    res.code()
                };
                let client_hash = client_hash.as_ref();

                let mut buf = Vec::new();
                buf.extend_from_slice(b"AUTHENTICATE ");
                buf.extend_from_slice(hex::encode_upper(client_hash.as_ref()).as_bytes());
                buf.extend_from_slice(b"\r\n");
                self.conn.write_data(&buf[..]).await?;
            }
        }
        let (code, _) = self.conn.receive_data().await?;
        if code != 250 {
            return Err(ConnError::InvalidResponseCode(code));
        }
        Ok(())
    }

    /// into_authenticated creates `AuthenticatedConn` from this one without checking if it makes any sense.
    /// It should be called after successful call to `authenticate`.
    pub async fn into_authenticated<H>(self) -> AuthenticatedConn<S, H> {
        AuthenticatedConn::from(self.conn)
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use crate::utils::block_on;

    use super::*;

    #[test]
    fn test_can_parse_response() {
        for (i, o) in [
            (
                concat!(
                "250-PROTOCOLINFO 1\r\n",
                "250-AUTH METHODS=NULL\r\n",
                "250-VERSION Tor=\"0.4.2.5\"\r\n",
                "250 OK\r\n",
                ),
                Some(
                    TorPreAuthInfo {
                        tor_version: Cow::Owned("0.4.2.5".to_string()),
                        auth_methods: [
                            TorAuthMethod::Null,
                        ].iter().copied().collect(),
                        cookie_file: None,
                    }
                )
            ),
            (
                concat!(
                "250-PROTOCOLINFO 1\r\n",
                "250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/home/user/.tor/control_auth_cookie\"\r\n",
                "250-VERSION Tor=\"0.4.2.5\"\r\n",
                "250 OK\r\n"
                ),
                Some(
                    TorPreAuthInfo {
                        tor_version: Cow::Owned("0.4.2.5".to_string()),
                        auth_methods: [
                            // sets do not have order!
                            TorAuthMethod::SafeCookie,
                            TorAuthMethod::Cookie,
                        ].iter().copied().collect(),
                        cookie_file: Some(Cow::Owned("/home/user/.tor/control_auth_cookie".to_string())),
                    }
                )
            ),
            (
                concat!(
                "250-PROTOCOLINFO 1\r\n",
                "250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"/home/user/.tor/control_auth_cookie\"\r\n",
                "250-VERSION Tor=\"0.4.2.5\"\r\n",
                "250 OK\r\n"
                ),
                Some(
                    TorPreAuthInfo {
                        tor_version: Cow::Owned("0.4.2.5".to_string()),
                        auth_methods: [
                            // sets do not have order!
                            TorAuthMethod::SafeCookie,
                            TorAuthMethod::Cookie,
                            TorAuthMethod::HashedPassword,
                        ].iter().copied().collect(),
                        cookie_file: Some(Cow::Owned("/home/user/.tor/control_auth_cookie".to_string())),
                    }
                )
            ),
        ].iter().cloned() {
            block_on(async move {
                let mut conn = UnauthenticatedConn::new(Cursor::new(i.as_bytes()));
                match o {
                    Some(v) => {
                        let pai = conn.read_protocol_info().await.unwrap();
                        assert_eq!(pai, &v);
                    }
                    None => {
                        let _ = conn.read_protocol_info().await.unwrap_err();
                    }
                }
            });
        }
    }
}

#[cfg(all(test, testtor))]
mod test_tor {
    use std::net::IpAddr;

    use tokio::fs::File;
    use tokio::net::TcpStream;
    use tokio::prelude::*;

    use crate::control::COOKIE_LENGTH;
    use crate::utils::{AutoKillChild, block_on_with_env, run_testing_tor_instance, TOR_TESTING_PORT};

    use super::*;

    #[test]
    fn test_can_null_authenticate() {
        let c = run_testing_tor_instance(&["--DisableNetwork", "1", "--ControlPort", &TOR_TESTING_PORT.to_string()]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();
            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap();
            // test conn further?
        });
    }

    #[test]
    fn test_can_cookie_authenticate() {
        let c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
                "--CookieAuthentication", "1",
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();
            // panic!("{:#?}", proto_info);
            assert!(proto_info.auth_methods.contains(&TorAuthMethod::Cookie));
            assert!(proto_info.cookie_file.is_some());
            let cookie = {
                let mut cookie_file = File::open(proto_info.cookie_file.as_ref().unwrap().as_ref()).await.unwrap();
                let mut cookie = Vec::new();
                cookie_file.read_to_end(&mut cookie).await.unwrap();
                assert_eq!(cookie.len(), COOKIE_LENGTH);
                cookie
            };
            utc.authenticate(&TorAuthData::Cookie(Cow::Owned(cookie))).await.unwrap();
            // test conn further?
        });
    }

    #[test]
    fn test_authenticate_fails_when_invalid_method() {
        let c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
                "--CookieAuthentication", "1",
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();
            assert!(!proto_info.auth_methods.contains(&TorAuthMethod::Null));
            utc.authenticate(&TorAuthData::Null).await.unwrap_err();
        });
    }

    #[test]
    fn test_can_safe_cookie_authenticate() {
        let c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
                "--CookieAuthentication", "1",
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();
            // panic!("{:#?}", proto_info);
            assert!(proto_info.auth_methods.contains(&TorAuthMethod::SafeCookie));
            assert!(proto_info.cookie_file.is_some());
            let cookie = {
                let mut cookie_file = File::open(proto_info.cookie_file.as_ref().unwrap().as_ref()).await.unwrap();
                let mut cookie = Vec::new();
                cookie_file.read_to_end(&mut cookie).await.unwrap();
                assert_eq!(cookie.len(), COOKIE_LENGTH);
                cookie
            };
            utc.authenticate(&TorAuthData::SafeCookie(Cow::Owned(cookie))).await.unwrap();
            // test conn further?
        });
    }

    #[test]
    fn test_can_auto_auth_with_null() {
        let c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
                // "--CookieAuthentication", "1",
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();
            let ad = proto_info.make_auth_data().unwrap().unwrap();
            utc.authenticate(&ad).await.unwrap();
            // test conn further?
        });
    }

    #[test]
    fn test_can_auto_auth_with_cookie() {
        let c = run_testing_tor_instance(
            &[
                "--DisableNetwork", "1",
                "--ControlPort", &TOR_TESTING_PORT.to_string(),
                "--CookieAuthentication", "1",
            ]);

        block_on_with_env(async move {
            let mut s = TcpStream::connect(&format!("127.0.0.1:{}", TOR_TESTING_PORT)).await.unwrap();
            let mut utc = UnauthenticatedConn::new(s);
            let proto_info = utc.load_protocol_info().await.unwrap();
            println!("{:#?}", proto_info);
            let ad = proto_info.make_auth_data().unwrap().unwrap();
            utc.authenticate(&ad).await.unwrap();
            // test conn further?
        });
    }
}
