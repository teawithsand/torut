use crate::control::conn::Conn;

/// AuthenticatedConn represents connection to TorCP after it has been authenticated so one may
/// perform various operations on it.
///
/// This connection is aware of asynchronous events which may occur sometimes.
///
/// It wraps `Conn`
pub struct AuthenticatedConn<S> {
    conn: Conn<S>,
}

impl<S> From<Conn<S>> for AuthenticatedConn<S> {
    fn from(conn: Conn<S>) -> Self {
        Self {
            conn,
        }
    }
}