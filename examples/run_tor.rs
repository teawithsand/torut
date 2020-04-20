use torut::utils::{run_tor, AutoKillChild};
use torut::control::{UnauthenticatedConn, AuthenticatedConn, TorAuthMethod, TorAuthData};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    // testing port is 47835
    // it must be free

    let child = run_tor("../tor_runnable", &mut [
        "--DisableNetwork", "1",
        "--ControlPort", "47835",
        // "--CookieAuthentication", "1",
    ].iter()).expect("Starting tor filed");
    let _child = AutoKillChild::new(child);

    let mut s = TcpStream::connect(&format!("127.0.0.1:{}", 47835)).await.unwrap();
    let mut utc = UnauthenticatedConn::new(s);
    let proto_info = utc.load_protocol_info().await.unwrap();

    assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null), "Null authentication is not allowed");
    utc.authenticate(&TorAuthData::Null).await.unwrap();
    let mut ac = utc.into_authenticated().await;
    ac.set_async_event_handler(Some(|_| {
        async move { Ok(()) }
    }));

    ac.take_ownership().await.unwrap();

    let socksport = ac.get_info("net/listeners/socks").await.unwrap();
    println!("Tor is running now. It's socks port is listening(or not) on: {:?} but it's not connected to the network because DisableNetwork is set", socksport);

    let controlport = ac.get_info("net/listeners/control").await.unwrap();
    println!("Tor is running now. It's control port listening on: {:?}", controlport);
}