use torut::utils::{run_tor, AutoKillChild};
use torut::control::{UnauthenticatedConn, TorAuthMethod, TorAuthData};
use tokio::net::TcpStream;

use std::net::{SocketAddr, IpAddr, Ipv4Addr};

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

    let s = TcpStream::connect(&format!("127.0.0.1:{}", 47835)).await.unwrap();
    let mut utc = UnauthenticatedConn::new(s);
    let proto_info = utc.load_protocol_info().await.unwrap();

    assert!(proto_info.auth_methods.contains(&TorAuthMethod::Null), "Null authentication is not allowed");
    utc.authenticate(&TorAuthData::Null).await.unwrap();
    let mut ac = utc.into_authenticated().await;
    ac.set_async_event_handler(Some(|_| {
        async move { Ok(()) }
    }));

    ac.take_ownership().await.unwrap();

    let key = torut::onion::TorSecretKeyV3::generate();
    println!("Generated new onion service v3 key for address: {}", key.public().get_onion_address());

    println!("Adding onion service v3...");
    ac.add_onion_v3(&key, false, false, false, None, &mut [
        (15787, SocketAddr::new(IpAddr::from(Ipv4Addr::new(127,0,0,1)), 15787)),
    ].iter()).await.unwrap();
    println!("Added onion service v3!");

    println!("Now after enabling network clients should be able to connect to this port");

    println!("Deleting created onion service...");
    // delete onion service so it works no more
    ac.del_onion(&key.public().get_onion_address().get_address_without_dot_onion()).await.unwrap();
    println!("Deleted created onion service! It runs no more!");
}