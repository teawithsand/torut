use torut::utils::{run_tor, AutoKillChild};
use torut::control::{UnauthenticatedConn, TorAuthMethod, TorAuthData};
use tokio::net::TcpStream;

use std::thread::sleep;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // testing port is 47835
    // it must be free

    let child = run_tor( std::env::var("TORUT_TOR_BINARY").unwrap(), &mut [
        // "--DisableNetwork", "1",
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

    loop {
        println!("getting shared random value...");
        let shared_random = ac.get_info("sr/previous").await.unwrap();
        println!("sr: {}", shared_random);
        sleep(Duration::new(1, 0));
    }
}