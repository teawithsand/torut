use torut::utils::{run_tor, AutoKillChild};
use torut::control::{UnauthenticatedConn};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    // testing port is 47835
    // it must be free

    let child = run_tor(std::env::var("TORUT_TOR_BINARY").unwrap(), &mut [
        "--DisableNetwork", "1",
        "--ControlPort", "47835",
        "--CookieAuthentication", "1",
    ].iter()).expect("Starting tor filed");
    let _child = AutoKillChild::new(child);

    let s = TcpStream::connect(&format!("127.0.0.1:{}", 47835)).await.unwrap();
    let mut utc = UnauthenticatedConn::new(s);
    let proto_info = utc.load_protocol_info().await.unwrap();
    let ad = proto_info.make_auth_data().unwrap().unwrap();

    utc.authenticate(&ad).await.unwrap();
    let mut ac = utc.into_authenticated().await;
    ac.set_async_event_handler(Some(|_| {
        async move { Ok(()) }
    }));

    ac.take_ownership().await.unwrap();

    println!("Now we can use tor conn. We are now forced to use cookie auth due to different tor config.");
}