use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let sock = UdpSocket::bind("0.0.0.0:11013").await.unwrap();
    match trairi::overlay::upnp::try_map(&sock).await {
        Ok(port) => println!("UPnP mapping OK, external UDP port {port}"),
        Err(e) => println!("UPnP mapping failed: {e:#}"),
    }
}
