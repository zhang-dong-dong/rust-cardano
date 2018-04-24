extern crate protocol;

use self::protocol::ntt;
use self::protocol::packet;

use std::net::TcpStream;

const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";

fn main() {
    let mut stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true);

    let mut connection = ntt::Connection::handshake(&mut stream).unwrap();
    connection.create_light(1024);
    let mut lwc = ntt::LightConnection::new(&mut connection, 1024);

    let buf = packet::send_handshake(764824073);
    println!("{}", buf.len());

    lwc.send(&buf);

    let (id, dat) = connection.recv_data().unwrap();

    connection.close_light(1024);

}
