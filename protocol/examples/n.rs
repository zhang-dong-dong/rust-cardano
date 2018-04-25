extern crate protocol;

use self::protocol::ntt;
use self::protocol::packet;

use std::net::TcpStream;

const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";
const LIGHT_CONNECTION_ID : ntt::LightweightConnectionId = 0x400;
const PROTOCOL_MAGIC : u32 = 764824073;

fn main() {
    let stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true).unwrap();

    let mut connection = ntt::Connection::handshake(stream).unwrap();
    connection.create_light(LIGHT_CONNECTION_ID);

    let buf = packet::send_handshake(PROTOCOL_MAGIC);
    connection.light_send_data(LIGHT_CONNECTION_ID, &buf);
    let buf = packet::send_hardcoded_blob_after_handshake();
    connection.light_send_data(LIGHT_CONNECTION_ID, &buf);

    match connection.recv().unwrap() {
        ntt::protocol::Command::Control(_,_) => println!("control"),
        ntt::protocol::Command::Data(_,_)    => println!("data"),
    }
    match connection.recv().unwrap() {
        ntt::protocol::Command::Data(_,len)  => {
            let dat = connection.recv_len(len);
            println!("received data len {}", len);
        },
        _ => println!("error")
    }
    //let (id, dat) = connection.recv_data().unwrap();

    connection.close_light(LIGHT_CONNECTION_ID);
}
