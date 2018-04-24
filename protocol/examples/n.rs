extern crate protocol;

use self::protocol::ntt;
use self::protocol::packet;

use std::net::TcpStream;

const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";

fn main() {
    let mut stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true).unwrap();

    let mut connection = ntt::Connection::handshake(&mut stream).unwrap();
    connection.create_light(1024);
    let mut lwc = ntt::LightConnection::new(&mut connection, 1024);

    let buf = packet::send_handshake(764824073);
    lwc.send(&buf);
    let buf = packet::send_hardcoded_blob_after_handshake();
    lwc.send(&buf);

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

    connection.close_light(1024);
}
