extern crate protocol;
extern crate wallet_crypto;

use self::protocol::ntt;
use self::protocol::packet;

use protocol::{Connection, LightConnection, LightId};
use wallet_crypto::cbor;
use std::net::TcpStream;

const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";
const LIGHT_CONNECTION_ID : ntt::LightweightConnectionId = 0x401;
const PROTOCOL_MAGIC : u32 = 764824073;

fn main() {
    let stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true).unwrap();

    let conn = ntt::Connection::handshake(stream).unwrap();
    let mut connection = Connection::new(conn, PROTOCOL_MAGIC);

    let lwc = LightId::new(LIGHT_CONNECTION_ID);
    connection.new_light_connection(lwc);
    connection.broadcast(); // expect ack of connection creation

    // require the initial header
    let (mut get_header_id, mut get_header_dat) = packet::send_msg_getheaders(&[], None);
    let mut max_counter : usize = 3;
    loop {
        max_counter -= 1;
        if max_counter == 0 { break; }
        connection.send_bytes(lwc, &[get_header_id]);
        connection.send_bytes(lwc, &get_header_dat[..]);
        connection.broadcast();
        match connection.poll() {
            Some(lc) => {
                assert!(lc.get_id() == lwc);
                // drop the received data.
                let _ = lc.get_received();
            },
            None => {
                panic!("connection failed");
            }
        };
        connection.broadcast();
        match connection.poll() {
            Some(lc) => {
                assert!(lc.get_id() == lwc);
                if let Some(dat) = lc.get_received() {
                    let l : packet::BlockHeaderResponse = cbor::decode_from_cbor(&dat).unwrap();
                    println!("{}", l);

                    match l {
                        packet::BlockHeaderResponse::Ok(ll) =>
                            match ll.front() {
                                Some(packet::BlockHeader::MainBlockHeader(bh)) => {
                                    println!("previous block: {}", bh.previous_header);
                                    let (id2, dat2) = packet::send_msg_getheaders(&[], Some(&bh.previous_header));
                                    get_header_id = id2;
                                    get_header_dat = dat2;
                                },
                                _  => println!("error no block header"),
                            }
                    }
                }
            },
            None => {
                panic!("connection failed");
            }
        };
    }

    connection.close_light_connection(lwc);
}
