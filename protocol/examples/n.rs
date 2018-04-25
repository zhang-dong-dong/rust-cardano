extern crate protocol;
extern crate wallet_crypto;

use self::protocol::ntt;
use self::protocol::packet;

use protocol::{Connection, LightConnection, LightId};
use wallet_crypto::cbor;
use std::net::TcpStream;

const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";
const LIGHT_CONNECTION_ID : ntt::LightweightConnectionId = 0x400;
const PROTOCOL_MAGIC : u32 = 764824073;

fn main() {
    let stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true).unwrap();

    let conn = ntt::Connection::handshake(stream).unwrap();
    let mut connection = Connection::new(conn);

    let lwc = LightId::new(LIGHT_CONNECTION_ID);

    connection.new_light_connection(lwc);

    // we are expecting the first broadcast to respond a connection ack
    connection.broadcast();
    match connection.poll() {
        Some(lc) => {
            assert!(lc.id() == lwc);
            assert!(lc.connected());
        },
        None {
            panic!("connection failed")
        }
    };

    connection.send_bytes(lwc, &packet::send_handshake(PROTOCOL_MAGIC));
    connection.send_bytes(lwc, &packet::send_hardcoded_blob_after_handshake());

    match connection.recv().unwrap() {
        ntt::protocol::Command::Data(_,len)  => {
            let dat = connection.recv_len(len);
            println!("received data len {}", len);
        },
        _ => println!("error")
    }
    //let (id, dat) = connection.recv_data().unwrap();
    let (id, dat) = packet::send_msg_getheaders(&[], None);
    connection.light_send_data(lwc, &[id]);
    connection.light_send_data(lwc, &dat[..]);

    match connection.recv().unwrap() {
        ntt::protocol::Command::Data(_,len)  => {
            let dat = connection.recv_len(len);
            println!("received data len {}", len);
        },
        _ => println!("error")
    }
    match connection.recv().unwrap() {
        ntt::protocol::Command::Data(_,len)  => {
            let dat = connection.recv_len(len).unwrap();
            let l : packet::BlockHeaderResponse = cbor::decode_from_cbor(&dat).unwrap();
            println!("{}", l);

            match l {
                packet::BlockHeaderResponse::Ok(ll) =>
                    match ll.front() {
                        Some(packet::BlockHeader::MainBlockHeader(bh)) => {
                            println!("previous block: {}", bh.previous_header);
                            let (id2, dat2) = packet::send_msg_getheaders(&[], Some(&bh.previous_header));
                            connection.light_send_data(lwc, &[id2]);
                            connection.light_send_data(lwc, &dat2[..]);
                            match connection.recv().unwrap() {
                                ntt::protocol::Command::Data(_,len)  => {
                                    let dat = connection.recv_len(len).unwrap();
                                    let x : packet::BlockHeaderResponse = cbor::decode_from_cbor(&dat).unwrap();
                                    println!("previous block is: {:?}", x)
                                },
                                ntt::protocol::Command::Control(x, y) => {
                                    println!("control taken error {:?} {}", x, y)
                                }
                            }
                        },
                        _  => println!("error no block header"),
                    }
            }


            //let l : packet::BlockHeaderResponse = cbor::decode_from_cbor(&dat).unwrap();
            //println!("{}", l);
        },
        _ => println!("error")
    }

    connection.close_light(lwc);
}
