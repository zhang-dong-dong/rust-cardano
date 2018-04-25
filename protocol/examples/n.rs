extern crate protocol;
extern crate wallet_crypto;

use self::protocol::ntt;
use self::protocol::packet;

use wallet_crypto::cbor;
use std::net::TcpStream;

const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";
const LIGHT_CONNECTION_ID : ntt::LightweightConnectionId = 0x400;
const PROTOCOL_MAGIC : u32 = 764824073;

fn main() {
    let stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true).unwrap();

    let mut connection = ntt::Connection::handshake(stream).unwrap();
    let lwc = LIGHT_CONNECTION_ID;
    connection.create_light(lwc);

    let buf = packet::send_handshake(PROTOCOL_MAGIC);
    connection.light_send_data(lwc, &buf);
    let buf = packet::send_hardcoded_blob_after_handshake();
    connection.light_send_data(lwc, &buf);

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
                            println!("previous block: {}", bh.previous_block);
                            let (id2, dat2) = packet::send_msg_getheaders(&[], Some(&bh.previous_block));
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
