extern crate protocol;
extern crate wallet_crypto;
extern crate rand;

use self::protocol::ntt;
use self::protocol::packet;

use protocol::{Connection, LightConnection, LightId};
use wallet_crypto::cbor;
use std::net::TcpStream;
use std::io::{Read, Write};

const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";
//const LIGHT_CONNECTION_ID : ntt::LightweightConnectionId = 0x401;
const PROTOCOL_MAGIC : u32 = 764824073;

trait Command<W: Read+Write> {
    type Output;
    fn execute(&self, connection: &mut Connection<W>, id: LightId) -> Result<Self::Output, &'static str>;
}

#[derive(Debug)]
struct GetBlockHeader(Option<packet::HeaderHash>);
impl GetBlockHeader {
    fn first() -> Self { GetBlockHeader(None) }
    fn some(hh: packet::HeaderHash) -> Self { GetBlockHeader(Some(hh)) }
}

impl<W> Command<W> for GetBlockHeader where W: Read+Write {
    type Output = packet::MainBlockHeader;
    fn execute(&self, connection: &mut Connection<W>, id: LightId) -> Result<Self::Output, &'static str> {
        connection.new_light_connection(id);
        connection.broadcast(); // expect ack of connection creation

        // require the initial header
        let (get_header_id, get_header_dat) = packet::send_msg_getheaders(&[], &self.0);
        connection.send_bytes(id, &[get_header_id]);
        connection.send_bytes(id, &get_header_dat[..]);
        connection.broadcast();
        match connection.poll() {
            Some(lc) => {
                assert!(lc.get_id() == id);
                // drop the received data.
                let _ = lc.get_received();
            },
            None => {
                panic!("connection failed");
            }
        };
        connection.broadcast();
        let rep = match connection.poll() {
            Some(lc) => {
                assert!(lc.get_id() == id);
                if let Some(dat) = lc.get_received() {
                    let mut l : packet::BlockHeaderResponse = cbor::decode_from_cbor(&dat).unwrap();
                    println!("{}", l);

                    match l {
                        packet::BlockHeaderResponse::Ok(mut ll) =>
                            match ll.pop_front() {
                                Some(packet::BlockHeader::MainBlockHeader(bh)) => Ok(bh),
                                _  => Err("No first main block header")
                            }
                    }
                } else { Err("No received data...") }
            },
            None => {
                panic!("connection failed");
            }
        };
        connection.close_light_connection(id);

        rep
    }
}


fn main() {
    let drg_seed = rand::random();

    let stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true).unwrap();

    let conn = ntt::Connection::handshake(drg_seed, stream).unwrap();
    let hs = packet::Handshake::default();
    let mut connection = Connection::new(conn, &hs);

    let mut mbh = GetBlockHeader::first().execute(&mut connection, LightId::new(0x401))
        .expect("to get one header at least");
    println!("prv block header: {}", mbh.previous_header);

    for i in 0x402..0x405 {
        mbh = GetBlockHeader::some(mbh.previous_header)
           .execute(&mut connection, LightId::new(i)).expect("to get one header at least");
        println!("prv block header: {}", mbh.previous_header);
    }
}
