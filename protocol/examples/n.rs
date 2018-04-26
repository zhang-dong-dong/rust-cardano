extern crate protocol;
extern crate wallet_crypto;
extern crate rand;

use self::protocol::ntt;
use self::protocol::packet;
use self::protocol::packet::{Handshake};

use protocol::{Connection, LightConnection, LightId};
use wallet_crypto::cbor;
use wallet_crypto::config::{ProtocolMagic};
use std::net::TcpStream;
use std::io::{Read, Write};

// mainnet:
// const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";
// const PROTOCOL_MAGIC : u32 = 764824073;

// staging:
const HOST: &'static str = "relays.awstest.iohkdev.io:3000";
const PROTOCOL_MAGIC : u32 = 633343913;

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
                assert_eq!(lc.get_id(), id);
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

#[derive(Debug)]
struct GetBlock {
    from: packet::HeaderHash,
    to:   packet::HeaderHash
}
impl GetBlock {
    fn only(hh: packet::HeaderHash) -> Self { GetBlock::from(hh.clone(), hh) }
    fn from(from: packet::HeaderHash, to: packet::HeaderHash) -> Self { GetBlock { from: from, to: to } }
}

impl<W> Command<W> for GetBlock where W: Read+Write {
    type Output = packet::block::Block;
    fn execute(&self, connection: &mut Connection<W>, id: LightId) -> Result<Self::Output, &'static str> {
        connection.new_light_connection(id);
        connection.broadcast(); // expect ack of connection creation

        // require the initial header
        let (get_header_id, get_header_dat) = packet::send_msg_getblocks(&self.from, &self.to);
        connection.send_bytes(id, &[get_header_id]);
        connection.send_bytes(id, &get_header_dat[..]);
        connection.broadcast();
        match connection.poll() {
            Some(lc) => {
                assert_eq!(lc.get_id(), id);
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
                    let mut l : packet::BlockResponse = cbor::decode_from_cbor(&dat).unwrap();
                    println!("{:?}", l);

                    match l {
                        packet::BlockResponse::Ok(resp) => Ok(resp),
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

const MAX_ALLOWED_ITERATIONS : u32 = 5;

fn main() {
    let drg_seed = rand::random();
    let mut hs = Handshake::default();
    hs.protocol_magic = ProtocolMagic::new(PROTOCOL_MAGIC);

    let stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true).unwrap();

    let conn = ntt::Connection::handshake(drg_seed, stream).unwrap();
    let mut connection = Connection::new(conn, &hs);

    let mut mbh = GetBlockHeader::first().execute(&mut connection, LightId::new(0x401))
        .expect("to get one header at least");
    println!("prv block header: {}", mbh.previous_header);

    let mut current = 10;
    loop {
        current += 1;
        if current > (10 + MAX_ALLOWED_ITERATIONS) { break; }

        {
            let id = 0x400 + current;
            mbh = GetBlockHeader::some(mbh.previous_header)
               .execute(&mut connection, LightId::new(id)).expect("to get one header at least");
            println!("prv block header: {}", mbh.previous_header);
        };

        current += 1;
        {
            let id = 0x400 + current;
            let blk = GetBlock::only(mbh.previous_header.clone())
                .execute(&mut connection, LightId::new(id)).expect("to get one header at least");
            println!("Block: {:?}", blk);
        };
    }
}
