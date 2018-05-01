extern crate protocol;
extern crate wallet_crypto;
extern crate rand;

use protocol::packet::{Handshake};

use protocol::command::{Command};

use protocol::{packet, command, ntt, Connection};
use wallet_crypto::config::{ProtocolMagic};
use std::net::TcpStream;

// mainnet:
// const HOST: &'static str = "relays.cardano-mainnet.iohk.io:3000";
// const PROTOCOL_MAGIC : u32 = 764824073;

// staging:
const HOST: &'static str = "relays.awstest.iohkdev.io:3000";
const PROTOCOL_MAGIC : u32 = 633343913;

const MAX_ALLOWED_ITERATIONS : u32 = 10;

fn main() {
    let drg_seed = rand::random();
    let mut hs = Handshake::default();
    hs.protocol_magic = ProtocolMagic::new(PROTOCOL_MAGIC);

    let stream = TcpStream::connect(HOST).unwrap();
    stream.set_nodelay(true).unwrap();

    let conn = ntt::Connection::handshake(drg_seed, stream).unwrap();
    let mut connection = Connection::new(conn, &hs);

    let mut mbh = command::GetBlockHeader::first().execute(&mut connection)
        .expect("to get one header at least");
    println!("prv block header: {}", mbh.previous_header);

    let mut current = 1;
    loop {
        current += 1;
        if current > (2 + MAX_ALLOWED_ITERATIONS) { break; }

        {
            mbh = command::GetBlockHeader::some(mbh.previous_header)
               .execute(&mut connection).expect("to get one header at least");
            println!("prv block header: {}", mbh.previous_header);
        };

    }

    let prev_blk_id = mbh.previous_header;
    // example below works on mainnet only:
    // let prev_block_id = packet::HeaderHash::from_bytes([0x42, 0x88, 0xff, 0xec, 0x11, 0x22, 0x10, 0x6d, 0xf4, 0x4c, 0xcf, 0x12, 0xfc, 0xfb, 0xde, 0x44, 0xdb, 0xe0, 0x7d, 0x24, 0x5d, 0xba, 0x06, 0x23, 0xba, 0xb8, 0xb8, 0x63, 0xa7, 0x04, 0x85, 0x64]);
    {
        let getter = command::GetBlock::only(prev_blk_id);
        let dat = getter.get_block(connection, id)(&mut connection).expect("to get a block");
        let l : packet::BlockResponse = wallet_crypto::cbor::decode_from_cbor(&dat).unwrap();
        match l {
            packet::BlockResponse::Ok(blk) => {
                println!("Block: {:?}", blk);
            }
        }
    };
}
