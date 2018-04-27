use wallet_crypto::util::{hex};
use wallet_crypto::{cbor};
use command::{HasCommand};
use clap::{ArgMatches, Arg, SubCommand, App};
use config::{Config};
use storage::{Storage, StorageConfig, blob, tag};
use rand;
use std::net::TcpStream;

use protocol;
use protocol::packet;
use protocol::packet::block;
use protocol::command::*;

pub struct Network(protocol::Connection<TcpStream>);
impl Network {
    fn new(cfg: &Config) -> Self {
        let drg_seed = rand::random();
        let mut hs = protocol::packet::Handshake::default();
        hs.protocol_magic = cfg.protocol_magic;

        let stream = TcpStream::connect(cfg.network_domain.clone()).unwrap();
        stream.set_nodelay(true).unwrap();

        let conn = protocol::ntt::Connection::handshake(drg_seed, stream).unwrap();
        Network(protocol::Connection::new(conn, &hs))
    }
}

impl HasCommand for Network {
    type Output = ();

    fn clap_options<'a, 'b>() -> App<'a, 'b> {
        SubCommand::with_name("network")
            .about("blockchain network operation")
            .subcommand(SubCommand::with_name("get-block-header")
                .about("get a given block header")
            )
            .subcommand(SubCommand::with_name("get-block")
                .about("get a given block")
                .arg(Arg::with_name("blockid").help("hexadecimal encoded block id").index(1).required(true))
            )
            .subcommand(SubCommand::with_name("sync")
                .about("get the next block repeatedly")
            )
    }
    fn run(config: Config, args: &ArgMatches) -> Self::Output {
        match args.subcommand() {
            ("get-block-header", _) => {
                let mut net = Network::new(&config);
                let mut mbh = GetBlockHeader::first().execute(&mut net.0)
                    .expect("to get one header at least");
                let store_config = StorageConfig::new(&config.storage, &config.network_type);
                let storage = Storage::init(&store_config).unwrap();
                tag::write(&storage, "HEAD", mbh.previous_header.as_ref());
                println!("prv block header: {}", mbh.previous_header);
            },
            ("get-block", Some(opt)) => {
                let hh_hex = value_t!(opt.value_of("blockid"), String).unwrap();
                let hh_bytes = hex::decode(&hh_hex);
                let hh = protocol::packet::HeaderHash::from_slice(&hh_bytes).expect("blockid invalid");
                let mut net = Network::new(&config);
                let mut b = GetBlock::only(hh.clone()).execute(&mut net.0)
                    .expect("to get one block at least");
                let store_config = StorageConfig::new(&config.storage, &config.network_type);
                let storage = Storage::init(&store_config).unwrap();
                blob::write(&storage, hh.bytes(), &b[2..]);
            },
            ("sync", _) => {
                let store_config = StorageConfig::new(&config.storage, &config.network_type);
                let storage = Storage::init(&store_config).unwrap();

                let genesis_tag = tag::read(&storage, "GENESIS").or_else(|| {
                    tag::read(&storage, "HEAD")
                }).unwrap();

                let hh = protocol::packet::HeaderHash::from_slice(&genesis_tag).expect("blockid invalid");
                let mut net = Network::new(&config);
                let mut b = GetBlock::only(hh.clone()).execute(&mut net.0)
                    .expect("to get one block at least");
                blob::write(&storage, hh.bytes(), &b[2..]);
                let blk : packet::block::Block = cbor::decode_from_cbor(&b[2..]).unwrap();
                match blk {
                    block::Block::MainBlock(blk) => {
                        tag::write(&storage, "GENESIS", blk.header.previous_header.as_ref());
                    }
                }
            },
            _ => {
                println!("{}", args.usage());
                ::std::process::exit(1);
            },
        }
    }
}

