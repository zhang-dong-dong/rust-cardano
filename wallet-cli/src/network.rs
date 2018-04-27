use wallet_crypto::util::{hex, base58};
use command::{HasCommand};
use clap::{ArgMatches, Arg, SubCommand, App};
use config::{Config};
use storage::{Storage, blob};
use rand;
use std::net::TcpStream;

use wallet_crypto::config::ProtocolMagic;
use protocol;
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
    }
    fn run(config: Config, args: &ArgMatches) -> Self::Output {
        match args.subcommand() {
            ("get-block-header", _) => {
                let mut net = Network::new(&config);
                let mut mbh = GetBlockHeader::first().execute(&mut net.0)
                    .expect("to get one header at least");
                println!("prv block header: {}", mbh.previous_header);
            },
            ("get-block", Some(opt)) => {
                let hh_hex = value_t!(opt.value_of("blockid"), String).unwrap();
                let hh_bytes = hex::decode(&hh_hex);
                let hh = protocol::packet::HeaderHash::from_slice(&hh_bytes).expect("blockid invalid");
                let mut net = Network::new(&config);
                let mut b = GetBlock::only(hh.clone()).execute(&mut net.0)
                    .expect("to get one block at least");
                let storage = Storage::init(config.storage.clone(), config.network_type.clone()).unwrap();
                blob::write(&storage, hh.bytes(), &b);
            },
            _ => {
                println!("{}", args.usage());
                ::std::process::exit(1);
            },
        }
    }
}

