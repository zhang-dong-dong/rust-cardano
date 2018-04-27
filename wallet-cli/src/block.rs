use wallet_crypto::util::{hex};
use command::{HasCommand};
use clap::{ArgMatches, Arg, SubCommand, App};
use config::{Config};
use storage::{Storage, blob};
use wallet_crypto::cbor;

use protocol;
use protocol::{packet};

pub struct Block;

impl HasCommand for Block {
    type Output = ();

    fn clap_options<'a, 'b>() -> App<'a, 'b> {
        SubCommand::with_name("block")
            .about("block/blobs operations")
            .subcommand(SubCommand::with_name("cat")
                .about("show content of a block")
                .arg(Arg::with_name("blockid").help("hexadecimal encoded block id").index(1).required(true))
            )
    }
    fn run(config: Config, args: &ArgMatches) -> Self::Output {
        match args.subcommand() {
            ("cat", Some(opt)) => {
                let hh_hex = value_t!(opt.value_of("blockid"), String).unwrap();
                let hh_bytes = hex::decode(&hh_hex);
                let hh = protocol::packet::HeaderHash::from_slice(&hh_bytes).expect("blockid invalid");
                let storage = Storage::init(config.storage.clone(), config.network_type.clone()).unwrap();
                if ! blob::exist(&storage, hh.bytes()) {
                    println!("Error: block `{}' does not exit", hh);
                    ::std::process::exit(1);
                }
                let bytes = blob::read(&storage, hh.bytes());

                let blk : packet::block::Block = cbor::decode_from_cbor(&bytes).unwrap();
                println!("Block: {:?}", blk);
            },
            _ => {
                println!("{}", args.usage());
                ::std::process::exit(1);
            },
        }
    }
}


