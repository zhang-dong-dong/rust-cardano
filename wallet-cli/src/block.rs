use wallet_crypto::util::{hex};
use command::{HasCommand};
use clap::{ArgMatches, Arg, SubCommand, App};
use config::{Config};
use storage::{Storage, StorageConfig, blob, block_location, block_read_location};
use wallet_crypto::cbor;

use ansi_term::Colour::*;

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
                let hh_bytes = hex::decode(&hh_hex).unwrap();
                let hh = protocol::block::HeaderHash::from_slice(&hh_bytes).expect("blockid invalid");
                let store_config = StorageConfig::new(&config.storage, &config.network_type);
                let storage = Storage::init(&store_config).unwrap();

                match block_location(&storage, hh.bytes()) {
                    None => {
                        println!("Error: block `{}' does not exit", hh);
                        ::std::process::exit(1);
                    },
                    Some(loc) => {
                        match block_read_location(&storage, &loc, hh.bytes()) {
                            None        => println!("error while reading"),
                            Some(bytes) => {
                                let blk : protocol::block::Block = cbor::decode_from_cbor(&bytes).unwrap();
                                println!("blk location: {:?}", loc);
                                match blk {
                                    protocol::block::Block::MainBlock(mblock) => {
                                        let hdr = mblock.header;
                                        let body = mblock.body;
                                        println!("### Header");
                                        println!("{} : {}"  , Green.paint("protocol magic"), hdr.protocol_magic);
                                        println!("{} : {}"  , Green.paint("previous hash "), hex::encode(hdr.previous_header.as_ref()));
                                        println!("{} : {:?}", Green.paint("body proof    "), hdr.body_proof);
                                        println!("{} : {:?}", Green.paint("consensus     "), hdr.consensus);
                                        println!("{} : {:?}", Green.paint("extra-data    "), hdr.extra_data);
                                        println!("### Body");
                                        println!("{}", Green.paint("tx-payload"));
                                        for e in body.tx.iter() {
                                            println!("  {}", e);
                                        }
                                        println!("{} : {:?}", Green.paint("scc           "), body.scc);
                                        println!("{} : {:?}", Green.paint("delegation    "), body.delegation);
                                        println!("{} : {:?}", Green.paint("update        "), body.update);
                                        println!("### Extra");
                                        println!("{} : {:?}", Green.paint("extra         "), mblock.extra);
                                        //println!("{}: {}", Red.paint("protocol magic:"), mblock.protocol.magic);
                                    },
                                }
                                //println!("[header]");
                                //println!("");
                                //println!("{}: {}", Red.paint("hash"));
                                //println!("{}", blk);
                            }
                        }
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


