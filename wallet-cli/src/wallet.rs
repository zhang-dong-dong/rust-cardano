use wallet_crypto::{wallet, bip44, bip39};
use wallet_crypto::util::base58;
use command::{HasCommand};
use clap::{ArgMatches, Arg, SubCommand, App};
use config::{Config};
use account::{Account};
use rand;

use termion::{style, color, clear, cursor};
use termion::input::TermRead;
use std::io::{Write, stdout, stdin};

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet(wallet::Wallet);
impl Wallet {
    fn generate(seed: bip39::Seed) -> Self {
        Wallet(wallet::Wallet::new_from_bip39(&seed))
    }
}

impl HasCommand for Wallet {
    type Output = Option<Config>;

    fn clap_options<'a, 'b>() -> App<'a, 'b> {
        SubCommand::with_name("wallet")
            .about("wallet management")
            .subcommand(SubCommand::with_name("generate")
                .about("generate a new wallet")
                .arg(Arg::with_name("LANGUAGE")
                    .long("language")
                    .takes_value(true)
                    .value_name("LANGUAGE")
                    .possible_values(&["english"])
                    .help("use the given language for the mnemonic")
                    .required(false)
                    .default_value(r"english")
                )
                .arg(Arg::with_name("MNEMONIC SIZE")
                    .long("number-of-mnemonic-words")
                    .takes_value(true)
                    .value_name("MNEMOENIC_SIZE")
                    .possible_values(&["12", "15", "18", "21", "24"])
                    .help("set the number of the mnemonic words")
                    .required(false)
                    .default_value(r"15")
                )
                .arg(Arg::with_name("PASSWORD")
                    .long("--password")
                    .takes_value(true)
                    .value_name("PASSWORD")
                    .help("set the password from the CLI instead of prompting for it. It is quite unsafe as the password can be visible from your shell history.")
                    .required(false)
                )
            )
            .subcommand(SubCommand::with_name("recover")
                .about("recover a wallet from bip39 mnemonics")
                .arg(Arg::with_name("LANGUAGE")
                    .long("language")
                    .takes_value(true)
                    .value_name("LANGUAGE")
                    .possible_values(&["english"])
                    .help("use the given language for the mnemonic")
                    .required(false)
                    .default_value(r"english")
                )
                .arg(Arg::with_name("PASSWORD")
                    .long("--password")
                    .takes_value(true)
                    .value_name("PASSWORD")
                    .help("set the password from the CLI instead of prompting for it. It is quite unsafe as the password can be visible from your shell history.")
                    .required(false)
                )
            )
            .subcommand(SubCommand::with_name("address")
                .about("create an address with the given options")
                .arg(Arg::with_name("is_internal").long("internal").help("to generate an internal address (see BIP44)"))
                .arg(Arg::with_name("account").help("account to generate an address in").index(1).required(true))
                .arg(Arg::with_name("indices")
                    .help("list of indices for the addresses to create")
                    .multiple(true)
                )
            )
    }
    fn run(config: Config, args: &ArgMatches) -> Self::Output {
        let mut cfg = config;
        match args.subcommand() {
            ("generate", Some(opts)) => {
                // expect no existing wallet
                assert!(cfg.wallet.is_none());
                let language    = value_t!(opts.value_of("LANGUAGE"), String).unwrap(); // we have a default value
                let mnemonic_sz = value_t!(opts.value_of("MNEMONIC SIZE"), bip39::Type).unwrap();
                let password    = value_t!(opts.value_of("PASSWORD"), String).ok();
                let seed = generate_entropy(language, password, mnemonic_sz);
                cfg.wallet = Some(Wallet::generate(seed));
                let _storage = cfg.get_storage().unwrap();
                Some(cfg) // we need to update the config's wallet
            },
            ("recover", Some(opts)) => {
                // expect no existing wallet
                assert!(cfg.wallet.is_none());
                let language    = value_t!(opts.value_of("LANGUAGE"), String).unwrap(); // we have a default value
                let password    = value_t!(opts.value_of("PASSWORD"), String).ok();
                let seed = recover_entropy(language, password);
                cfg.wallet = Some(Wallet::generate(seed));
                let _storage = cfg.get_storage().unwrap();
                Some(cfg) // we need to update the config's wallet
            },
            ("address", Some(opts)) => {
                // expect existing wallet
                assert!(cfg.wallet.is_some());
                match &cfg.wallet {
                    &None => panic!("No wallet created, see `wallet generate` command"),
                    &Some(ref wallet) => {
                        let addr_type = if opts.is_present("is_internal") {
                            bip44::AddrType::Internal
                        } else {
                            bip44::AddrType::External
                        };
                        let account_name = opts.value_of("account")
                            .and_then(|s| Some(Account::new(s.to_string())))
                            .unwrap();
                        let account = match cfg.find_account(&account_name) {
                            None => panic!("no account {:?}", account_name),
                            Some(r) => r,
                        };
                        let indices = values_t!(opts.values_of("indices"), u32).unwrap_or_else(|_| vec![0]);

                        let addresses = wallet.0.gen_addresses(account, addr_type, indices);
                        for addr in addresses {
                            println!("{}", base58::encode(&addr.to_bytes()));
                        };
                        None // we don't need to update the wallet
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

fn get_password() -> String {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    stdout.write_all(b"password: ").unwrap();
    stdout.flush().unwrap();

    let pwd = stdin.read_passwd(&mut stdout).unwrap().unwrap_or("".to_string());
    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();
    pwd
}

fn get_mnemonic_word<D>(index: usize, dic: &D) -> Option<bip39::Mnemonic>
    where D: bip39::dictionary::Language
{
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let mut mmne = None;

    for _ in 0..3 {
        write!(stdout, "mnemonic {}: ", index).unwrap();
        stdout.flush().unwrap();
        let midx = stdin.read_passwd(&mut stdout).unwrap();
        write!(stdout, "{}{}", clear::CurrentLine, cursor::Left(14)).unwrap();
        stdout.flush().unwrap();
        match midx.and_then(|s| if s == "" { None } else { Some(s)}) {
            None => {
                write!(stdout, "{}No mnemonic entered.{} Are you done? (No|yes): ", color::Fg(color::Red), color::Fg(color::Reset)).unwrap();
                stdout.flush().unwrap();
                let mchoice = stdin.read_line().unwrap();
                match mchoice {
                    None => {},
                    Some(choice) => {
                        if choice.to_uppercase() == "YES" { break; }
                    }
                };
            },
            Some(word) => {
                match bip39::Mnemonic::from_word(dic, word.as_str()) {
                    Ok(mne) => { mmne = Some(mne); break; },
                    Err(err) => {
                        writeln!(stdout, "{}Invalid mnemonic{}: {}", color::Fg(color::Red), color::Fg(color::Reset), err).unwrap();
                        stdout.flush().unwrap();
                    }
                }
            }
        }
    }

    mmne
}

fn get_mnemonic_words<D>(dic: &D) -> bip39::Mnemonics
    where D: bip39::dictionary::Language
{
    let mut vec = vec![];

    print!("{}", style::Italic);
    println!("Enter the mnemonic word one by one as prompted.");
    print!("{}", style::NoItalic);

    for index in 1..25 {
        match get_mnemonic_word(index, dic) {
            None => break,
            Some(idx) => vec.push(idx)
        }
    }

    match bip39::Mnemonics::from_mnemonics(vec) {
        Err(err) => { panic!("Invalid mnemonic phrase: {}", err); },
        Ok(mn) => mn
    }
}

fn generate_entropy(language: String, opt_pwd: Option<String>, t: bip39::Type) -> bip39::Seed {
    assert!(language == "english");
    let dic = &bip39::dictionary::ENGLISH;

    let pwd = match opt_pwd {
        Some(pwd) => pwd,
        None => get_password()
    };

    let entropy = bip39::Entropy::generate(t, rand::random);

    let mnemonic = entropy.to_mnemonics().to_string(dic);
    println!("mnemonic: {}", mnemonic);

    bip39::Seed::from_mnemonic_string(&mnemonic, pwd.as_bytes())
}

fn recover_entropy(language: String, opt_pwd: Option<String>) -> bip39::Seed {
    assert!(language == "english");
    let dic = &bip39::dictionary::ENGLISH;

    let mnemonics = get_mnemonic_words(dic);

    let pwd = match opt_pwd {
        Some(pwd) => pwd,
        None => get_password()
    };

    let mnemonics_str = mnemonics.to_string(dic);

    bip39::Seed::from_mnemonic_string(&mnemonics_str, pwd.as_bytes())
}