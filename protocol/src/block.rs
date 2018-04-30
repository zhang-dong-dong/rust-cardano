use std::collections::{LinkedList};
use std::{fmt};
use wallet_crypto::cbor::{Value, ExtendedResult};
use wallet_crypto::{cbor, util};
use wallet_crypto::config::{ProtocolMagic};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Version {
   major:    u32, 
   minor:    u32, 
   revision: u32, 
}
impl Version {
    pub fn new(major: u32, minor: u32, revision: u32) -> Self {
        Version { major: major, minor: minor, revision: revision }
    }
}
impl Default for Version {
    fn default() -> Self { Version::new(0,1,0) }
}
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.revision)
    }
}
impl cbor::CborValue for Version {
    fn encode(&self) -> cbor::Value {
        cbor::Value::Array(
            vec![
                cbor::CborValue::encode(&self.major),
                cbor::CborValue::encode(&self.minor),
                cbor::CborValue::encode(&self.revision),
            ]
        )
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.array().and_then(|array| {
            let (array, major)    = cbor::array_decode_elem(array, 0).embed("major")?;
            let (array, minor)    = cbor::array_decode_elem(array, 0).embed("minor")?;
            let (array, revision) = cbor::array_decode_elem(array, 0).embed("revision")?;
            if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
            Ok(Version::new(major, minor, revision))
        }).embed("while decoding Version")
    }
}

const HASH_SIZE : usize = 32;

#[derive(Clone)]
pub struct HeaderHash([u8;HASH_SIZE]);
impl AsRef<[u8]> for HeaderHash { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl fmt::Debug for HeaderHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", util::hex::encode(self.as_ref()))
    }
}
impl fmt::Display for HeaderHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", util::hex::encode(self.as_ref()))
    }
}

impl HeaderHash {
    pub fn bytes<'a>(&'a self) -> &'a [u8;HASH_SIZE] { &self.0 }
    pub fn from_bytes(bytes :[u8;HASH_SIZE]) -> Self { HeaderHash(bytes) }
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HASH_SIZE { return None; }
        let mut buf = [0;HASH_SIZE];

        buf[0..HASH_SIZE].clone_from_slice(bytes);
        Some(Self::from_bytes(buf))
    }
}
impl cbor::CborValue for HeaderHash {
    fn encode(&self) -> cbor::Value { cbor::Value::Bytes(cbor::Bytes::from_slice(self.as_ref())) }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.bytes().and_then(|bytes| {
            match Self::from_slice(bytes.as_ref()) {
                Some(digest) => Ok(digest),
                None         => {
                    cbor::Result::bytes(bytes, cbor::Error::InvalidSize(HASH_SIZE))
                }
            }
        }).embed("while decoding Hash")
    }
}

type Todo = Vec<Value>;

#[derive(Debug)]
pub struct MainBlockHeader {
    pub protocol_magic: ProtocolMagic,
    pub previous_header: HeaderHash,
    pub body_proof: Todo,
    pub consensus: Todo,
    pub extra_data: Todo
}
impl fmt::Display for MainBlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!( f
              , "Magic: 0x{:?} Previous Header: {}"
              , self.protocol_magic
              , self.previous_header
              )
    }
}
impl MainBlockHeader {
   pub fn new(pm: ProtocolMagic, pb: HeaderHash, bp: Todo, c: Todo, ed: Todo) -> Self {
        MainBlockHeader {
            protocol_magic: pm,
            previous_header: pb,
            body_proof: bp,
            consensus: c,
            extra_data: ed
        }
   }
}

impl cbor::CborValue for MainBlockHeader {
    fn encode(&self) -> cbor::Value {
        unimplemented!()
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.array().and_then(|array| {
            let (array, p_magic)    = cbor::array_decode_elem(array, 0).embed("protocol magic")?;
            let (array, prv_header) = cbor::array_decode_elem(array, 0).embed("Previous Header Hash")?;
            let (array, body_proof) = cbor::array_decode_elem(array, 0).embed("body proof")?;
            let (array, consensus)  = cbor::array_decode_elem(array, 0).embed("consensus")?;
            let (array, extra_data) = cbor::array_decode_elem(array, 0).embed("extra_data")?;
            if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
            Ok(MainBlockHeader::new(p_magic, prv_header, body_proof, consensus, extra_data))
        }).embed("While decoding a MainBlockHeader")
    }
}

#[derive(Debug)]
pub enum BlockHeader {
    // Todo: GenesisBlockHeader
    MainBlockHeader(MainBlockHeader)
}
impl fmt::Display for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &BlockHeader::MainBlockHeader(ref mbh) => {
                write!(f, "{}", mbh)
            }
        }
    }
}

impl cbor::CborValue for BlockHeader {
    fn encode(&self) -> cbor::Value {
        match self {
            &BlockHeader::MainBlockHeader(ref mbh) => {
                cbor::Value::Array(
                   vec![cbor::Value::U64(1), cbor::CborValue::encode(mbh)]
                )
            }
        }
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.array().and_then(|array| {
            let (array, code)  = cbor::array_decode_elem(array, 0).embed("enumeration code")?;
            if code == 1u64 {
                let (array, mbh) = cbor::array_decode_elem(array, 0)?;
                if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
                Ok(BlockHeader::MainBlockHeader(mbh))
            } else {
                cbor::Result::array(array, cbor::Error::InvalidSumtype(code))
            }
        })
    }
}

pub mod main {
    use super::*;
    use wallet_crypto::{tx, cbor};
    use std::{fmt};

    #[derive(Debug)]
    pub struct TxPayload {
        pub txaux: LinkedList<tx::TxAux>
        // txs: LinkedList<tx::Tx>,
        // witnesses: LinkedList<Vec<tx::TxInWitness>>
    }
    impl fmt::Display for TxPayload {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            if self.txaux.is_empty() {
                return write!(f, "<no transactions>");
            }
            for txaux in self.txaux.iter() {
                writeln!(f, "{}", txaux)?;
            }
            write!(f, "")
        }
    }
    impl TxPayload {
        // pub fn new(txs: LinkedList<tx::Tx>, wts: LinkedList<Vec<tx::TxInWitness>>) -> Self {
            // TxPayload { txs: txs, witnesses: wts }
        pub fn new(txaux: LinkedList<tx::TxAux>) -> Self {
            TxPayload { txaux: txaux }
            // TxPayload { txs: txs, witnesses: wts }
        }
        pub fn empty() -> Self {
            TxPayload::new(LinkedList::new())
            // TxPayload::new(LinkedList::new(), LinkedList::new())
        }
    }
    impl cbor::CborValue for TxPayload {
        fn encode(&self) -> cbor::Value {
            unimplemented!()
        }
        fn decode(value: cbor::Value) -> cbor::Result<Self> {
            value.iarray().and_then(|array| {
                let mut l = LinkedList::new();
                for i in array {
                    l.push_back(cbor::CborValue::decode(i)?);
                }
                Ok(TxPayload::new(l))
            }).embed("While decoding TxPayload")
        }
    }

    #[derive(Debug)]
    pub struct Body {
        pub tx: TxPayload,
        pub scc: cbor::Value,
        pub delegation: cbor::Value,
        pub update: cbor::Value
    }
    impl Body {
        pub fn new(tx: TxPayload, scc: cbor::Value, dlg: cbor::Value, upd: cbor::Value) -> Self {
            Body { tx: tx, scc: scc, delegation: dlg, update: upd }
        }
    }
    impl fmt::Display for Body {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.tx)
        }
    }
    impl cbor::CborValue for Body {
        fn encode(&self) -> cbor::Value {
            unimplemented!()
        }
        fn decode(value: cbor::Value) -> cbor::Result<Self> {
            value.array().and_then(|array| {
                let (array, tx)  = cbor::array_decode_elem(array, 0).embed("tx")?;
                let (array, scc) = cbor::array_decode_elem(array, 0).embed("scc")?;
                let (array, dlg) = cbor::array_decode_elem(array, 0).embed("dlg")?;
                let (array, upd) = cbor::array_decode_elem(array, 0).embed("update")?;
                if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
                Ok(Body::new(tx, scc, dlg, upd))
            }).embed("While decoding Body")
        }
    }

    #[derive(Debug)]
    pub struct Block {
        pub header: MainBlockHeader,
        pub body: Body,
        pub extra: cbor::Value
    }
    impl Block {
        pub fn new(h: MainBlockHeader, b: Body, e: cbor::Value) -> Self {
            Block { header: h, body: b, extra: e }
        }
    }
    impl fmt::Display for Block {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            writeln!(f, "{}", self.header)?;
            write!(f, "{}", self.body)
        }
    }
    impl cbor::CborValue for Block {
        fn encode(&self) -> cbor::Value {
            unimplemented!()
        }
        fn decode(value: cbor::Value) -> cbor::Result<Self> {
            value.array().and_then(|array| {
                let (array, header) = cbor::array_decode_elem(array, 0).embed("header")?;
                let (array, body)   = cbor::array_decode_elem(array, 0).embed("body")?;
                let (array, extra)  = cbor::array_decode_elem(array, 0).embed("extra")?;
                if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
                Ok(Block::new(header, body, extra))
            }).embed("While decoding block::Block")
        }
    }
}

#[derive(Debug)]
pub enum Block {
    MainBlock(main::Block)
}
impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Block::MainBlock(ref blk) => write!(f, "{}", blk)
        }
    }
}

impl cbor::CborValue for Block {
    fn encode(&self) -> cbor::Value {
        unimplemented!()
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.array().and_then(|array| {
            let (array, code)  = cbor::array_decode_elem(array, 0).embed("enumeration code")?;
            // if code == 0u64 { TODO: support genesis::Block
            if code == 1u64 {
                let (array, blk) = cbor::array_decode_elem(array, 0)?;
                if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
                Ok(Block::MainBlock(blk))
            } else {
                cbor::Result::array(array, cbor::Error::InvalidSumtype(code))
            }
        }).embed("While decoding block::Block")
    }
}
