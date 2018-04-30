use std::collections::{BTreeMap};
use std::collections::{LinkedList};
use std::{fmt};
use wallet_crypto::cbor::{encode_to_cbor, Value, ObjectKey, Bytes, ExtendedResult};
use wallet_crypto::{cbor, util};
use wallet_crypto::config::{ProtocolMagic};
use block;

type MessageCode = u32;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct HandlerSpec(u16);
impl HandlerSpec {
    pub fn new(c: u16) -> Self { HandlerSpec(c) }
}
impl fmt::Display for HandlerSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl cbor::CborValue for HandlerSpec {
    fn encode(&self) -> cbor::Value {
        let b = cbor::encode_to_cbor(&self.0).unwrap();
        cbor::Value::Array(
            vec![ cbor::Value::U64(0)
                , cbor::Value::Tag(24, Box::new(cbor::Value::Bytes(cbor::Bytes::new(b))))
                ]
        )
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.array().and_then(|array| {
            let (array, id) = cbor::array_decode_elem(array, 0).embed("sum type id")?;
            if id != 0u64 { return cbor::Result::array(array, cbor::Error::InvalidSumtype(id)); }
            let (array, tag) = cbor::array_decode_elem(array, 0).embed("tagged bytes")?;
            if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
            cbor::Value::tag(tag).and_then(|(tag_id, value)| {
                assert!(tag_id == 24);
                value.bytes().and_then(|bs| {
                    cbor::decode_from_cbor(bs.as_ref())
                }).map(|c| HandlerSpec::new(c))
            })
        }).embed("while decoding HandlerSpec")
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct HandlerSpecs(BTreeMap<MessageCode, HandlerSpec>);
impl HandlerSpecs {
    pub fn default_ins() -> Self {
        let mut bm = BTreeMap::new();
        bm.insert(0x04,  HandlerSpec::new(0x05));
        bm.insert(0x05,  HandlerSpec::new(0x04));
        bm.insert(0x06,  HandlerSpec::new(0x07));
        bm.insert(0x22,  HandlerSpec::new(0x5e));
        bm.insert(0x25,  HandlerSpec::new(0x5e));
        bm.insert(0x2b,  HandlerSpec::new(0x5d));
        bm.insert(0x31,  HandlerSpec::new(0x5c));
        bm.insert(0x37,  HandlerSpec::new(0x62));
        bm.insert(0x3d,  HandlerSpec::new(0x61));
        bm.insert(0x43,  HandlerSpec::new(0x60));
        bm.insert(0x49,  HandlerSpec::new(0x5f));
        bm.insert(0x53,  HandlerSpec::new(0x00));
        bm.insert(0x5c,  HandlerSpec::new(0x31));
        bm.insert(0x5d,  HandlerSpec::new(0x2b));
        bm.insert(0x5e,  HandlerSpec::new(0x25));
        bm.insert(0x5f,  HandlerSpec::new(0x49));
        bm.insert(0x60,  HandlerSpec::new(0x43));
        bm.insert(0x61,  HandlerSpec::new(0x3d));
        bm.insert(0x62,  HandlerSpec::new(0x37));
        HandlerSpecs(bm)
    }
    pub fn default_outs() -> Self {
        let mut bm = BTreeMap::new();
        bm.insert(0x04,  HandlerSpec::new(0x05));
        bm.insert(0x05,  HandlerSpec::new(0x04));
        bm.insert(0x06,  HandlerSpec::new(0x07));
        bm.insert(0x0d,  HandlerSpec::new(0x00));
        bm.insert(0x0e,  HandlerSpec::new(0x00));
        bm.insert(0x25,  HandlerSpec::new(0x5e));
        bm.insert(0x2b,  HandlerSpec::new(0x5d));
        bm.insert(0x31,  HandlerSpec::new(0x5c));
        bm.insert(0x37,  HandlerSpec::new(0x62));
        bm.insert(0x3d,  HandlerSpec::new(0x61));
        bm.insert(0x43,  HandlerSpec::new(0x60));
        bm.insert(0x49,  HandlerSpec::new(0x5f));
        bm.insert(0x53,  HandlerSpec::new(0x00));
        HandlerSpecs(bm)
    }
}
impl cbor::CborValue for HandlerSpecs {
    fn encode(&self) -> cbor::Value {
        let bm = self.0.iter().map(|(k,v)| (cbor::ObjectKey::Integer(*k as u64), cbor::CborValue::encode(v))).collect();
        cbor::Value::Object(bm)
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.object().and_then(|object| {
            let mut bm = BTreeMap::new();
            for (&cbor::ObjectKey::Integer(ref k), v) in object.iter() {
                bm.insert(*k as u32, cbor::CborValue::decode(v.clone())?);
            }
            Ok(HandlerSpecs(bm))
        }).embed("while decoding HandlerSpecs")
    }
}
impl fmt::Display for HandlerSpecs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for kv in self.0.iter() {
            write!(f, "  * {} -> {}\n", kv.0, kv.1)?;
        }
        write!(f, "")
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Handshake {
    pub protocol_magic: ProtocolMagic,
    pub version: block::Version,
    pub in_handlers:  HandlerSpecs,
    pub out_handlers: HandlerSpecs
}
impl Handshake {
    pub fn new(pm: ProtocolMagic, v: block::Version, ins: HandlerSpecs, outs: HandlerSpecs) -> Self {
        Handshake {
            protocol_magic: pm,
            version: v,
            in_handlers: ins,
            out_handlers: outs
        }
    }
}
impl fmt::Display for Handshake {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "protocol magic: {:?}", self.protocol_magic)?;
        writeln!(f, "version: {}", self.version)?;
        writeln!(f, "in handlers:\n{}", self.in_handlers)?;
        writeln!(f, "out handlers:\n{}", self.out_handlers)
    }
}
impl Default for Handshake {
    fn default() -> Self {
        Handshake::new(
            ProtocolMagic::default(),
            block::Version::default(),
            HandlerSpecs::default_ins(),
            HandlerSpecs::default_outs(),
        )
    }
}
impl cbor::CborValue for Handshake {
    fn encode(&self) -> cbor::Value {
        cbor::Value::Array(
            vec![
                cbor::CborValue::encode(&self.protocol_magic),
                cbor::CborValue::encode(&self.version),
                cbor::CborValue::encode(&self.in_handlers),
                cbor::CborValue::encode(&self.out_handlers),
            ]
        )
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.array().and_then(|array| {
            let (array, pm)   = cbor::array_decode_elem(array, 0)?;
            let (array, v)    = cbor::array_decode_elem(array, 0)?;
            let (array, ins)  = cbor::array_decode_elem(array, 0)?;
            let (array, outs) = cbor::array_decode_elem(array, 0)?;
            if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
            Ok(Handshake::new(pm, v, ins, outs))
        }).embed("while decoding Version")
    }
}

pub fn send_handshake(hs: &Handshake) -> Vec<u8> {
    cbor::encode_to_cbor(hs).unwrap()
}

pub fn send_hardcoded_blob_after_handshake() -> Vec<u8> {
    vec![
        0x53, 0x78, 0x29, 0x6e, 0xc5, 0xd4, 0x5c, 0x95, 0x24
    ]
}

// Message Header follow by the data
type Message = (u8, Vec<u8>);

const HASH_SIZE : usize = 32;
// TODO move to another crate/module
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

pub enum MsgType {
    MsgSubscribe,
    MsgGetHeaders,
    MsgGetBlocks,
}

impl MsgType {
    pub fn to_u8(self) -> u8 {
        match self {
            MsgType::MsgSubscribe => 0xe,
            MsgType::MsgGetHeaders => 0x4,
            MsgType::MsgGetBlocks => 0x6,
        }
    }
}

pub fn send_msg_subscribe(keep_alive: bool) -> Message {
    let value = if keep_alive { 43 } else { 42 };
    let dat = encode_to_cbor(&Value::U64(value)).unwrap();
    (0xe, dat)
}

pub fn send_msg_getheaders(froms: &[HeaderHash], to: &Option<HeaderHash>) -> Message {
    let mut from_encoded = LinkedList::new();
    for f in froms {
        let b = Bytes::from_slice(f.as_ref());
        from_encoded.push_back(Value::Bytes(b));
    }
    let to_encoded =
        match to {
            &None    => Value::Array(vec![]),
            &Some(ref h) => {
                let b = Bytes::from_slice(h.as_ref());
                Value::Array(vec![Value::Bytes(b)])
            }
        };
    let r = Value::Array(vec![Value::IArray(from_encoded), to_encoded]);
    let dat = encode_to_cbor(&r).unwrap();
    (0x4, dat)
}

pub fn send_msg_getblocks(from: &HeaderHash, to: &HeaderHash) -> Message {
    let from_encoded = Value::Bytes(Bytes::from_slice(from.as_ref()));
    let to_encoded = Value::Bytes(Bytes::from_slice(to.as_ref()));
    let dat = encode_to_cbor(&Value::Array(vec![from_encoded, to_encoded])).unwrap();
    (0x6, dat)
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

#[derive(Debug)]
pub enum BlockHeaderResponse {
    Ok(LinkedList<BlockHeader>)
}
impl fmt::Display for BlockHeaderResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &BlockHeaderResponse::Ok(ref ll) => {
                for i in ll {
                    write!(f, "{}\n", i)?;
                }
            }
        }
        write!(f, "")
    }
}
impl cbor::CborValue for BlockHeaderResponse {
    fn encode(&self) -> cbor::Value {
        match self {
            &BlockHeaderResponse::Ok(ref l) => {
                cbor::Value::Array(
                   vec![ cbor::Value::U64(0)
                       , cbor::CborValue::encode(l)
                       ]
                )
            }
        }
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.array().and_then(|array| {
            let (array, code)  = cbor::array_decode_elem(array, 0).embed("enumeration code")?;
            if code == 0u64 {
                let (array, l) = cbor::array_decode_elem(array, 0)?;
                if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
                Ok(BlockHeaderResponse::Ok(l))
            } else {
                cbor::Result::array(array, cbor::Error::InvalidSumtype(code))
            }
        })
    }
}

pub mod xblock {
    pub mod main {
        use super::super::*;
        use wallet_crypto::{tx, cbor};
        use std::{fmt};

        #[derive(Debug)]
        pub struct TxPayload {
            txaux: LinkedList<tx::TxAux>
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
            tx: TxPayload,
            scc: cbor::Value,
            delegation: cbor::Value,
            update: cbor::Value
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

    use super::*;
    use wallet_crypto::{cbor};

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
}

#[derive(Debug)]
pub enum BlockResponse {
    Ok(xblock::Block)
}
impl cbor::CborValue for BlockResponse {
    fn encode(&self) -> cbor::Value {
        match self {
            &BlockResponse::Ok(ref l) => {
                cbor::Value::Array(
                   vec![ cbor::Value::U64(0)
                       , cbor::CborValue::encode(l)
                       ]
                )
            }
        }
    }
    fn decode(value: cbor::Value) -> cbor::Result<Self> {
        value.array().and_then(|array| {
            let (array, code)  = cbor::array_decode_elem(array, 0).embed("enumeration code")?;
            if code == 0u64 {
                let (array, l) = cbor::array_decode_elem(array, 0)?;
                if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
                Ok(BlockResponse::Ok(l))
            } else {
                cbor::Result::array(array, cbor::Error::InvalidSumtype(code))
            }
        }).embed("While decoding block's response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_crypto::cbor;

    const GET_BLOCK_HEADER_BYTES : &'static [u8] = &[
          0x82, 0x00, 0x9f, 0x82, 0x01, 0x85, 0x1a, 0x2d
        , 0x96, 0x4a, 0x09, 0x58, 0x20, 0x9d, 0x63, 0xd4, 0x66, 0x7d, 0x43, 0x26, 0x09, 0x8b, 0x1a, 0xb9
        , 0xa9, 0x61, 0xef, 0x30, 0x35, 0xbc, 0xe2, 0x49, 0x99, 0x07, 0xa0, 0x31, 0x24, 0x95, 0x5f, 0xbd
        , 0x58, 0xaf, 0x3e, 0xb8, 0xdc, 0x84, 0x83, 0x01, 0x58, 0x20, 0x9a, 0x01, 0x44, 0x1c, 0x71, 0x68
        , 0x84, 0xd9, 0xe3, 0x20, 0xc1, 0xdf, 0xd6, 0x1f, 0x4c, 0x6d, 0xd4, 0x17, 0x8c, 0x6d, 0x8c, 0x56
        , 0xdb, 0x50, 0x98, 0x60, 0xd8, 0x79, 0x10, 0x89, 0xaf, 0xb3, 0x58, 0x20, 0xef, 0xe1, 0x25, 0x42
        , 0xac, 0xc4, 0xc7, 0x7e, 0x48, 0x46, 0x7c, 0xb4, 0x99, 0xb3, 0xbb, 0xb4, 0x22, 0xd6, 0x52, 0x74
        , 0x5e, 0x91, 0xf9, 0xc3, 0x49, 0x82, 0x89, 0xc8, 0xa4, 0xda, 0x21, 0x6b, 0x82, 0x03, 0x58, 0x20
        , 0xd3, 0x6a, 0x26, 0x19, 0xa6, 0x72, 0x49, 0x46, 0x04, 0xe1, 0x1b, 0xb4, 0x47, 0xcb, 0xcf, 0x52
        , 0x31, 0xe9, 0xf2, 0xba, 0x25, 0xc2, 0x16, 0x91, 0x77, 0xed, 0xc9, 0x41, 0xbd, 0x50, 0xad, 0x6c
        , 0x58, 0x20, 0xaf, 0xc0, 0xda, 0x64, 0x18, 0x3b, 0xf2, 0x66, 0x4f, 0x3d, 0x4e, 0xec, 0x72, 0x38
        , 0xd5, 0x24, 0xba, 0x60, 0x7f, 0xae, 0xea, 0xb2, 0x4f, 0xc1, 0x00, 0xeb, 0x86, 0x1d, 0xba, 0x69
        , 0x97, 0x1b, 0x58, 0x20, 0x4e, 0x66, 0x28, 0x0c, 0xd9, 0x4d, 0x59, 0x10, 0x72, 0x34, 0x9b, 0xec
        , 0x0a, 0x30, 0x90, 0xa5, 0x3a, 0xa9, 0x45, 0x56, 0x2e, 0xfb, 0x6d, 0x08, 0xd5, 0x6e, 0x53, 0x65
        , 0x4b, 0x0e, 0x40, 0x98, 0x84, 0x82, 0x18, 0x2a, 0x19, 0x1e, 0x84, 0x58, 0x40, 0x26, 0x56, 0x6e
        , 0x86, 0xfc, 0x6b, 0x9b, 0x17, 0x7c, 0x84, 0x80, 0xe2, 0x75, 0xb2, 0xb1, 0x12, 0xb5, 0x73, 0xf6
        , 0xd0, 0x73, 0xf9, 0xde, 0xea, 0x53, 0xb8, 0xd9, 0x9c, 0x4e, 0xd9, 0x76, 0xb3, 0x35, 0xb2, 0xb3
        , 0x84, 0x2f, 0x0e, 0x38, 0x00, 0x01, 0xf0, 0x90, 0xbc, 0x92, 0x3c, 0xaa, 0x96, 0x91, 0xed, 0x91
        , 0x15, 0xe2, 0x86, 0xda, 0x94, 0x21, 0xe2, 0x74, 0x5c, 0x7a, 0xcc, 0x87, 0xf1, 0x81, 0x1a, 0x00
        , 0x0d, 0xf5, 0xdd, 0x82, 0x02, 0x82, 0x84, 0x00, 0x58, 0x40, 0x26, 0x56, 0x6e, 0x86, 0xfc, 0x6b
        , 0x9b, 0x17, 0x7c, 0x84, 0x80, 0xe2, 0x75, 0xb2, 0xb1, 0x12, 0xb5, 0x73, 0xf6, 0xd0, 0x73, 0xf9
        , 0xde, 0xea, 0x53, 0xb8, 0xd9, 0x9c, 0x4e, 0xd9, 0x76, 0xb3, 0x35, 0xb2, 0xb3, 0x84, 0x2f, 0x0e
        , 0x38, 0x00, 0x01, 0xf0, 0x90, 0xbc, 0x92, 0x3c, 0xaa, 0x96, 0x91, 0xed, 0x91, 0x15, 0xe2, 0x86
        , 0xda, 0x94, 0x21, 0xe2, 0x74, 0x5c, 0x7a, 0xcc, 0x87, 0xf1, 0x58, 0x40, 0xf1, 0x4f, 0x71, 0x2d
        , 0xc6, 0x00, 0xd7, 0x93, 0x05, 0x2d, 0x48, 0x42, 0xd5, 0x0c, 0xef, 0xa4, 0xe6, 0x58, 0x84, 0xea
        , 0x6c, 0xf8, 0x37, 0x07, 0x07, 0x9e, 0xb8, 0xce, 0x30, 0x2e, 0xfc, 0x85, 0xda, 0xe9, 0x22, 0xd5
        , 0xeb, 0x38, 0x38, 0xd2, 0xb9, 0x17, 0x84, 0xf0, 0x48, 0x24, 0xd2, 0x67, 0x67, 0xbf, 0xb6, 0x5b
        , 0xd3, 0x6a, 0x36, 0xe7, 0x4f, 0xec, 0x46, 0xd0, 0x9d, 0x98, 0x85, 0x8d, 0x58, 0x40, 0x8a, 0xb4
        , 0x3e, 0x90, 0x4b, 0x06, 0xe7, 0x99, 0xc1, 0x81, 0x7c, 0x5c, 0xed, 0x4f, 0x3a, 0x7b, 0xbe, 0x15
        , 0xcd, 0xbf, 0x42, 0x2d, 0xea, 0x9d, 0x2d, 0x5d, 0xc2, 0xc6, 0x10, 0x5c, 0xe2, 0xf4, 0xd4, 0xc7
        , 0x1e, 0x5d, 0x47, 0x79, 0xf6, 0xc4, 0x4b, 0x77, 0x0a, 0x13, 0x36, 0x36, 0x10, 0x99, 0x49, 0xe1
        , 0xf7, 0x78, 0x6a, 0xcb, 0x5a, 0x73, 0x2b, 0xcd, 0xea, 0x04, 0x70, 0xfe, 0xa4, 0x06, 0x58, 0x40
        , 0xc9, 0xd3, 0x57, 0x01, 0x70, 0xd8, 0xa6, 0xb5, 0x16, 0xe2, 0x32, 0xa5, 0xad, 0x79, 0x32, 0xae
        , 0x0a, 0x2c, 0x4d, 0x48, 0x5b, 0x8a, 0x23, 0xe5, 0x68, 0xab, 0x78, 0x43, 0xb6, 0xea, 0x5c, 0xa8
        , 0x68, 0x75, 0xfa, 0x30, 0xd0, 0x82, 0x19, 0x14, 0x24, 0x8b, 0x61, 0x6b, 0xbe, 0x71, 0x80, 0x65
        , 0xfc, 0x56, 0x55, 0xc5, 0xac, 0xc6, 0x73, 0x94, 0x70, 0xdb, 0xa7, 0xe3, 0x03, 0x86, 0xd5, 0x05
        , 0x84, 0x83, 0x00, 0x01, 0x00, 0x82, 0x6a, 0x63, 0x61, 0x72, 0x64, 0x61, 0x6e, 0x6f, 0x2d, 0x73
        , 0x6c, 0x00, 0xa0, 0x58, 0x20, 0x4b, 0xa9, 0x2a, 0xa3, 0x20, 0xc6, 0x0a, 0xcc, 0x9a, 0xd7, 0xb9
        , 0xa6, 0x4f, 0x2e, 0xda, 0x55, 0xc4, 0xd2, 0xec, 0x28, 0xe6, 0x04, 0xfa, 0xf1, 0x86, 0x70, 0x8b
        , 0x4f, 0x0c, 0x4e, 0x8e, 0xdf, 0xff
    ];

    #[test]
    fn parse_get_block_headers_response() {
        let b = cbor::decode_from_cbor(GET_BLOCK_HEADER_BYTES).unwrap();
        match b {
            BlockHeaderResponse::Ok(ll) => assert!(ll.len() == 1),
        }
    }

    const HANDSHAKE_BYTES : &'static [u8] = &[
        0x84, 0x1a, 0x2d, 0x96, 0x4a, 0x09, 0x83, 0x00
      , 0x01, 0x00, 0xb3, 0x04, 0x82, 0x00, 0xd8, 0x18, 0x41, 0x05, 0x05, 0x82, 0x00, 0xd8, 0x18, 0x41
      , 0x04, 0x06, 0x82, 0x00, 0xd8, 0x18, 0x41, 0x07, 0x18, 0x22, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18
      , 0x5e, 0x18, 0x25, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x5e, 0x18, 0x2b, 0x82, 0x00, 0xd8, 0x18
      , 0x42, 0x18, 0x5d, 0x18, 0x31, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x5c, 0x18, 0x37, 0x82, 0x00
      , 0xd8, 0x18, 0x42, 0x18, 0x62, 0x18, 0x3d, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x61, 0x18, 0x43
      , 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x60, 0x18, 0x49, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x5f
      , 0x18, 0x53, 0x82, 0x00, 0xd8, 0x18, 0x41, 0x00, 0x18, 0x5c, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18
      , 0x31, 0x18, 0x5d, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x2b, 0x18, 0x5e, 0x82, 0x00, 0xd8, 0x18
      , 0x42, 0x18, 0x25, 0x18, 0x5f, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x49, 0x18, 0x60, 0x82, 0x00
      , 0xd8, 0x18, 0x42, 0x18, 0x43, 0x18, 0x61, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x3d, 0x18, 0x62
      , 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x37, 0xad, 0x04, 0x82, 0x00, 0xd8, 0x18, 0x41, 0x05, 0x05
      , 0x82, 0x00, 0xd8, 0x18, 0x41, 0x04, 0x06, 0x82, 0x00, 0xd8, 0x18, 0x41, 0x07, 0x0d, 0x82, 0x00
      , 0xd8, 0x18, 0x41, 0x00, 0x0e, 0x82, 0x00, 0xd8, 0x18, 0x41, 0x00, 0x18, 0x25, 0x82, 0x00, 0xd8
      , 0x18, 0x42, 0x18, 0x5e, 0x18, 0x2b, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x5d, 0x18, 0x31, 0x82
      , 0x00, 0xd8, 0x18, 0x42, 0x18, 0x5c, 0x18, 0x37, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x62, 0x18
      , 0x3d, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x61, 0x18, 0x43, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18
      , 0x60, 0x18, 0x49, 0x82, 0x00, 0xd8, 0x18, 0x42, 0x18, 0x5f, 0x18, 0x53, 0x82, 0x00, 0xd8, 0x18
      , 0x41, 0x00
    ];

    #[test]
    fn handshake_decoding() {
        let hs = Handshake::default();

        let hs_ : Handshake = cbor::decode_from_cbor(HANDSHAKE_BYTES).unwrap();
        println!("");
        println!("{}", hs.in_handlers);
        println!("{}", hs_.in_handlers);
        assert_eq!(hs.protocol_magic, hs_.protocol_magic);
        assert_eq!(hs.version, hs_.version);
        assert_eq!(hs.in_handlers, hs_.in_handlers);
        assert_eq!(hs.out_handlers, hs_.out_handlers);
        assert_eq!(hs, hs_);
    }

    #[test]
    fn handshake_encoding() {
        let hs = Handshake::default();

        let vec = cbor::encode_to_cbor(&hs).unwrap();
        assert_eq!(HANDSHAKE_BYTES, vec.as_slice());
    }
}
