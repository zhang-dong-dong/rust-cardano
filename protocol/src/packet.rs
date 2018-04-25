extern crate wallet_crypto;

//use std::collections::{BTreeMap};
use std::collections::{LinkedList};
use self::wallet_crypto::cbor::{encode_to_cbor, Value, ObjectKey, Bytes, ExtendedResult};
use self::wallet_crypto::cbor;

pub fn send_handshake(_protocol_magic: u32) -> Vec<u8> {
/*
    let mut inSpecs = BTreeMap::new();
    let mut outSpecs = BTreeMap::new();

    let inHandlers = [ (4u64, b"05") ];
    let outHandlers = [ (4u64, b"05") ];

    for (k,bs) in inHandlers.iter() {
        let b = Bytes::from_slice(&bs[..]);
        inSpecs.insert(ObjectKey::Integer(*k), Value::Array(vec![ Value::U64(0), Value::Tag(24, Box::new(Value::Bytes(b)))]));
    }

    for (k,bs) in outHandlers.iter() {
        let b = Bytes::from_slice(&bs[..]);
        outSpecs.insert(ObjectKey::Integer(*k), Value::Array(vec![ Value::U64(0), Value::Tag(24, Box::new(Value::Bytes(b)))]));
    }

    let content = vec![ Value::U64(protocol_magic as u64)
                      , Value::Array(vec![Value::U64(0), Value::U64(1), Value::U64(0)])
                      , Value::Object(inSpecs)
                      , Value::Object(outSpecs)
                      ];
    encode_to_cbor(&Value::Array(content)).unwrap()
*/
    vec![
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
    ]
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
pub struct HeaderHash([u8;HASH_SIZE]);
impl AsRef<[u8]> for HeaderHash { fn as_ref(&self) -> &[u8] { self.0.as_ref() } }
impl HeaderHash {
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

pub fn send_msg_subscribe(keep_alive: bool) -> Message {
    let value = if keep_alive { 43 } else { 42 };
    let dat = encode_to_cbor(&Value::U64(value)).unwrap();
    (0xe, dat)
}

pub fn send_msg_getheaders(froms: &[HeaderHash], to: Option<&HeaderHash>) -> Message {
    let mut fromEncoded = LinkedList::new();
    for f in froms {
        let b = Bytes::from_slice(f.as_ref());
        fromEncoded.push_back(Value::Bytes(b));
    }
    let toEncoded =
        match to {
            None    => Value::Array(vec![]),
            Some(h) => {
                let b = Bytes::from_slice(h.as_ref());
                Value::Array(vec![Value::Bytes(b)])
            }
        };
    let r = Value::Array(vec![Value::IArray(fromEncoded), toEncoded]);
    let dat = encode_to_cbor(&r).unwrap();
    (0x4, dat)
}

type Todo = Vec<Value>;

pub struct MainBlockHeader {
    protocol_magic: u32,
    previous_block: HeaderHash,
    body_proof: Todo,
    consensus: Todo,
    extra_data: Todo
}
impl MainBlockHeader {
   pub fn new(pm: u32, pb: HeaderHash, bp: Todo, c: Todo, ed: Todo) -> Self {
        MainBlockHeader {
            protocol_magic: pm,
            previous_block: pb,
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
            let (array, prv_block)  = cbor::array_decode_elem(array, 0).embed("Previous Block Hash")?;
            let (array, body_proof) = cbor::array_decode_elem(array, 0).embed("body proof")?;
            let (array, consensus)  = cbor::array_decode_elem(array, 0).embed("consensus")?;
            let (array, extra_data) = cbor::array_decode_elem(array, 0).embed("extra_data")?;
            if ! array.is_empty() { return cbor::Result::array(array, cbor::Error::UnparsedValues); }
            Ok(MainBlockHeader::new(p_magic, prv_block, body_proof, consensus, extra_data))
        }).embed("While decoding a MainBlockHeader")
    }
}