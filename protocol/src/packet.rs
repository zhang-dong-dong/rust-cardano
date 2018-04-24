extern crate wallet_crypto;

use std::collections::{BTreeMap};
use self::wallet_crypto::cbor::{encode_to_cbor, Value, ObjectKey, Bytes};

pub fn send_handshake(protocol_magic: u32) -> Vec<u8> {

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
}
