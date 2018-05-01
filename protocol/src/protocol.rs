use std::collections::BTreeMap;
use std::io::{Read, Write};

use packet;
use packet::{Handshake};
use ntt;

use wallet_crypto::cbor;

/// Light ID create by the server or by the client
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct LightId(u32);
impl LightId {
    /// create a `LightId` from the given number
    ///
    /// identifier from 0 to 1023 are reserved.
    ///
    /// # Example
    ///
    /// ```
    /// use protocol::{LightId};
    /// let id = LightId::new(0x400);
    /// ```
    pub fn new(id: u32) -> Self {
        assert!(id >= 1024);
        LightId(id)
    }
    pub fn next(self) -> Self {
        LightId(self.0 + 1)
    }
}

/// A light connection will hold pending message to send or
/// awaiting to be read data
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct LightConnection {
    id: LightId,
    node_id: Option<ntt::protocol::NodeId>,
    received: Option<Vec<u8>>
}
impl LightConnection {
    pub fn new_with_nodeid(id: LightId, nonce: u64) -> Self {
        LightConnection {
            id: id,
            node_id: Some (ntt::protocol::NodeId::make_syn(nonce)),
            received: None
        }
    }
    pub fn new_expecting_nodeid(id: LightId) -> Self {
        LightConnection {
            id: id,
            node_id: None,
            received: None
        }
    }

    pub fn get_id(&self) -> LightId { self.id }

    /// tell if the `LightConnection` has some pending message to read
    pub fn pending_received(&self) -> bool {
        self.received.is_some()
    }

    /// consume the eventual data to read
    /// 
    /// to call only if you are ready to process the data
    pub fn get_received(&mut self) -> Option<Vec<u8>> {
        let mut v = None;
        ::std::mem::swap(&mut self.received, &mut v);
        v
    }

    /// add data to the received bucket
    fn receive(&mut self, bytes: &[u8]) {
        self.received = Some(match self.get_received() {
            None => bytes.iter().cloned().collect(),
            Some(mut v) => { v.extend_from_slice(bytes); v }
        });
    }
}

pub struct Connection<T> {
    ntt:               ntt::Connection<T>,
    // this is a line of active connections open by the server/client
    // that have not been closed yet.
    server_cons: BTreeMap<LightId, LightConnection>,
    client_cons: BTreeMap<LightId, LightConnection>,
    // potentialy the server close its connection before we have time
    // to process it on the client, so keep the buffer alive here
    server_dones: BTreeMap<LightId, LightConnection>,
    //await_reply: BTreeMap<ntt::protocol::NodeId, >

    next_light_id: LightId
}

impl<T: Write+Read> Connection<T> {

    // search for the next free LIGHT ID in the client connection map
    fn find_next_connection_id(&self) -> LightId {
        let mut x = LightId(ntt::LIGHT_ID_MIN);
        while self.client_cons.contains_key(&x) {
            x = x.next();
        }
        return x;
    }

    fn get_free_light_id(&mut self) -> LightId {
        let id = self.next_light_id;
        self.next_light_id = id.next();
        id
    }

    pub fn new(ntt: ntt::Connection<T>, hs: &packet::Handshake) -> Self {
        let mut conn = Connection {
            ntt: ntt,
            server_cons: BTreeMap::new(),
            client_cons: BTreeMap::new(),
            server_dones: BTreeMap::new(),
            next_light_id: LightId::new(0x401)
        };

        let lcid = conn.find_next_connection_id();
        let lc = LightConnection::new_with_nodeid(lcid, conn.ntt.get_nonce());
        conn.ntt.create_light(lcid.0);
        conn.client_cons.insert(lcid, lc);

        // we are expecting the first broadcast to respond a connection ack
        // initial handshake
        conn.send_bytes(lcid, &packet::send_handshake(hs));
        conn.send_bytes(lcid, &packet::send_hardcoded_blob_after_handshake());

        conn.broadcast(); // expect ack of connection creation
        conn.broadcast(); // expect the handshake reply
        if let Some(lc) = conn.poll() {
            assert!(lc.get_id() == lcid);
            let bs = lc.get_received().unwrap();
            let _hs : Handshake = cbor::decode_from_cbor(&bs).unwrap();
            // println!("{}", _hs);
        }
        conn.broadcast(); // expect some data regarding the nodeid or something like it
        if let Some(lc) = conn.poll() {
            assert!(lc.get_id() == lcid);
            let _ = lc.get_received();
        }
        conn.close_light_connection(lcid);

        conn
    }

    pub fn new_light_connection(&mut self, id: LightId) {
        self.ntt.create_light(id.0);

        let lc = LightConnection::new_with_nodeid(id, self.ntt.get_nonce());
        self.client_cons.insert(id, lc);

        // TODO: this is a hardcoded block sent everytime we
        // create a light connection, we might want to figure
        // out what it is at some point.
        //
        // see the send endpoint command
        let buf = packet::send_hardcoded_blob_after_handshake();
        self.send_bytes(id, &buf);
    }

    pub fn close_light_connection(&mut self, id: LightId) {
        self.client_cons.remove(&id);
        self.ntt.close_light(id.0);
    }

    /// get a mutable reference to a LightConnection so one can read its received data
    ///
    pub fn poll<'a>(&'a mut self) -> Option<&'a mut LightConnection> {
        self.server_cons.iter_mut().find(|t| t.1.pending_received()).map(|t| t.1)
    }

    pub fn poll_id<'a>(&'a mut self, id: LightId) -> Option<&'a mut LightConnection> {
        self.server_cons.iter_mut().find(|t| t.0 == &id && t.1.pending_received()).map(|t| t.1)
    }

    pub fn send_bytes(&mut self, id: LightId, bytes: &[u8]) {
        self.ntt.light_send_data(id.0, bytes)
    }

    // TODO return some kind of opaque token
    pub fn send_bytes_ack(&mut self, id: LightId, bytes: &[u8]) -> ntt::protocol::NodeId {
        match self.client_cons.get(&id) {
            None => panic!("send bytes ack ERROR. connection doesn't exist"),
            Some(con) => {
                match con.node_id.clone() {
                    None      => panic!("connection without node id asking for ack. internal bug"),
                    Some(nid) => {
                        self.ntt.light_send_data(id.0, bytes);
                        nid
                    }
                }
            }
        }
    }

    pub fn broadcast(&mut self) {
        use ntt::protocol::{ControlHeader, Command};
        match self.ntt.recv().unwrap() {
            Command::Control(ControlHeader::CloseConnection, cid) => {
                let id = LightId::new(cid);
                match self.server_cons.remove(&id) {
                    Some(v) => {
                        if let Some(_) = v.received {
                            self.server_dones.insert(id, v);
                        }
                    }
                    None    =>
                        // BUG, server asked to close connection but connection doesn't exists in tree
                        {},
                }
            },
            Command::Control(ControlHeader::CreatedNewConnection, cid) => {
                let id = LightId::new(cid);
                if let Some(_) = self.server_cons.get(&id) {
                    panic!("light id create twice")
                } else {
                    let con = LightConnection::new_expecting_nodeid(id);
                    self.server_cons.insert(id, con);
                }
            },
            Command::Control(ch, cid) => {
                println!("{}:{}: LightId({}) Unsupported control `{:?}`", file!(), line!(), cid, ch);
            },
            ntt::protocol::Command::Data(cid, len) => {
                let id = LightId::new(cid);
                let bytes = self.ntt.recv_len(len).unwrap();
                match self.server_cons.get_mut(&id) {
                    Some(con) =>
                        con.receive(&bytes),
                    None => {
                        println!("{}:{}: LightId({}) does not exists but received data", file!(), line!(), cid)
                    },
                }
            },
        }
    }
}

pub mod command {
    use std::io::{Read, Write};
    use super::{LightId, Connection};
    use wallet_crypto::cbor;
    use block;
    use packet;

    pub trait Command<W: Read+Write> {
        type Output;
        fn cmd(&self, connection: &mut Connection<W>, id: LightId) -> Result<Self::Output, &'static str>;

        fn execute(&self, connection: &mut Connection<W>) -> Result<Self::Output, &'static str> {
            let id = connection.get_free_light_id();

            connection.new_light_connection(id);
            connection.broadcast(); // expect ack of connection creation

            let ret = self.cmd(connection, id)?;

            connection.close_light_connection(id);

            Ok(ret)
        }
    }

    #[derive(Debug)]
    pub struct GetBlockHeader(Option<block::HeaderHash>);
    impl GetBlockHeader {
        pub fn first() -> Self { GetBlockHeader(None) }
        pub fn some(hh: block::HeaderHash) -> Self { GetBlockHeader(Some(hh)) }
    }

    impl<W> Command<W> for GetBlockHeader where W: Read+Write {
        type Output = block::MainBlockHeader;
        fn cmd(&self, connection: &mut Connection<W>, id: LightId) -> Result<Self::Output, &'static str> {
            // require the initial header
            let (get_header_id, get_header_dat) = packet::send_msg_getheaders(&[], &self.0);
            connection.send_bytes(id, &[get_header_id]);
            connection.send_bytes(id, &get_header_dat[..]);
            connection.broadcast();
            match connection.poll_id(id) {
                Some(lc) => {
                    let _ = lc.get_received();
                },
                None => {
                    panic!("connection failed");
                }
            };
            connection.broadcast();
            match connection.poll_id(id) {
                Some(lc) => {
                    assert!(lc.get_id() == id);
                    if let Some(dat) = lc.get_received() {
                        let mut l : packet::BlockHeaderResponse = cbor::decode_from_cbor(&dat).unwrap();
                        println!("{}", l);
    
                        match l {
                            packet::BlockHeaderResponse::Ok(mut ll) =>
                                match ll.pop_front() {
                                    Some(block::BlockHeader::MainBlockHeader(bh)) => Ok(bh),
                                    _  => Err("No first main block header")
                                }
                        }
                    } else { Err("No received data...") }
                },
                None => {
                    panic!("connection failed");
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct GetBlock {
        from: block::HeaderHash,
        to:   block::HeaderHash
    }
    impl GetBlock {
        pub fn only(hh: block::HeaderHash) -> Self { GetBlock::from(hh.clone(), hh) }
        pub fn from(from: block::HeaderHash, to: block::HeaderHash) -> Self { GetBlock { from: from, to: to } }
    }

    impl<W> Command<W> for GetBlock where W: Read+Write {
        type Output = Vec<u8>; // packet::block::Block;
        fn cmd(&self, connection: &mut Connection<W>, id: LightId) -> Result<Self::Output, &'static str> {
            // require the initial header
            let (get_header_id, get_header_dat) = packet::send_msg_getblocks(&self.from, &self.to);
            connection.send_bytes(id, &[get_header_id]);
            connection.send_bytes(id, &get_header_dat[..]);
            connection.broadcast();
            match connection.poll_id(id) {
                Some(lc) => {
                    assert_eq!(lc.get_id(), id);
                    // drop the received data.
                    let _ = lc.get_received();
                },
                None => {
                    panic!("connection failed");
                }
            };
            connection.broadcast();
            match connection.poll_id(id) {
                Some(lc) => {
                    assert!(lc.get_id() == id);
                    if let Some(dat) = lc.get_received() {
                        Ok(dat)
                    } else { Err("No received data...") }
                },
                None => {
                    panic!("connection failed");
                }
            }
        }
    }

}