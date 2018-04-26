use std::collections::BTreeMap;
use std::io::{Read, Write};

use packet;
use ntt;

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
}

/// A light connection will hold pending message to send or
/// awaiting to be read data
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct LightConnection {
    id: LightId,
    client_connected: bool,
    server_connected: bool,
    received: Option<Vec<u8>>
}
impl LightConnection {
    /// create a new `LightConnection` from the given `LightId`
    ///
    /// # Example
    ///
    /// ```
    /// use protocol::{LightId, LightConnection};
    /// let id = LightId::new(0x400);
    /// let lcon = LightConnection::new(id);
    /// ```
    pub fn new_server(id: LightId) -> Self {
        LightConnection {
            id: id,
            client_connected: false,
            server_connected: true,
            received: None
        }
    }
    pub fn new_client(id: LightId) -> Self {
        LightConnection {
            id: id,
            client_connected: true,
            server_connected: false,
            received: None,
        }
    }

    pub fn get_id(&self) -> LightId { self.id }

    pub fn client_connected(&self) -> bool {
        self.client_connected
    }
    pub fn server_connected(&self) -> bool {
        self.client_connected
    }

    fn client_set_connect(&mut self, st: bool) {
        self.client_connected = st
    }
    fn server_set_connect(&mut self, st: bool) {
        self.server_connected = st
    } 

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
    light_connections: BTreeMap<LightId, LightConnection>
}

impl<T: Write+Read> Connection<T> {
    pub fn new(ntt: ntt::Connection<T>, pm: u32) -> Self {
        let mut conn = Connection {
            ntt: ntt,
            light_connections: BTreeMap::new()
        };

        let lcid = LightId(0x400);
        let lc = LightConnection::new_client(lcid);
        conn.ntt.create_light(lcid.0);
        conn.light_connections.insert(lcid, lc);

        // we are expecting the first broadcast to respond a connection ack
        // initial handshake
        conn.send_bytes(lcid, &packet::send_handshake(pm));
        conn.send_bytes(lcid, &packet::send_hardcoded_blob_after_handshake());
        conn.broadcast();
        conn.broadcast();
        if let Some(lc) = conn.poll() {
            assert!(lc.get_id() == lcid);
            let _ = lc.get_received();
        }
        conn.broadcast();
        if let Some(lc) = conn.poll() {
            assert!(lc.get_id() == lcid);
            let _ = lc.get_received();
        }
        conn.close_light_connection(lcid);

        conn
    }

    pub fn new_light_connection(&mut self, id: LightId) {
        self.ntt.create_light(id.0);

        let lc = LightConnection::new_client(id);
        self.light_connections.insert(id, lc);

        // TODO: this is a hardcoded block sent everytime we
        // create a light connection, we might want to figure
        // out what it is at some point.
        //
        // see the send endpoint command
        let buf = packet::send_hardcoded_blob_after_handshake();
        self.send_bytes(id, &buf);
    }

    pub fn close_light_connection(&mut self, id: LightId) {
        let remove = if let Some(con) = self.light_connections.get_mut(&id) {
            con.client_set_connect(false);
            !con.server_connected && !con.client_connected
        } else { false };
        if remove {
            self.light_connections.remove(&id);
        }
    }

    /// get a mutable reference to a LightConnection so one can read its received data
    ///
    pub fn poll<'a>(&'a mut self) -> Option<&'a mut LightConnection> {
        self.light_connections.iter_mut().find(|t| t.1.pending_received()).map(|t| t.1)
    }

    pub fn send_bytes(&mut self, id: LightId, bytes: &[u8]) {
        self.ntt.light_send_data(id.0, bytes)
    }

    pub fn broadcast(&mut self) {
        use ntt::protocol::{ControlHeader, Command};
        match self.ntt.recv().unwrap() {
            Command::Control(ControlHeader::CloseConnection, cid) => {
                let id = LightId::new(cid);
                match self.light_connections.get_mut(&id) {
                    Some(v) => v.server_set_connect(false),
                    None    =>
                        // BUG, server asked to close connection but connection doesn't exists in tree
                        {},
                }
            },
            Command::Control(ControlHeader::CreatedNewConnection, cid) => {
                let id = LightId::new(cid);
                let create = if let Some(con) = self.light_connections.get_mut(&id) {
                    con.server_set_connect(true);
                    false
                } else {
                    true
                };
                if create {
                    let con = LightConnection::new_server(id);
                    self.light_connections.insert(id, con);
                }
            },
            Command::Control(ch, cid) => {
                println!("{}:{}: LightId({}) Unsupported control `{:?}`", file!(), line!(), cid, ch);
            },
            ntt::protocol::Command::Data(cid, len) => {
                let id = LightId::new(cid);
                let bytes = self.ntt.recv_len(len).unwrap();
                match self.light_connections.get_mut(&id) {
                    Some(con) => con.receive(&bytes),
                    None => {
                        println!("{}:{}: LightId({}) does not exists but received data", file!(), line!(), cid)
                    },
                }
            },
        }
    }
}
