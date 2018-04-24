use std::net::TcpStream;
use std::io::Read;
use std::io::Write;
use std::iter;

type LightweightConnectionId = u32;

const LIGHT_ID_MIN : u32 = 1024;

pub struct EndPoint(Vec<u8>);
impl AsRef<[u8]> for EndPoint {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl EndPoint {
    pub fn unaddressable() -> Self {
        EndPoint(vec![])
    }
}

pub struct Connection {
    stream: TcpStream,
}

impl Clone for Connection {
    fn clone(&self) -> Self { Connection { stream: self.stream.try_clone().unwrap() } }
}

impl Connection {
    pub fn handshake(stream: &TcpStream) -> Result<Self,&str> {
        let s_clone = stream.try_clone().unwrap();
        let mut conn = Connection { stream: s_clone };
        let mut buf = vec![];
        protocol::handshake(&mut buf);
        conn.emit("handshake", &buf);
        match conn.recv_u32() {
            Ok(0xffffffff) => Err("unsupported version"),
            Ok(0x00000001) => Err("request invalid"),
            Ok(0x00000002) => Err("request crossed"),
            Ok(0x00000000) => { println!("HANDSHAKE OK"); Ok(conn) },
            Ok(_)          => Err("unknown code"),
            Err(_)         => Err("random io error"),
        }
    }

    pub fn create_light(&mut self, cid: LightweightConnectionId) {
        assert!(cid >= LIGHT_ID_MIN);
        let mut buf = vec![];
        protocol::create_conn(cid, &mut buf);
        self.emit("create-connection", &buf);
    }

    pub fn close_light(&mut self, cid: LightweightConnectionId) {
        assert!(cid >= LIGHT_ID_MIN);
        let mut buf = vec![];
        protocol::delete_conn(cid, &mut buf);
        self.emit("close-connection", &buf);
    }

    pub fn send_endpoint(&mut self, endpoint: &EndPoint) {
        let mut buf = vec![];
        protocol::append_with_length(endpoint.as_ref(), &mut buf);
        self.emit("send endpoint", &buf);
    }

    pub fn light_send_data(&mut self, lwc: LightweightConnectionId, dat: &[u8]) {
        let mut buf = vec![];
        protocol::append_lightweight_data(lwc, dat.len() as u32, &mut buf);
        self.emit("send lightcon data header", &buf);
        self.emit("send lightcon data",  &dat);
    }

    // emit utility
    fn emit(&mut self, step: &str, dat: &[u8]) {
        println!("sending {} {:?}", step, dat);
        self.stream.write_all(dat).unwrap();
    }

    // TODO some kind of error
    fn recv_u32(&mut self) -> Result<u32, &str> {
        let mut buf = [0u8; 4];
        match self.stream.read_exact(&mut buf) {
            Ok(_) => {
                let v = ((buf[0] as u32) << 24) |
                        ((buf[1] as u32) << 16) |
                        ((buf[2] as u32) << 8) |
                        (buf[3] as u32);
                Ok(v)
            },
            Err(s) => Err("recvword32: io error"),
        }
    }

    pub fn recv_data(&mut self) -> Result<(LightweightConnectionId, Vec<u8>), &str> {
        let lwc = self.recv_u32().unwrap();
        println!("received lwc {}", lwc);
        let len = self.recv_u32().unwrap();
        let mut buf : Vec<u8> = iter::repeat(0).take(len as usize).collect();
        self.stream.read_exact(&mut buf[..]).unwrap();
        Ok((lwc,buf))
    }
}

pub struct LightConnection {
    conn: Connection,
    id: LightweightConnectionId,
}

impl LightConnection {
    pub fn new(conn: &Connection, lwc: LightweightConnectionId) -> Self {
        LightConnection { conn: conn.clone(), id: lwc }
    }

    pub fn send(&mut self, dat: &[u8]) {
        self.conn.light_send_data(self.id, dat);
    }
}

mod protocol {
    const PROTOCOL_VERSION : u32 = 0x00000000;

    pub enum ControlHeader {
        CreatedNewConnection,
        CloseConnection,
        CloseSocket,
        CloseEndPoint,
        ProbeSocket,
        ProbeSocketAck,
    }

    pub fn handshake(buf: &mut Vec<u8>) {
        let handshake_length = 0;
        append_u32(PROTOCOL_VERSION, buf);
        append_u32(handshake_length, buf);
        append_u32(0, buf); // ourEndPointId
        append_u32(0, buf); // send length 0
        //append_u32(0, buf); // ignored but should be handshake length
        //append_u32(0, buf); // ignored but should be handshake length
    }

    /// encode an int32
    fn append_i32(v: i32, buf: &mut Vec<u8>) {
        buf.push((v >> 24) as u8);
        buf.push((v >> 16) as u8);
        buf.push((v >> 8) as u8);
        buf.push(v as u8);
    }
    
    fn append_u32(v: u32, buf: &mut Vec<u8>) {
        buf.push((v >> 24) as u8);
        buf.push((v >> 16) as u8);
        buf.push((v >> 8) as u8);
        buf.push(v as u8);
    }

    pub fn append_lightweight_data(cid: super::LightweightConnectionId, len: u32, buf: &mut Vec<u8>) {
        assert!(cid >= 1024);
        append_u32(cid, buf);
        append_u32(len, buf);
    }

    pub fn create_conn(cid: super::LightweightConnectionId, buf: &mut Vec<u8>) {
        append_u32(control_header_to_u32(ControlHeader::CreatedNewConnection), buf);
        append_u32(cid, buf);
    }

    pub fn delete_conn(cid: super::LightweightConnectionId, buf: &mut Vec<u8>) {
        append_u32(control_header_to_u32(ControlHeader::CloseConnection), buf);
        append_u32(cid, buf);
    }


    pub fn append_with_length(dat: &[u8], buf: &mut Vec<u8>) {
        append_u32(dat.len() as u32, buf);
        buf.extend_from_slice(dat);
    }

    pub fn control_header_to_u32(h: ControlHeader) -> u32 {
        match h {
            ControlHeader::CreatedNewConnection => 0,
            ControlHeader::CloseConnection      => 1,
            ControlHeader::CloseSocket          => 2,
            ControlHeader::CloseEndPoint        => 3,
            ControlHeader::ProbeSocket          => 4,
            ControlHeader::ProbeSocketAck       => 5,
        }
    }
}
