type VarInt = i32;
type VarLong = i64;

trait VarIntExt {
    fn append_varint_as_bytes(&self, vector: &mut Vec<u8>) -> ();
    fn from_varint_bytes<'a, I: Iterator<Item = &'a u8>>(iter: &mut I) -> Self;
}

impl VarIntExt for i32 {
    fn append_varint_as_bytes(&self, vector: &mut Vec<u8>) {
        let mut tmp = *self as u32;
        loop {
            if tmp & (!0x0000007F) == 0 {
                vector.push((tmp & 0xFF) as u8);
                break;
            }
    
            vector.push((((tmp & 0x7f) | 0x80) & 0xFF) as u8);
            tmp = tmp >> 7;
        }
    }

    fn from_varint_bytes<'a, I: Iterator<Item = &'a u8>>(iter: &mut I) -> VarInt {
        let mut ret: VarInt = 0;
        let mut pos: i32 = 0;
        loop {
            let current = iter.next().expect("VarInt shorter than expected");
            ret |= ((current & 0x7F) as i32) << pos;
            if (current & 0x80) == 0 {
                break;
            }
    
            pos += 7;
            if pos >= 32 {
                panic!("VarInt is too big!");
            }
        }
        ret
    }
}

trait VarLongExt {
    fn append_varlong_as_bytes(&self, vector: &mut Vec<u8>) -> ();
    fn from_varlong_bytes<'a, I: Iterator<Item = &'a u8>>(iter: &mut I) -> Self;
}

impl VarLongExt for i64 {
    fn append_varlong_as_bytes(&self, vector: &mut Vec<u8>) {
        let mut tmp = *self as u64;
        loop {
            if tmp & (!0x7Fu64) == 0 {
                vector.push((tmp & 0xFF) as u8);
                break;
            }
    
            vector.push((((tmp & 0x7f) | 0x80) & 0xFF) as u8);
            tmp = tmp >> 7;
        }
    }

    fn from_varlong_bytes<'a, I: Iterator<Item = &'a u8>>(iter: &mut I) -> Self {
        let mut ret: VarLong = 0;
        let mut pos: i64 = 0;
        loop {
            let current = iter.next().expect("VarInt shorter than expected");
            ret |= ((current & 0x7F) as i64) << pos;
            if (current & 0x80) == 0 {
                break;
            }
    
            pos += 7;
            if pos >= 64 {
                panic!("VarLong is too big!");
            }
        }
        ret
    }
}


pub trait Sendable {
    fn serialize_to(&self) -> Vec<u8>;
}

pub struct Handshake {
    id: VarInt,
    pub protocol_version: VarInt,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: VarInt
}

impl Handshake {
    pub fn new() -> Handshake {
        Handshake {
            id: 0x00, 
            protocol_version: -1,
            server_address: "localhost".to_string(), 
            server_port: 25565, 
            next_state: 1
        }
    }
}

impl Sendable for Handshake {
    fn serialize_to(&self) -> Vec<u8> {
        let mut packet_data: Vec<u8> = Vec::new();
        self.id.append_varint_as_bytes(&mut packet_data);
        self.protocol_version.append_varint_as_bytes(&mut packet_data);
        let string_length:VarInt = self.server_address.len().try_into().unwrap();
        string_length.append_varint_as_bytes(&mut packet_data);
        let addr_bytes = &mut self.server_address.clone().into_bytes().to_vec();
        packet_data.append(addr_bytes);
        let port_bytes = &mut self.server_port.to_be_bytes().to_vec();
        packet_data.append(port_bytes);
        self.next_state.append_varint_as_bytes(&mut packet_data);
        let packet_len: VarInt = packet_data.len().try_into().unwrap();
        let mut packet = Vec::<u8>::new();
        packet_len.append_varint_as_bytes(&mut packet);
        packet.append(&mut packet_data);
        return packet;
    }
}

pub struct StatusRequest {
}

impl StatusRequest {
    pub fn new() -> StatusRequest {
        StatusRequest {}
    }
}

impl Sendable for StatusRequest {
    fn serialize_to(&self) -> Vec<u8> {
        vec![0x01u8, 0x00]
    }
}

pub struct StatusResponse {
    pub status: serde_json::Value
}

pub enum ReceivablePacket {
    StatusResponse(StatusResponse)
}

impl ReceivablePacket {
    pub fn deserialize_from(resp: &Vec<u8>) -> Result<ReceivablePacket, &'static str> {
        let mut it = resp.iter();
        let _length = VarInt::from_varint_bytes(&mut it);
        let id = VarInt::from_varint_bytes(&mut it);
        match id {
            0x00 => {
                let length = VarInt::from_varint_bytes(&mut it);
                let status = serde_json::from_slice(&it.take(length as usize)
                                                                                    .map(|value| *value)
                                                                                    .collect::<Vec<u8>>()[..]).unwrap();
                //return Ok(ReceivablePacket::StatusResponse {0: StatusResponse { status: status}});
                return Ok(ReceivablePacket::StatusResponse (StatusResponse {status: status }));
            },
            _ => return Err("Packet ID does not match implemented Packets"),
        };
        
    }
}