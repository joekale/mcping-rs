type VarInt = i32;

fn write_varint(vector: &mut Vec<u8>, value: VarInt) {
    let mut tmp = value as u32;
    loop {
        if tmp & (!0x0000007F) == 0 {
            vector.push((tmp & 0xFF) as u8);
            break;
        }

        vector.push((((tmp & 0x7f) | 0x80) & 0xFF) as u8);
        tmp = tmp >> 7;
    }
}

fn read_varint<'a, I: Iterator<Item = &'a u8>>(iter: &mut I) -> VarInt {
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
            
        }
    }
    ret
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
            next_state: 1}
    }
}

impl Sendable for Handshake {
    fn serialize_to(&self) -> Vec<u8> {
        let mut packet_data: Vec<u8> = Vec::new();
        write_varint(&mut packet_data, self.id);
        write_varint(&mut packet_data, self.protocol_version);
        let string_length:VarInt = self.server_address.len().try_into().unwrap();
        write_varint(&mut packet_data, string_length);
        let addr_bytes = &mut self.server_address.clone().into_bytes().to_vec();
        packet_data.append(addr_bytes);
        let port_bytes = &mut self.server_port.to_be_bytes().to_vec();
        packet_data.append(port_bytes);
        write_varint(&mut packet_data, self.next_state);

        let packet_len: VarInt = packet_data.len().try_into().unwrap();
        let mut packet = Vec::<u8>::new();
        write_varint(&mut packet, packet_len);
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
    pub status: String
}

pub enum ReceivablePacket {
    StatusResponse(StatusResponse)
}

impl ReceivablePacket {
    pub fn deserialize_from(resp: &Vec<u8>) -> Result<ReceivablePacket, &'static str> {
        let mut it = resp.iter();
        let _length = read_varint(&mut it);
        let id = read_varint(&mut it);
        match id {
            0x00 => {
                let length = read_varint(&mut it);
                let status = String::from_utf8(it.take(length as usize).map(|value| *value).collect::<Vec<u8>>()).unwrap();
                //return Ok(ReceivablePacket::StatusResponse {0: StatusResponse { status: status}});
                return Ok(ReceivablePacket::StatusResponse (StatusResponse {status: status }));
            },
            _ => return Err("Packet ID does not match implemented Packets"),
        };
        
    }
}