use std::net::{TcpStream, Shutdown, ToSocketAddrs};
use std::time::Duration;

use crate::mc_packets::Sendable;
use std::io::Write;
use std::io::Read;
pub mod mc_packets;

fn main() {
    println!("MineCraft Ping!");

    let server = String::from("purpleprison.org");
    let port: u16 = 25565;

    let addr_str = format!("{}:{}", server, port.to_string());
    let mut addrs = addr_str.to_socket_addrs().unwrap();
    let addr = &mut addrs.next().expect("Server did not resolve to Socket Address");
    println!("Connecting to {}", addr);
    let mut stream = TcpStream::connect_timeout(addr, Duration::new(10, 0)).unwrap();
    let _rt_res = stream.set_read_timeout(Some(Duration::new(10, 0)));
    let mut hsp = mc_packets::Handshake::new();
    hsp.server_address = server;

    let hs_bytes = hsp.serialize_to();
    let write_res = stream.write(hs_bytes.as_slice());
    if write_res.is_err() {
        panic!("Failed to write handshake packet: {:?}", write_res.err());
    }

    let status_req_packet = mc_packets::StatusRequest::new();
    let srq_bytes = status_req_packet.serialize_to();
    let srq_res = stream.write(&srq_bytes.as_slice());
    if srq_res.is_err() {
        panic!("Failed to write StatusRequest Packet: {:?}", srq_res.err());
    }

    //expecting status response
    let buf = &mut Vec::<u8>::new();
    let resp = stream.read_to_end(buf);
    let read_size = match resp {
        Ok(read) => read,
        Err(error) => {
            panic!("Failed to read_to_end of response: {:?}", error);
        },
    };

    if read_size > 0 {
        let received = mc_packets::ReceivablePacket::deserialize_from(buf).unwrap();

        let json_resp: serde_json::Value = match received {
            mc_packets::ReceivablePacket::StatusResponse(packet) => serde_json::from_str(&packet.status).unwrap(),
        };

        print!("{:?}", json_resp);
    } else {
        println!("Received no bytes back from read");
    }

    stream.shutdown(Shutdown::Both).unwrap();
    
}
