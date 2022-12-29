use std::net::{TcpStream, Shutdown, SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashSet;
use std::time::Duration;

use crate::mc_packets::Sendable;
use std::io::Write;
use std::io::Read;
pub mod mc_packets;

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author = "Joe Kale")]
#[command(version = "0.1.0")] 
#[command(about = "Scans IP Addresses for MineCraft Servers.", long_about = None)]
struct Args {
   /// IP Addresses to include in scan (CIDR Notation). Can be passed multiple times
   #[arg(short, long, )]
   include: Vec<String>,

   /// IP Addresses to exclude from scan (CIDR Notation). Can be passed multiple timest
   #[arg(short, long)]
   exclude: Vec<String>,

   #[arg(short, long)]
   verbose: bool
}

fn range_from_cidr(cidr_str: &str) -> Result<(u32, u32), &'static str> {
    let parts: Vec<&str> = cidr_str.split("/").collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR notation");
    }

    let ip_str = parts[0];
    let mask_length_str = parts[1];

    let ip = match ip_str.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => {
            return Err("Invalid IP address");
        }
    };

    let mask_length = match mask_length_str.parse::<u8>() {
        Ok(length) => length,
        Err(_) => {
            return Err("Invalid mask length");
        }
    };

    let ip_int = u32::from(ip);
    let mask = !(0xffffffff >> mask_length); // shift down and bitwise not
    let start = ip_int & mask;
    let end = start | !mask;

    Ok((start, end))
}

fn merge_include_and_exclude_ranges(includes: &HashSet<(u32,u32)>, excludes: &HashSet<(u32,u32)>) -> HashSet<(u32,u32)> {
    let mut scan_ranges = HashSet::<(u32,u32)>::new();
    for range in includes {
        for erange in excludes {
            match match ((range.0 ..= range.1).contains(&erange.0), (range.0 ..= range.1).contains(&erange.1)) {
                (true, false) => {
                    Some(merge_include_and_exclude_ranges(&vec![(range.0, erange.0 - 1)].into_iter().collect(), &excludes.clone()))
                },
                (false, true) => {
                    Some(merge_include_and_exclude_ranges(&vec![(erange.1 + 1, range.1)].into_iter().collect(), &excludes.clone()))
                },
                (true, true) => {
                    if range == erange {
                        None
                    } else if range.0 == erange.0 {
                        Some(merge_include_and_exclude_ranges(&vec![(erange.1 + 1, range.1)].into_iter().collect(), &excludes.clone()))
                    } else if range.1 == erange.1 {
                        Some(merge_include_and_exclude_ranges(&vec![(range.0, erange.0 - 1)].into_iter().collect(), &excludes.clone()))
                    } else {
                        Some(merge_include_and_exclude_ranges(& vec![(range.0, erange.0 - 1), (erange.1 + 1, range.1)].into_iter().collect(), &excludes.clone()))
                    }
                },
                _ => None
            } {
                Some(x) => {
                    for range in x {
                        scan_ranges.insert(range);
                    }
                },
                None => continue
            };
        }
    }
    if scan_ranges.len() == 0 {
        includes.clone()
    } else {
        scan_ranges
    }
}

#[test]
fn test_merge_simple_high_overlap() {
    // (192.168.0.0 - 192.168.1.255) excluding (192.168.1.0 - 192.168.1.255) (overlap and subset)
    assert_eq!(merge_include_and_exclude_ranges(&vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,1,255)))].into_iter().collect(), 
                                                &vec![(u32::from(Ipv4Addr::new(192,168,1,0)), u32::from(Ipv4Addr::new(192,168,2,255)))].into_iter().collect()), 
                                                vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,0,255)))].into_iter().collect());
    assert_eq!(merge_include_and_exclude_ranges(&vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,1,255)))].into_iter().collect(), 
                                                &vec![(u32::from(Ipv4Addr::new(192,168,1,0)), u32::from(Ipv4Addr::new(192,168,1,255)))].into_iter().collect()), 
                                                vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,0,255)))].into_iter().collect());
}

#[test]
fn test_merge_simple_low_overlap() {
    // (192.168.0.0 - 192.168.1.255) excluding (192.168.0.0 - 192.168.0.255) (overlap and subset)
    assert_eq!(merge_include_and_exclude_ranges(&vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,1,255)))].into_iter().collect(), 
                                                &vec![(u32::from(Ipv4Addr::new(192,167,0,0)), u32::from(Ipv4Addr::new(192,168,0,255)))].into_iter().collect()), 
                                                vec![(u32::from(Ipv4Addr::new(192,168,1,0)), u32::from(Ipv4Addr::new(192,168,1,255)))].into_iter().collect());
    assert_eq!(merge_include_and_exclude_ranges(&vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,1,255)))].into_iter().collect(), 
                                                &vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,0,255)))].into_iter().collect()), 
                                                vec![(u32::from(Ipv4Addr::new(192,168,1,0)), u32::from(Ipv4Addr::new(192,168,1,255)))].into_iter().collect());
}

#[test]
fn test_merge_multiple_overlap() {
    // (192.168.0.0 - 192.168.4.255) excluding (192.168.1.0 - 192.168.1.255) and (192.168.3.0 - 192.168.3.255)
    assert_eq!(merge_include_and_exclude_ranges(&vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,4,255)))].into_iter().collect(), 
                                                &vec![(u32::from(Ipv4Addr::new(192,168,1,0)), u32::from(Ipv4Addr::new(192,168,1,255))),
                                                (u32::from(Ipv4Addr::new(192,168,3,0)), u32::from(Ipv4Addr::new(192,168,3,255)))].into_iter().collect()), 
                                                vec![(u32::from(Ipv4Addr::new(192,168,0,0)), u32::from(Ipv4Addr::new(192,168,0,255))),
                                                (u32::from(Ipv4Addr::new(192,168,2,0)), u32::from(Ipv4Addr::new(192,168,2,255))),
                                                (u32::from(Ipv4Addr::new(192,168,4,0)), u32::from(Ipv4Addr::new(192,168,4,255)))].into_iter().collect());
}

fn main() {
    let app_cli = Args::parse();
    println!("MineCraft Ping!");

    println!("include: {:#?}", app_cli.include);
    println!("exclude: {:#?}", app_cli.exclude);

    let mut include_ranges = HashSet::<(u32, u32)>::new();
    for cidr_str in &app_cli.include {
        include_ranges.insert(range_from_cidr(cidr_str).unwrap());
    }

    let mut exclude_ranges = HashSet::<(u32, u32)>::new();
    for cidr_str in &app_cli.exclude {
        exclude_ranges.insert(range_from_cidr(cidr_str).unwrap());
    }

    let scan_ranges = merge_include_and_exclude_ranges(&include_ranges, &exclude_ranges);
    let port: u16 = 25565;

    for range in scan_ranges {
        for ip in range.0 ..= range.1 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port);
            let mut stream = match TcpStream::connect_timeout(&addr, Duration::new(1, 0)) {
                Ok(x) => x,
                Err(err) => {
                    if app_cli.verbose {
                        println!("Failed to connect to {}: {}", addr.ip().to_string(), err);
                    }
                    continue
                }
            };
            let _ = stream.set_read_timeout(Some(Duration::new(1, 0)));

            let mut hsp = mc_packets::Handshake::new();
            hsp.server_address = addr.ip().to_string();

            let hs_bytes = hsp.serialize_to();
            if stream.write(hs_bytes.as_slice()).is_err() {
                if app_cli.verbose {
                    println!("Connected to socket, but writing handshake failed.");
                }
                stream.shutdown(Shutdown::Both).unwrap();
                continue
            }

            let status_req_packet = mc_packets::StatusRequest::new();
            let srq_bytes = status_req_packet.serialize_to();
            if stream.write(&srq_bytes.as_slice()).is_err() {
                if app_cli.verbose {
                    println!("Connected to socket, but writing StatusRequest failed.");
                }
                stream.shutdown(Shutdown::Both).unwrap();
                continue
            }

            let buf = &mut Vec::<u8>::new();
            let resp = stream.read_to_end(buf);
            let read_size = match resp {
                Ok(read) => read,
                Err(error) => {
                    if app_cli.verbose {
                        println!("Connected to socket, but reading response failed: {}", error);
                    }
                    stream.shutdown(Shutdown::Both).unwrap();
                    continue
                },
            };

            if read_size > 0 {
                let received = mc_packets::ReceivablePacket::deserialize_from(buf).unwrap();

                let json_resp: serde_json::Value = match received {
                    mc_packets::ReceivablePacket::StatusResponse(packet) => packet.status,
                };

                print!("{}", json_resp);
            } else {
                println!("Received no bytes back from read");
            }

        }
    }
    
}
