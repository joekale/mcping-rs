use std::net::{TcpStream, Shutdown, SocketAddr, IpAddr, Ipv4Addr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashSet;
use std::time::Duration;

use crate::mc_packets::{Sendable, PingRequest};
use std::io::Write;
use std::io::Read;
pub mod mc_packets;
use mcscan_rs::ThreadPool;

use clap::Parser;
use log::debug;
use log::error;
use log::info;
use log::warn;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author = "Joe Kale")]
#[command(version = "0.1.0")] 
#[command(about = "Scans IP Addresses for MineCraft Servers.", long_about = None)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand, Debug)]
enum Action {
    Scan {
        /// IP Addresses to include in scan (CIDR Notation). Can be passed multiple times
        #[arg(short, long, )]
        include: Vec<String>,

        /// IP Addresses to exclude from scan (CIDR Notation). Can be passed multiple timest
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Port number to use.
        #[arg(long, default_value_t = 25565)]
        port: u16,

        /// threads to use.
        #[arg(long, default_value_t = 1)]
        threads: u16,
    },
    Single {
        /// Hostname to test. Ignores include and exclude
        #[arg(long)]
        host: String,

        /// Port number to use.
        #[arg(long, default_value_t = 25565)]
        port: u16,
    }
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
    let mask = if mask_length >= 32 {0xffffffff} else { !(0xffffffff >> mask_length)}; // shift down and bitwise not
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

fn try_addr(addr: &SocketAddr, hostname: Option<&String>) -> Option<serde_json::Value> {
    let mut stream = match TcpStream::connect_timeout(addr, Duration::new(1, 0)) {
        Ok(x) => x,
        Err(err) => {
            debug!("Failed to connect to {}: {}", addr.ip().to_string(), err);
            return None
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::new(1, 0)));

    let mut hsp = mc_packets::Handshake::new();
    hsp.server_address = match hostname {
        Some(hostname) => hostname.to_owned(),
        None => addr.ip().to_string(),
    };

    let hs_bytes = hsp.serialize_to();
    if stream.write(hs_bytes.as_slice()).is_err() {
        error!("{}: Connected to socket, but writing handshake failed.", hsp.server_address);
        stream.shutdown(Shutdown::Both).unwrap();
        return None
    }

    let status_req_packet = mc_packets::StatusRequest::new();
    let srq_bytes = status_req_packet.serialize_to();
    if stream.write(&srq_bytes.as_slice()).is_err() {
        error!("{}: Connected to socket, but writing StatusRequest failed.", hsp.server_address);
        stream.shutdown(Shutdown::Both).unwrap();
        return None
    }

    let buf = &mut Vec::<u8>::new();
    let resp = stream.read_to_end(buf);
    let read_size = match resp {
        Ok(read) => read,
        Err(_) => {
            debug!("Timeout reading from socket. Trying to send ping to test notchian server.");
            let start = SystemTime::now();
            let since_the_epoch = start
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards");
            let ping_req = PingRequest{number: since_the_epoch.as_millis() as i64};
            let ping_bytes = ping_req.serialize_to();
            if stream.write(&ping_bytes.as_slice()).is_err() {
                error!("Writing to stream failed");
                stream.shutdown(Shutdown::Both).unwrap();
                return None;
            }  

            let fallback_resp = stream.read_to_end(buf);
            if fallback_resp.is_ok() {
                fallback_resp.ok().unwrap()
            } else {
                return None;
            }
        },
    };

    if read_size > 0 {
        let received = match mc_packets::ReceivablePacket::deserialize_from(buf) {
            Ok(x) => Some(x),
            Err(error) => {
                error!("Failed to deserialize recieved packet from Server: {}", error);
                None
            }
        };

        match received {
            Some(mc_packets::ReceivablePacket::StatusResponse(packet)) => Some(packet.status),
            Some(mc_packets::ReceivablePacket::PingResponse(packet)) => {
                info!("Received Ping Response instead of Status Response. Pong Number: {}", packet.number);
                None
            }
            _ => None
        }
    } else {
        error!("Received no bytes back from read");
        return None
    }
}

fn main() {
    env_logger::init();
    let app_cli = Args::parse();
    info!("MineCraft Scanner!");

    match &app_cli.action {
        Action::Scan {include, exclude, port, threads} => {
            let mut include_ranges = HashSet::<(u32, u32)>::new();
            for cidr_str in include {
                include_ranges.insert(match range_from_cidr(cidr_str) {
                    Ok(x) => x,
                    Err(error) => {
                        warn!("Bad CIDR provided as include: {}. Skipping.", error);
                        continue
                    }
                });
            }
        
            let mut exclude_ranges = HashSet::<(u32, u32)>::new();
            for cidr_str in exclude {
                exclude_ranges.insert(match range_from_cidr(cidr_str) {
                    Ok(x) => x,
                    Err(error) => {
                        warn!("Bad CIDR provided as exclude: {}. Skipping.", error);
                        continue
                    }
                });
            }
        
            let scan_ranges = merge_include_and_exclude_ranges(&include_ranges, &exclude_ranges);
            let pool = ThreadPool::new(*threads as usize);
        
            for range in scan_ranges {
                for ip in range.0 ..= range.1 {
                    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), *port);
                    pool.execute(move || {
                        let resp = try_addr(&addr, None);
                        if resp.is_some() {
                            info!("{}", resp.unwrap());
                        }
                    });
                }
            }

            info!("Exiting Scan");
        },
        Action::Single {host, port} => {
            let full_address = host.clone() + ":" + port.to_string().as_str();
            let addr = match full_address.to_socket_addrs() {
                Ok(mut addrs) => {
                    let next = addrs.next();
                    next
                },
                Err(error) => {
                    error!("Invalid Host Provided: {}", error);
                    return;
                }
            };
            let resp = match addr {
                Some(addr) => try_addr(&addr, Some(&host)),
                None => {
                    error!("Hostname did not resolve to an address.");
                    return;
                }
            };
            if resp.is_some() {
                info!("{}", resp.unwrap());
            }
        }
    };
    
    
}
