//! Definitions of messages that can be sent between nodes.
use std::io;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;

pub mod accepted;
pub mod accepted_frontier;
pub mod accepted_state_summary;
pub mod ancestors;
pub mod app_gossip;
pub mod app_request;
pub mod app_response;
pub mod chits;
pub mod compress;
pub mod get;
pub mod get_accepted;
pub mod get_accepted_frontier;
pub mod get_accepted_state_summary;
pub mod get_ancestors;
pub mod get_state_summary_frontier;
pub mod peerlist;
pub mod ping;
pub mod pong;
pub mod pull_query;
pub mod push_query;
pub mod put;
pub mod state_summary_frontier;
pub mod version;
pub mod parser;

pub fn ip_addr_to_bytes(ip_addr: std::net::IpAddr) -> Vec<u8> {
    match ip_addr {
        std::net::IpAddr::V4(v) => {
            // "avalanchego" encodes IPv4 address as it is
            // (not compatible with IPv6, e.g., prepends 2 "0xFF"s as in Rust)
            let octets = v.octets();
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, octets[0], octets[1], octets[2], octets[3],
            ]
        }
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    }
}

pub fn bytes_to_ip_addr(bytes: Vec<u8>) -> io::Result<IpAddr> {
    let bytes: [u8; 16] = match bytes.as_slice() {
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] => {
            [
                *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o, *p
            ]
        },
        _ => {
            log::warn!(
                    "Peer IP address is not 16 bytes long"
                );
            return Err(Error::new(ErrorKind::Other, "Peer IP address is not 16 bytes long"));
        }
    };

    let ip_addr = match IpAddr::from(bytes) {
        IpAddr::V4(v) => IpAddr::V4(v),
        IpAddr::V6(v) => IpAddr::V6(v),
    };

    Ok(ip_addr)
}

fn prepend_message_length(message: &mut Vec<u8>) {
    let length = message.len();
    let mut length_bytes = vec![];

    // Convert the length to bytes (big-endian byte order)
    for i in (0..std::mem::size_of::<usize>()).rev() {
        length_bytes.push(((length >> (i * 8)) & 0xFF) as u8);
    }

    // Insert the length bytes at the beginning of the vector
    message.splice(0..0, length_bytes);
}

