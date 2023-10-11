//! Definitions of messages that can be sent between nodes.
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

pub fn ip_addr_to_bytes(ip_addr: std::net::IpAddr) -> Vec<u8> {
    match ip_addr {
        std::net::IpAddr::V4(v) => {
            // "avalanchego" encodes IPv4 address as it is
            // (not compatible with IPv6, e.g., prepends 2 "0xFF"s as in Rust)
            let [a, b, c, d] = v.octets();
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d]
        }
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    }
}

pub fn bytes_to_ip_addr(bytes: Vec<u8>) -> Option<IpAddr> {
    let bytes: [u8; 16] = bytes.try_into().ok()?;

    let ip_addr = IpAddr::from(bytes);

    Some(ip_addr)
}

fn prepend_message_length(message: &mut Vec<u8>) {
    let length = message.len();
    // Explicitly turning into a u64 so that 32 bit platforms won't be different behaviour
    let length_bytes = (length as u64).to_be_bytes();

    // Insert the length bytes at the beginning of the vector
    message.splice(0..0, length_bytes);
}
