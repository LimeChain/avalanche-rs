use std::cell::Cell;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use log::{info, trace};
use env_logger::Env;
use mio::net::TcpStream;
use rustls::ServerName;
use avalanche_types::message;
use bootstrap::Bootstrappers;
use crypto::rsa;
use network::peer::{inbound, outbound};
use network::tls::client::{CLIENT, TlsClient};
use hex;
use rustls::sign::CertifiedKey;
use avalanche_types::packer::ip::IP_LEN;
use avalanche_types::packer::Packer;

fn main() {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    start().expect("failed to start client");
    info!("Done!");
}

/*
 * Starts the client
 */
fn start() -> io::Result<()> {
    let bootstrappers = Bootstrappers::read_boostrap_json();
    // TODO: Add cli parameter for chain selection
    let peer  = bootstrappers.mainnet.get(0).expect("failed to get peer");
    let cert = network::tls::certificate::generate_certificate().expect("failed to generate certificate");
    let connector = outbound::Connector::new_from_pem(&cert.key_path, &cert.cert_path)?;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let server_name: ServerName = ServerName::try_from(peer.ip.ip().to_string().as_ref()).unwrap();
    let sock = TcpStream::connect(peer.ip).unwrap();
    let tls_client = Arc::new(Mutex::new(TlsClient::new(sock, server_name, connector.client_config.clone())));

    let tls_client_clone = tls_client.clone();
    rt.spawn( async move {
        connector.connect(tls_client_clone, Duration::from_secs(10)).expect("failed to connect to peer");
    });

    let now = SystemTime::now();
    let now_unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("unexpected None duration_since")
        .as_secs();

    let packer = Packer::new(IP_LEN + 8, 0);
    // packer.pack_ip_with_timestamp(IpAddr::V4(Ipv4Addr::from_str("54.94.43.49").unwrap()), 9651, 1695411469).expect("failed to pack ip");
    packer.pack_ip_with_timestamp(IpAddr::V4(Ipv4Addr::LOCALHOST), 9651, now_unix).expect("failed to pack ip");
    let packed = packer.take_bytes();
    let (private_key, cert) =
        cert_manager::x509::load_pem_key_cert_to_der(cert.key_path.as_ref(), cert.cert_path.as_ref())?;

    info!("private key is {}", hex::encode(private_key.0.clone()));
    let signature = rsa::sign_message(packed.as_ref(), &private_key.0).expect("failed to sign message");

    let sig_bytes: Box<[u8]> = Box::from(signature.as_ref());
    let msg = message::version::Message::default()
        .network_id(1)
        .my_time(now_unix)
        .ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .ip_port(9651)
        .my_version("avalanche/1.10.11".to_string())
        .my_version_time(now_unix)
        .sig(sig_bytes.to_vec())
        .tracked_subnets(Vec::new());

    let mut msg = msg.serialize().expect("failed serialize");
    prepend_length(&mut msg);
    info!("Sending version message: {}", hex::encode(msg.clone()));
    tls_client.lock().expect("Failed to obtain lock").send_version_message(&msg).expect("failed to write");
    Ok(())
}

fn prepend_length(vec: &mut Vec<u8>) {
    let length = vec.len();
    let mut length_bytes = vec![];

    // Convert the length to bytes (big-endian byte order)
    for i in (0..std::mem::size_of::<usize>()).rev() {
        length_bytes.push(((length >> (i * 8)) & 0xFF) as u8);
    }

    // Insert the length bytes at the beginning of the vector
    vec.splice(0..0, length_bytes);
}

#[test]
fn test_pack_ip() {
    let packer = Packer::new(IP_LEN + 8, 0);
    let packed = packer.pack_ip_with_timestamp(IpAddr::V4(Ipv4Addr::from_str("54.94.43.49").unwrap()), 9651, 1696840122).expect("failed to pack ip");
    println!("packed ip is {}", hex::encode(packer.take_bytes().as_ref()));
}

#[test]
fn test_hashing() {
    //00000000000000000000ffff365e2b3125b300000000650ded0d
    let hashed = "";
    assert_eq!("f9bdc1aa480af190c3e90397ad4f68d776a4871badff6bb4ecd25951ef65ad60", hashed)
}