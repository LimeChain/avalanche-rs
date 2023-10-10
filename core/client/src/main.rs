use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use log::{info};
use env_logger::Env;
use mio::net::TcpStream;
use rustls::ServerName;
use avalanche_types::message;
use bootstrap::Bootstrappers;
use crypto::{ecdsa};
use network::peer::{outbound};
use network::tls::client::{TlsClient};
use hex;
use avalanche_types::packer::ip::IP_LEN;
use avalanche_types::packer::Packer;
use crypto::ecdsa::verify_signature;

fn main() {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    match start() {
        Ok(_) => info!("Client started"),
        Err(e) => info!("Client failed to start: {}", e)
    }
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
    let tls_client = Arc::new(Mutex::new(TlsClient::new(sock, server_name, connector.client_config.clone(), 1)));

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
    packer.pack_ip_with_timestamp(IpAddr::V4(Ipv4Addr::LOCALHOST), 9651, now_unix).expect("failed to pack ip");
    let packed = packer.take_bytes();
    let (private_key, cert) =
        cert_manager::x509::load_pem_key_cert_to_der(cert.key_path.as_ref(), cert.cert_path.as_ref())?;
    info!("cert is {}", hex::encode(&cert.0));
    info!("private key is {}", hex::encode(private_key.0.clone()));
    let signature = ecdsa::sign_message(packed.as_ref(), &private_key.0).expect("failed to sign message");
    let x509_cert = x509_certificate::X509Certificate::from_der(&cert.0).expect("failed to parse cert");

    info!("public key is: {}", hex::encode(x509_cert.public_key_data().as_ref()));

    // if verify_signature(x509_cert.public_key_data().as_ref(), packed.as_ref(), signature.as_ref()).is_err() {
    //     panic!("failed to verify signature");
    // }

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

    let msg = msg.serialize().expect("failed serialize");
    info!("Sending version message: {}", hex::encode(msg.clone()));
    tls_client.lock().expect("Failed to obtain lock").send_version_message(&msg).expect("failed to write");
    Ok(())
}