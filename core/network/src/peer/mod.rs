use std::error::Error;
use std::net::IpAddr;
use std::ptr::null;
use std::time::SystemTime;
use avalanche_types::message;
use avalanche_types::message::bytes_to_ip_addr;
use crate::peer::ipaddr::{SignedIp, UnsignedIp};

pub mod inbound;
pub mod outbound;
pub mod ipaddr;
pub mod staking;

/// Represents a remote peer from the local node.
/// ref. <https://pkg.go.dev/github.com/ava-labs/avalanchego/network/peer#Start>
pub struct Peer {
    pub stream: outbound::Stream,

    pub ready: bool,
    pub network_id: u32,
    pub ip: Option<SignedIp>,
}

impl Peer {
    pub fn new(stream: outbound::Stream, network_id: u32) -> Self {
        Self {
            stream,
            ready: false,
            network_id,
            ip: None,
        }
    }

    pub fn handle_version(&mut self, msg: message::version::Message)  {
        if msg.msg.network_id != self.network_id {
            log::warn!(
                "Peer network ID {} doesn't match our network ID {}",
                msg.msg.network_id,
                self.network_id
            );
            return;
        }

        let now_unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("unexpected None duration_since")
            .as_secs();
        let time_diff = msg.msg.my_time.abs_diff(now_unix);
        if time_diff > 60 {
            log::warn!(
                "Peer time is off by {} seconds",
                time_diff
            );
            return;
        }

        // Skip version compatibility check for now

        if msg.msg.my_version_time.abs_diff(now_unix) > 60 {
            log::warn!(
                "Peer version time is off by {} seconds",
                msg.msg.my_version_time.abs_diff(now_unix)
            );
            return;
        }

        // Skip subnet handling for now
        if msg.msg.ip_addr.len() != 16 {
            log::warn!(
                "Peer IP address is not 16 bytes long"
            );
            return;
        }

        let ip_addr = match bytes_to_ip_addr(msg.msg.ip_addr.to_vec()) {
            Ok(ip_addr) => ip_addr,
            Err(e) => {
                log::warn!("Peer IP address is invalid: {}", e);
                return
            }
        };

        self.ip = Some(SignedIp::new(
            UnsignedIp::new(
                ip_addr,
                msg.msg.ip_port as u16,
                msg.msg.my_version_time
            ),
            msg.msg.sig.to_vec(),
        ));

        match self.ip.as_mut().unwrap().verify(&self.stream.peer_x509_certificate) {
            Ok(_) => {
                log::info!("Peer IP address verified");
            },
            Err(e) => {
                log::warn!("Peer IP address verification failed: {}", e);
                return
            }
        };

        // TODO: Send peer list message
    }
}

/// RUST_LOG=debug cargo test --package network --lib -- peer::test::test_listener --exact --show-output
///
/// TODO: make this test work. The client and server are both initialized correctly,
/// but making a connection fails.
/// Error is Os { code: 61, kind: ConnectionRefused, message: "Connection refused" } when connecting client to server.
#[cfg(test)]
mod test {
    use rcgen::CertificateParams;
    use rustls::ServerConfig;
    use std::{
        io::{self, Error, ErrorKind},
        net::{IpAddr, SocketAddr},
        str::FromStr,
        sync::Arc,
        time::Duration,
    };
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use crate::peer::outbound;

    #[tokio::test]
    #[ignore]
    async fn test_listener() -> io::Result<()> {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Trace)
            // .is_test(true)
            .try_init();

        let server_key_path = random_manager::tmp_path(10, None)?;
        let server_cert_path = random_manager::tmp_path(10, None)?;
        let server_cert_sna_params = CertificateParams::new(vec!["127.0.0.1".to_string()]);
        cert_manager::x509::generate_and_write_pem(
            Some(server_cert_sna_params),
            &server_key_path,
            &server_cert_path,
        )?;

        log::info!("[rustls] loading raw PEM files for inbound listener");
        let (private_key, certificate) = cert_manager::x509::load_pem_key_cert_to_der(
            server_key_path.as_ref(),
            server_cert_path.as_ref(),
        )?;

        let ip_addr = String::from("127.0.0.1");
        let ip_port = 9649_u16;

        let join_handle = tokio::task::spawn(async move {
            let server_config = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], private_key)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("failed to create TLS server config '{}'", e),
                    )
                })
                .unwrap();

            let ip = ip_addr.clone().parse::<std::net::IpAddr>().unwrap();
            let addr = SocketAddr::new(ip, ip_port);

            let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
            let tcp_listener = TcpListener::bind(addr).await.unwrap();

            loop {
                let (stream, _) = tcp_listener.accept().await.unwrap();
                let tls_acceptor = tls_acceptor.clone();
                log::info!("accepting TLS connection");
                let _ = tokio::spawn(async move {
                    match tls_acceptor.accept(stream).await {
                        Ok(_tls_stream) => {
                            println!("TLS connection accepted");
                            // handle(tls_stream).await
                        }
                        Err(e) => eprintln!("Error accepting TLS connection: {:?}", e),
                    }
                })
                .await;
            }
        });

        let client_key_path = random_manager::tmp_path(10, None)?;
        let client_cert_path = random_manager::tmp_path(10, None)?;
        let client_cert_sna_params = CertificateParams::new(vec!["127.0.0.1".to_string()]);
        cert_manager::x509::generate_and_write_pem(
            Some(client_cert_sna_params),
            &client_key_path,
            &client_cert_path,
        )?;
        log::info!("client cert path: {}", client_cert_path);

        let connector = outbound::Connector::new_from_pem(&client_key_path, &client_cert_path)?;
        let stream = connector.connect(
            IpAddr::from_str("127.0.0.1").unwrap(),
            ip_port,
            Duration::from_secs(5),
        )?;

        log::info!("peer certificate:\n\n{}", stream.peer_certificate_pem);

        join_handle.await?; // Hangs

        Ok(())
    }
}

// Represents an attached "test" peer to a remote peer
// with a hollow inbound handler implementation.
// Only used for testing.
// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/network/peer#Start
// ref. https://pkg.go.dev/github.com/ava-labs/avalanchego/network/peer#StartTestPeer
