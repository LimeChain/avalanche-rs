use log::{info, warn};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::process;
use std::sync::Arc;
use std::time::SystemTime;

use crate::peer::ipaddr::{SignedIp, UnsignedIp};
use avalanche_types::ids::node;
use avalanche_types::message::bytes_to_ip_addr;
use avalanche_types::message::version::Message;
use mio::net::TcpStream;
use x509_certificate::X509Certificate;

pub const CLIENT: mio::Token = mio::Token(0);

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
pub struct TlsClient {
    pub socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    received_first_message: bool,
    pub tls_conn: rustls::ClientConnection,
    network_id: u32,
    x509_certificate: Option<X509Certificate>,
    ip: Option<SignedIp>,
    peer_node_id: Option<node::Id>,
    peer_cert: Option<rustls::Certificate>,
}

impl TlsClient {
    pub fn new(
        sock: TcpStream,
        server_name: rustls::ServerName,
        cfg: Arc<rustls::ClientConfig>,
        network_id: u32,
    ) -> Self {
        Self {
            socket: sock,
            closing: false,
            clean_closure: false,
            received_first_message: false,
            tls_conn: rustls::ClientConnection::new(cfg, server_name).unwrap(),
            network_id,
            x509_certificate: None,
            ip: None,
            peer_node_id: None,
            peer_cert: None,
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    pub(crate) fn ready(&mut self, ev: &mio::event::Event) {
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() {
            self.do_read();
        }

        if ev.is_writable() {
            let _ = self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_conn.writer().write_all(&buf)?;
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return;
                }
                println!("TLS read error: {:?}", error);
                self.closing = true;
                return;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = vec![0u8; io_state.plaintext_bytes_to_read()];
            self.tls_conn.reader().read_exact(&mut plaintext).unwrap();

            // TODO: Improve length removal
            let real_message = plaintext[4..].to_vec();
            let version =
                Message::deserialize(real_message).expect("failed to deserialize version message");
            info!("Received version message: {:?}", version);
            self.handle_version(version);
        }

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
        }
    }

    pub fn do_write(&mut self) -> io::Result<()> {
        while self.tls_conn.wants_write() {
            self.tls_conn.write_tls(&mut self.socket)?;
        }
        Ok(())
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry) -> io::Result<()> {
        let interest = self.event_set();
        registry.register(&mut self.socket, CLIENT, interest)
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    pub(crate) fn reregister(&mut self, registry: &mio::Registry) -> io::Result<()> {
        let interest = self.event_set();
        registry.reregister(&mut self.socket, CLIENT, interest)
    }

    /// Sends a version message over the TLS connection.
    pub fn send_version_message(&mut self, version_message: &[u8]) -> io::Result<usize> {
        info!("Writing version message to stream");
        self.tls_conn.writer().write_all(version_message)?;
        self.do_write()?; // Flush the TLS data to the socket
        info!("Flushed message to stream");
        Ok(version_message.len())
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }

    pub fn handle_version(&mut self, msg: Message) {
        // TODO: There must be a better(earlier) time to extract the certificate data
        if self.handle_certificate().is_err() {
            warn!("Failed to handle peer certificate");
            return;
        }

        if msg.msg.network_id != self.network_id {
            warn!(
                "Peer network ID {} doesn't match our network ID {}",
                msg.msg.network_id, self.network_id
            );
            return;
        }

        let now_unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("unexpected None duration_since")
            .as_secs();

        let time_diff = msg.msg.my_time.abs_diff(now_unix);
        if time_diff > 60 {
            warn!("Peer time is off by {} seconds", time_diff);
            return;
        }

        // Skip version compatibility check for now

        if msg.msg.my_version_time.abs_diff(now_unix) > 60 {
            warn!(
                "Peer version time is off by {} seconds",
                msg.msg.my_version_time.abs_diff(now_unix)
            );
            return;
        }

        // Skip subnet handling for now
        if msg.msg.ip_addr.len() != 16 {
            warn!("Peer IP address is not 16 bytes long");
            return;
        }

        let ip_addr = match bytes_to_ip_addr(msg.msg.ip_addr.to_vec()) {
            Some(ip_addr) => ip_addr,
            None => {
                warn!("Peer IP address is invalid");
                return;
            }
        };

        if let Some(cert) = &self.x509_certificate {
            let ip = SignedIp::new(
                UnsignedIp::new(ip_addr, msg.msg.ip_port as u16, msg.msg.my_version_time),
                msg.msg.sig.to_vec(),
            );

            match ip.verify(cert) {
                Ok(()) => {
                    info!("Peer IP address verified");
                    self.ip = Some(ip)
                }
                Err(e) => {
                    warn!("Peer IP address verification failed: {}", e);
                }
            }
        }

        // TODO: Send peer list message
    }

    fn handle_certificate(&mut self) -> io::Result<()> {
        info!("retrieving peer certificates...");
        let peer_certs = self.tls_conn.peer_certificates();

        let peer_cert = if let Some(peer_certs) = peer_certs.and_then(|slice| slice.first()) {
            peer_certs
        } else {
            return Err(Error::new(
                ErrorKind::NotConnected,
                "no peer certificate found",
            ));
        };

        // The certificate details are used to establish node identity.
        // See https://docs.avax.network/specs/cryptographic-primitives#tls-certificates.
        // The avalanchego certs are intentionally NOT signed by a legitimate CA.
        let peer_node_id = node::Id::from_cert_der_bytes(&peer_cert.0)?;
        let x509_certificate =
            X509Certificate::from_der(&peer_cert.0).expect("failed to parse certificate");

        info!("peer node ID: {}", peer_node_id);

        self.peer_node_id = Some(peer_node_id);
        self.peer_cert = Some(peer_cert.clone());
        self.x509_certificate = Some(x509_certificate);
        Ok(())
    }
}
impl Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_conn.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_conn.writer().flush()
    }
}

impl Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.reader().read(bytes)
    }
}
