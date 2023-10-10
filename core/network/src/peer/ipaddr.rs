use std::io;
use std::net::IpAddr;
use x509_certificate::X509Certificate;
use avalanche_types::packer::ip::IP_LEN;
use avalanche_types::packer::Packer;
use crate::peer::staking;

pub struct SignedIp {
    pub unsigned_ip: UnsignedIp,
    pub signature: Vec<u8>,
}

pub struct UnsignedIp {
    pub ip: IpAddr,
    pub port: u16,
    pub timestamp: u64,
}

impl UnsignedIp {
    pub fn new(ip: IpAddr, port: u16, timestamp: u64) -> Self {
        Self {
            ip,
            port,
            timestamp,
        }
    }
}

impl SignedIp {
    pub fn new(unsigned_ip: UnsignedIp, signature: Vec<u8>) -> Self {
        Self {
            unsigned_ip,
            signature,
        }
    }

    pub fn verify(&self, cert: &X509Certificate) -> io::Result<()> {
        let packer = Packer::new(IP_LEN + 8, 0);
        if packer.pack_ip_with_timestamp(self.unsigned_ip.ip, self.unsigned_ip.port, self.unsigned_ip.timestamp).is_err() {
            return Err(io::Error::new(io::ErrorKind::Other, "failed to pack ip"));
        }
        let packed = packer.take_bytes();
        staking::check_signature(cert, packed.as_ref(), self.signature.as_ref())?;
        Ok(())
    }
}