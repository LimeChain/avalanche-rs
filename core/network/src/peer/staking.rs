use std::io;
use x509_certificate::X509Certificate;
use crypto::{ecdsa, rsa};

const MAX_CERT_SIZE: usize = 16 * 1024; // 16KiB
pub fn check_signature(cert: &X509Certificate, msg: &[u8], signature: &[u8]) -> io::Result<()> {
    validate_certificate(cert)?;

    let alg = cert.signature_algorithm().expect("failed to get signature algorithm");
    match alg {
        x509_certificate::SignatureAlgorithm::RsaSha256 => {
            rsa::verify_pkcs1v15_signature(cert.public_key_data().as_ref(), msg, signature);
        }
        x509_certificate::SignatureAlgorithm::EcdsaSha256 => {
            ecdsa::verify_signature(cert.public_key_data().as_ref(), msg, signature);
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::Other, "unsupported signature algorithm"));
        }
    }
    Ok(())
}

fn validate_certificate(cert: &X509Certificate) -> io::Result<()> {
    if cert.encode_der().expect("failed to encode").len() > MAX_CERT_SIZE {
        return Err(io::Error::new(io::ErrorKind::Other, "certificate too large"));
    }

    // Skip public key validation for now

    Ok(())
}