use std::fs;
use std::fs::File;
use std::path::Path;
use rsa::{pkcs8, RsaPrivateKey};
use log::info;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rustls_pemfile;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::hazmat::PrehashSigner;

// Generate an RSA private key and save it to a file
pub fn generate_and_save_private_key(filename: &str, bits: usize) -> Result<(), Box<dyn std::error::Error>> {
    // Generate an RSA private key
    let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), bits)?;

    // Write the private key to a file
    priv_key.write_pkcs8_pem_file(Path::new(filename), LineEnding::LF).expect("failed to write private key");
    info!("Private key saved to {}", filename);
    Ok(())
}


// Read an RSA private key from a file
pub fn read_tls_private_key_from_file(filename: &str) -> Result<rustls::PrivateKey, Box<dyn std::error::Error>> {
    // Read the private key from the file
    let file = File::open(filename).expect("failed to open file");
    let mut reader = std::io::BufReader::new(file);

    // Parse the private key from PEM format
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader).expect("failed to parse private key");

    match keys.len() {
        0 => Err(format!("No PKCS8-encoded private key found in {filename}").into()),
        1 => Ok(rustls::PrivateKey(keys.remove(0))),
        _ => Err(format!("More than one PKCS8-encoded private key found in {filename}").into()),
    }
}

// Read an RSA private key from a file
pub fn read_private_key_from_file(filename: &str) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    // Read the private key from the file
    let key = fs::read_to_string(filename).expect("failed to read private key");
    // Parse the private key from PEM format
    let decoded = pkcs8::DecodePrivateKey::from_pkcs8_pem(key.as_str())?;
    Ok(decoded)
}


pub fn sign_message(message: &[u8], private_key: RsaPrivateKey) -> Result<Signature, Box<dyn std::error::Error>> {
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_prehash(message).expect("failed to sign message");
    Ok(signature)
}
