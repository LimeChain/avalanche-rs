use std::fmt::Error;
use lazy_static::lazy_static;
use log::info;
use ring::digest;
#[cfg(not(windows))]
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Signature}; // requires 'getrandom' feature

pub fn sign_message(message: &[u8], private_key: &[u8]) -> Result<Signature, Error> {
    let hashed_msg = compute_hash256(message);
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key, secure_random())
        .expect("fail");
    let sig = key_pair.sign(secure_random(), &hashed_msg).expect("fail");
    info!("message is: {:?}", hex::encode(message));
    info!("hash is: {:?}", hex::encode(hashed_msg));
    info!("sig is: {:?}", hex::encode(sig.as_ref()));
    Ok(sig)
}

fn compute_hash256(buf: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let sha256_digest = digest::digest(&digest::SHA256, buf);
    result.copy_from_slice(sha256_digest.as_ref());
    result
}

#[cfg(not(windows))]
fn secure_random() -> &'static dyn SecureRandom {
    use std::ops::Deref;
    lazy_static! {
        static ref RANDOM: SystemRandom = SystemRandom::new();
    }
    RANDOM.deref()
}
