use thiserror::Error;
use lazy_static::lazy_static;
use log::info;
use ring::{digest, signature};
#[cfg(not(windows))]
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, RsaEncoding, Signature};
use x509_certificate::X509Certificate;

pub fn verify_pkcs1v15_signature(cert: &X509Certificate, msg: &[u8], signature: &[u8]) -> () {
    let public_key =
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,
                                          cert.public_key_data());

    public_key.verify(msg, &signature).expect("fail")
}
pub fn sign_message(message: &[u8], private_key: &[u8]) -> Result<Signature, RsaError> {
    let hashed_msg = compute_hash256(message);
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key, secure_random())?;
    let sig = key_pair.sign(secure_random(), &hashed_msg)?;
    info!("message is: {:?}", hex::encode(message));
    info!("hash is: {:?}", hex::encode(hashed_msg));
    info!("sig is: {:?}", hex::encode(sig.as_ref()));
    Ok(sig)
}

// pub fn sign_message_2(message: &[u8], private_key: &[u8]) -> Result<EcdsaSig, Error> {
//     let hashed_msg = compute_hash256(message);
//     let key = signature::RsaKeyPair::from_pkcs8(private_key).expect("fail");
//     let sig = key.sign(, secure_random(), &hashed_msg).expect("fail")
//     info!("message is: {:?}", hex::encode(message));
//     info!("hash is: {:?}", hex::encode(hashed_msg));
//     info!("sig is: {:?}", hex::encode(&sig.to_der().unwrap()));
//     Ok(sig)
// }

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

#[derive(Error, Debug)]
pub enum RsaError {
    #[error("Failed to create a EcdsaeKeyPair")]
    EcdsaeKeyPairRejected(#[from] ring::error::KeyRejected),
    #[error("Failed to sign key")]
    Signing(#[from] ring::error::Unspecified)
}