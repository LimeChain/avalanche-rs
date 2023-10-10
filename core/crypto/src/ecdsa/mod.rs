use log::info;
use ring::signature;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Signature};
use thiserror::Error;
use crate::secure_random;

pub fn verify_signature(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), EcdsaError> {
    let public_key =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1,
                                          public_key);

    match public_key.verify(&msg, &signature) {
        Ok(_) => Ok(()),
        Err(e) => Err(EcdsaError::SignOrVerify(e))
    }
}

pub fn sign_message(message: &[u8], private_key: &[u8]) -> Result<Signature, EcdsaError> {
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key, secure_random())?;
    let sig = key_pair.sign(secure_random(), &message)?;
    info!("message is: {:?}", hex::encode(message));
    info!("sig is: {:?}", hex::encode(sig.as_ref()));
    Ok(sig)
}

#[derive(Error, Debug)]
pub enum EcdsaError {
    #[error("Failed to create a EcdsaKeyPair")]
    EcdsaKeyPairRejected(#[from] ring::error::KeyRejected),
    #[error("Failed to sign or verify message")]
    SignOrVerify(#[from] ring::error::Unspecified)
}