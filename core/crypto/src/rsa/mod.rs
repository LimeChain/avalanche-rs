use ring::signature;
use thiserror::Error;

pub fn verify_pkcs1v15_signature(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), RsaError> {
    let public_key =
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,
                                          public_key);

    match public_key.verify(msg, &signature) {
        Ok(_) => Ok(()),
        Err(e) => Err(RsaError::Verify(e))
    }
}

#[derive(Error, Debug)]
pub enum RsaError {
    #[error("Failed to create a EcdsaKeyPair")]
    EcdsaKeyPairRejected(#[from] ring::error::KeyRejected),
    #[error("Failed to verify message")]
    Verify(#[from] ring::error::Unspecified)
}