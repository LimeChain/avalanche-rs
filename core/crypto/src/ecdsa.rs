use ring::signature;
use x509_certificate::X509Certificate;

pub fn verify_ecdsa_signature(cert: &X509Certificate, msg: &[u8], signature: &[u8]) -> () {
    let public_key =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1,
                                          cert.public_key_data());

    public_key.verify(msg, &signature).expect("signature verification failed")
}
