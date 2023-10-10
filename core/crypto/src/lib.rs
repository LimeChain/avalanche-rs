use lazy_static::lazy_static;
use ring::rand::{SystemRandom, SecureRandom};

pub mod rsa;
pub mod ecdsa;

#[cfg(not(windows))]
pub  fn secure_random() -> &'static dyn SecureRandom {
    use std::ops::Deref;
    lazy_static! {
        static ref RANDOM: SystemRandom = SystemRandom::new();
    }
    RANDOM.deref()
}
