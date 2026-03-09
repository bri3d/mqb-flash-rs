//! No-op crypto passthrough (no encryption/decryption).

use super::BlockCrypto;

pub struct NoCrypto;

impl BlockCrypto for NoCrypto {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}
