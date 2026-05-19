//! AES-128-CBC block encryption/decryption using RustCrypto.

use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

use super::BlockCrypto;

/// AES-128-CBC crypto with a fixed key and IV.
pub struct AesCrypto {
    key: [u8; 16],
    iv: [u8; 16],
}

impl AesCrypto {
    pub const fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self { key, iv }
    }
}

impl BlockCrypto for AesCrypto {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        // Pad to block boundary
        let pad_len = (16 - data.len() % 16) % 16;
        let mut buf = data.to_vec();
        buf.extend(std::iter::repeat(0u8).take(pad_len));

        let enc = Encryptor::<Aes128>::new_from_slices(&self.key, &self.iv)
            .expect("valid key/iv length");
        let out_len = buf.len();
        let encrypted = enc
            .encrypt_padded::<NoPadding>(&mut buf, out_len)
            .expect("encryption failed");
        encrypted.to_vec()
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        let dec = Decryptor::<Aes128>::new_from_slices(&self.key, &self.iv)
            .expect("valid key/iv length");
        let decrypted = dec
            .decrypt_padded::<NoPadding>(&mut buf)
            .expect("decryption failed");
        decrypted.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_round_trip() {
        let crypto = AesCrypto::new(
            [0x98, 0xD3, 0x10, 0x45, 0x23, 0xD6, 0x3A, 0x83, 0x20, 0x16, 0x82, 0x20, 0x10, 0x82, 0x49, 0x49],
            [0xE7, 0x86, 0x20, 0x49, 0x20, 0x49, 0x44, 0x20, 0x69, 0x6E, 0x67, 0x20, 0x20, 0x6E, 0x44, 0x20],
        );
        let plaintext = b"Hello, VW flash!"; // exactly 16 bytes
        let encrypted = crypto.encrypt(plaintext);
        let decrypted = crypto.decrypt(&encrypted);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn aes_round_trip_multi_block() {
        let crypto = AesCrypto::new([0x01; 16], [0x02; 16]);
        let plaintext = vec![0xABu8; 64]; // 4 blocks
        let encrypted = crypto.encrypt(&plaintext);
        assert_eq!(encrypted.len(), 64);
        let decrypted = crypto.decrypt(&encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_pads_to_block_boundary() {
        let crypto = AesCrypto::new([0x01; 16], [0x02; 16]);
        let plaintext = vec![0x55u8; 17]; // not aligned
        let encrypted = crypto.encrypt(&plaintext);
        assert_eq!(encrypted.len(), 32); // padded to next 16-byte boundary
    }
}
