//! Simos XOR "encryption": byte[i] XOR (i % 256). Symmetric.

use super::BlockCrypto;

pub struct SimosXorCrypto;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_is_symmetric() {
        let crypto = SimosXorCrypto;
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let encrypted = crypto.encrypt(&data);
        assert_ne!(encrypted, data);
        let decrypted = crypto.decrypt(&encrypted);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn xor_known_values() {
        let crypto = SimosXorCrypto;
        // byte[i] ^ i: 0^0=0x00, 0xFF^1=0xFE, 0xAA^2=0xA8
        let input = vec![0x00u8, 0xFF, 0xAA];
        let out = crypto.encrypt(&input);
        assert_eq!(out, vec![0x00, 0xFE, 0xA8]);
    }
}

impl BlockCrypto for SimosXorCrypto {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ (i as u8))
            .collect()
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        // Symmetric
        self.encrypt(data)
    }
}
