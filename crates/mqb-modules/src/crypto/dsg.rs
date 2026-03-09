//! DSG progressive substitution cipher.
//!
//! The key table is embedded from `data/mqb_dsg_key.bin`.
//! A rolling offset accumulates:
//!   offset += key[data_byte + offset & 0xFF]
//!   offset += last_plaintext_byte
//!   rolling_stream_offset += 0x167
//!   offset += key[(rolling_stream_offset >> 8) & 0xFF]

use super::BlockCrypto;

static DSG_KEY: &[u8] = include_bytes!("../../../../data/mqb_dsg_key.bin");

pub struct DsgCrypto;

impl BlockCrypto for DsgCrypto {
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let key = DSG_KEY;
        let mut output = Vec::with_capacity(data.len());
        let mut offset: u32 = 0;
        let mut rolling: u32 = 0;
        let mut last_data: u8 = 0;

        for &cipher_byte in data {
            let idx = (cipher_byte as u32).wrapping_add(offset) as u8;
            let plain = key[idx as usize];
            offset = offset.wrapping_add(plain as u32);
            offset = offset.wrapping_add(last_data as u32);
            rolling = rolling.wrapping_add(0x167);
            offset = offset.wrapping_add(key[((rolling >> 8) & 0xFF) as usize] as u32);
            last_data = plain;
            output.push(plain);
        }
        output
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let key = DSG_KEY;
        // Build inverse lookup: inv[key[i]] = i for all i.
        // The key is a 256-byte permutation, so every byte value appears exactly once.
        let mut inv = [0u8; 256];
        for (i, &k) in key.iter().enumerate() {
            inv[k as usize] = i as u8;
        }

        let mut output = Vec::with_capacity(data.len());
        let mut offset: u32 = 0;
        let mut rolling: u32 = 0;
        let mut last_data: u8 = 0;

        for &plain in data {
            let match_index = inv[plain as usize] as u32;
            let cipher_byte = match_index.wrapping_sub(offset) as u8;
            offset = offset.wrapping_add(plain as u32);
            offset = offset.wrapping_add(last_data as u32);
            rolling = rolling.wrapping_add(0x167);
            offset = offset.wrapping_add(key[((rolling >> 8) & 0xFF) as usize] as u32);
            last_data = plain;
            output.push(cipher_byte);
        }
        output
    }
}
