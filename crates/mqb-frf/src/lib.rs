//! FRF file decryption and ZIP extraction.
//!
//! FRF files are encrypted with a recursive XOR cipher and then contain a ZIP
//! archive with SGO (binary flash data) or ODX XML.

use std::collections::HashMap;
use std::io::{self, Read};
use thiserror::Error;
use zip::ZipArchive;

/// Embedded FRF decryption key.
static FRF_KEY: &[u8] = include_bytes!("../../../data/frf.key");

#[derive(Debug, Error)]
pub enum FrfError {
    #[error("FRF decryption produced invalid ZIP: {0}")]
    InvalidZip(#[from] zip::result::ZipError),
    #[error("IO error reading FRF ZIP entry: {0}")]
    Io(#[from] io::Error),
}

/// Decrypt FRF-encrypted data using the embedded key.
///
/// Algorithm: recursive XOR cipher — see `frf/decryptfrf.py`.
pub fn decrypt_frf(encrypted_data: &[u8]) -> Vec<u8> {
    let key = FRF_KEY;
    let mut output = Vec::with_capacity(encrypted_data.len());
    let mut first_seed: u32 = 0;
    let mut second_seed: u32 = 1;
    for (key_index, &data_byte) in encrypted_data.iter().enumerate() {
        let key_byte = key[key_index % key.len()] as u32;
        first_seed = ((first_seed + key_byte) * 3) & 0xFF;
        let decrypted = data_byte ^ ((first_seed ^ 0xFF ^ second_seed ^ key_byte) as u8);
        output.push(decrypted);
        second_seed = ((second_seed + 1) * first_seed) & 0xFF;
    }

    output
}

/// Decrypt a FRF file and extract all contents from the inner ZIP.
///
/// Returns a map of `filename → file_bytes`.
pub fn extract_frf(encrypted_data: &[u8]) -> Result<HashMap<String, Vec<u8>>, FrfError> {
    let decrypted = decrypt_frf(encrypted_data);
    let cursor = io::Cursor::new(decrypted);
    let mut archive = ZipArchive::new(cursor)?;
    let mut files = HashMap::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_owned();
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;
        files.insert(name, contents);
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_empty() {
        // Edge case: empty input
        let result = decrypt_frf(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn decrypt_roundtrip_deterministic() {
        // Encrypting twice with different seeds gives different results — the
        // cipher is a stream cipher, so just verify it's deterministic.
        let input = b"Hello, FRF!";
        let out1 = decrypt_frf(input);
        let out2 = decrypt_frf(input);
        assert_eq!(out1, out2);
        // The output should differ from the input (actually decrypting)
        assert_ne!(out1.as_slice(), input.as_slice());
    }
}
