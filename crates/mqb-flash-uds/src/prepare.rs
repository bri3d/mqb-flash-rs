//! Turning raw block bytes into a [`PreparedBlockData`] ready for the wire.
//!
//! Every field of a `PreparedBlockData` that used to be hardcoded at the call
//! site now comes from the module's own policy on [`FlashInfo`]. Before this
//! existed, the CLI and GUI each built `PreparedBlockData` by hand with Simos
//! constants — `0x0A`/`0x0A`, always-erase, LZSS with AES-block padding, and a
//! static UDS checksum — which is wrong on three of the four supported modules:
//!
//! | Module  | dataFormatIdentifier | Compression        | Erase       | UDS 0x0202 checksum |
//! |---------|----------------------|--------------------|-------------|---------------------|
//! | Simos18 | `0xAA`               | LZSS, pad to 0x10  | all blocks  | static table        |
//! | DQ250   | `0x11`               | LZSS, no padding   | not DRIVER  | static table        |
//! | DQ381   | `0xAA`               | LZSS, exact pad    | all blocks  | zlib CRC-32 BE      |
//! | Haldex  | `0x00`               | none — raw bytes   | not DRIVER  | zlib CRC-32 BE      |

use mqb_modules::{BlockCrypto, BlockPrep, FlashInfo, PreparedBlockData, UdsChecksumKind};

/// Compress (per the module's policy) and encrypt a raw block payload.
pub fn compress_and_encrypt(data: &[u8], flash_info: &FlashInfo) -> Vec<u8> {
    let compressed = match flash_info.block_prep {
        BlockPrep::LzssAesBlock => mqb_lzss::encode(data, mqb_lzss::Padding::AesBlock),
        BlockPrep::LzssNone => mqb_lzss::encode(data, mqb_lzss::Padding::None),
        BlockPrep::LzssExact => mqb_lzss::encode(data, mqb_lzss::Padding::Exact),
        // Haldex is flashed verbatim. Note this is the raw payload, not a
        // zero-length-compression encoding — the ECU is told `0x00`.
        BlockPrep::Raw => data.to_vec(),
    };
    flash_info.crypto.encrypt(&compressed)
}

/// LZSS-compress then AES-encrypt a raw binary block.
///
/// Deprecated shape kept for callers that only have a `&dyn BlockCrypto`.
/// Prefer [`compress_and_encrypt`], which honours the module's padding policy.
pub fn prepare_block_for_flash(data: &[u8], crypto: &dyn BlockCrypto) -> Vec<u8> {
    let compressed = mqb_lzss::encode(data, mqb_lzss::Padding::AesBlock);
    crypto.encrypt(&compressed)
}

/// Encrypt a raw binary without compression (unlock patch blocks, > 5).
pub fn prepare_patch_for_flash(data: &[u8], crypto: &dyn BlockCrypto) -> Vec<u8> {
    crypto.encrypt(data)
}

/// Build a [`PreparedBlockData`] for a normal block from its raw
/// (decompressed, checksum-corrected) bytes.
///
/// `raw` must already have had its internal checksums fixed — the UDS `0x0202`
/// checksum for CRC-32 modules is taken over exactly these bytes, so fixing a
/// checksum afterwards would make the two disagree and the ECU would reject the
/// block after a full transfer.
pub fn prepare_block(flash_info: &FlashInfo, block_num: u8, raw: &[u8]) -> PreparedBlockData {
    let uds_checksum = match flash_info.uds_checksum_kind {
        UdsChecksumKind::Static => flash_info.block_checksum(block_num).unwrap_or([0; 4]),
        UdsChecksumKind::Crc32Be => crc32fast::hash(raw).to_be_bytes(),
    };

    PreparedBlockData {
        block_number: block_num,
        block_encrypted_bytes: compress_and_encrypt(raw, flash_info),
        boxcode: String::new(),
        encryption_type: flash_info.encryption_type,
        compression_type: flash_info.compression_type,
        should_erase: flash_info.should_erase(block_num),
        uds_checksum,
        block_name: flash_info
            .block_number_to_name(block_num)
            .unwrap_or("UNKNOWN")
            .to_owned(),
        announced_length: flash_info.announced_length(block_num, raw.len()) as u32,
    }
}

/// Build a [`PreparedBlockData`] for an unlock patch block (number > 5).
///
/// Patch blocks are encrypted but never compressed, never erased, and carry no
/// UDS checksum — the patch flow ends at RequestTransferExit.
pub fn prepare_patch_block(flash_info: &FlashInfo, block_num: u8, raw: &[u8]) -> PreparedBlockData {
    let target_num = block_num.saturating_sub(5);
    PreparedBlockData {
        block_number: block_num,
        block_encrypted_bytes: prepare_patch_for_flash(raw, flash_info.crypto),
        boxcode: String::new(),
        encryption_type: 0x0A,
        compression_type: 0x00,
        should_erase: false,
        uds_checksum: [0; 4],
        block_name: "UNLOCK_PATCH".to_owned(),
        announced_length: flash_info.block_length(target_num).unwrap_or(raw.len()) as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mqb_modules::modules::{
        dq250mqb::DQ250_FLASH_INFO, dq381::DQ381_FLASH_INFO, haldex4motion::HALDEX_FLASH_INFO,
        simos18::S18_FLASH_INFO,
    };

    /// Each module's wire policy, pinned against the Python reference.
    /// Sources: simos_flash_utils.py:175-177, dsg_flash_utils.py:120-130/191-201,
    /// dq381_flash_utils.py:82/103/122-123, haldex_flash_utils.py:32-44.
    #[test]
    fn module_wire_policy_matches_python_reference() {
        let cases = [
            (
                &S18_FLASH_INFO,
                0xAAu8,
                BlockPrep::LzssAesBlock,
                UdsChecksumKind::Static,
                400u32,
            ),
            (
                &DQ250_FLASH_INFO,
                0x11,
                BlockPrep::LzssNone,
                UdsChecksumKind::Static,
                900,
            ),
            (
                &DQ381_FLASH_INFO,
                0xAA,
                BlockPrep::LzssExact,
                UdsChecksumKind::Crc32Be,
                900,
            ),
            (
                &HALDEX_FLASH_INFO,
                0x00,
                BlockPrep::Raw,
                UdsChecksumKind::Crc32Be,
                900,
            ),
        ];
        for (fi, dfi, prep, cks, stmin) in cases {
            assert_eq!(
                fi.data_format_identifier(),
                dfi,
                "DFI for {}",
                fi.project_name
            );
            assert_eq!(fi.block_prep, prep);
            assert_eq!(fi.uds_checksum_kind, cks);
            assert_eq!(fi.default_stmin_us, stmin);
        }
    }

    /// DQ250 must not erase DRIVER (block 2); Haldex must not erase DRIVER (block 1).
    #[test]
    fn driver_blocks_are_never_erased() {
        assert!(
            !DQ250_FLASH_INFO.should_erase(2),
            "DQ250 DRIVER must not be erased"
        );
        assert!(DQ250_FLASH_INFO.should_erase(3));
        assert!(DQ250_FLASH_INFO.should_erase(4));

        assert!(
            !HALDEX_FLASH_INFO.should_erase(1),
            "Haldex DRIVER must not be erased"
        );
        assert!(HALDEX_FLASH_INFO.should_erase(2));
        assert!(HALDEX_FLASH_INFO.should_erase(3));
        assert!(HALDEX_FLASH_INFO.should_erase(4));

        // Simos and DQ381 erase everything.
        for b in 1..=5 {
            assert!(S18_FLASH_INFO.should_erase(b));
        }
        for b in 1..=3 {
            assert!(DQ381_FLASH_INFO.should_erase(b));
        }
    }

    /// Haldex is flashed verbatim — compression would corrupt it, because the
    /// ECU is told `0x00` (no compression) in the dataFormatIdentifier.
    #[test]
    fn haldex_payload_is_byte_identical_to_input() {
        let raw: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let out = compress_and_encrypt(&raw, &HALDEX_FLASH_INFO);
        assert_eq!(out, raw);
    }

    /// DQ250's compressed output must not be rounded up to a 16-byte boundary.
    /// (Guards against a silent regression back to `Padding::AesBlock`.)
    #[test]
    fn dq250_compression_does_not_pad_to_block_size() {
        // A payload whose LZSS output is very unlikely to land on 0x10 naturally.
        let raw: Vec<u8> = (0..1000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let compressed = mqb_lzss::encode(&raw, mqb_lzss::Padding::None);
        let padded = mqb_lzss::encode(&raw, mqb_lzss::Padding::AesBlock);
        assert!(
            padded.len() >= compressed.len(),
            "AesBlock padding should never shrink the stream"
        );
        // The DQ250 policy must select the unpadded encoder.
        let out = compress_and_encrypt(&raw, &DQ250_FLASH_INFO);
        // DsgCrypto is a byte-wise substitution, so length is preserved.
        assert_eq!(out.len(), compressed.len());
    }

    /// DQ381 and Haldex carry a computed CRC-32, not the all-zero static default.
    #[test]
    fn crc32_modules_send_a_real_checksum() {
        let raw = vec![0xA5u8; 1024];
        let expected = crc32fast::hash(&raw).to_be_bytes();
        assert_ne!(expected, [0; 4]);

        assert_eq!(
            prepare_block(&DQ381_FLASH_INFO, 3, &raw).uds_checksum,
            expected
        );
        assert_eq!(
            prepare_block(&HALDEX_FLASH_INFO, 3, &raw).uds_checksum,
            expected
        );
        // Simos keeps its static table value.
        assert_eq!(prepare_block(&S18_FLASH_INFO, 5, &raw).uds_checksum, [0; 4]);
    }

    /// Haldex announces the length of the block it actually holds, not the
    /// static table default — the two differ on real firmware.
    #[test]
    fn haldex_announces_dynamic_length() {
        // Static table says CAL is 0x333E; a real image had 0x1826.
        assert_eq!(HALDEX_FLASH_INFO.block_length(2), Some(0x333E));
        let raw = vec![0u8; 0x1826];
        assert_eq!(
            prepare_block(&HALDEX_FLASH_INFO, 2, &raw).announced_length,
            0x1826
        );

        // A static-length module ignores the slice length and uses its table.
        let s18_raw = vec![0u8; 16];
        assert_eq!(
            prepare_block(&S18_FLASH_INFO, 5, &s18_raw).announced_length,
            0x7FC00
        );
    }
}
