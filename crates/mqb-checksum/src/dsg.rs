//! DSG JAMCRC — `0xFFFFFFFF - crc32(data[..-4])`, stored little-endian.

use mqb_bytes::{read_u32_le, write_u32_le};
use mqb_modules::ChecksumState;
use std::borrow::Cow;

/// Validate (and optionally fix) a DSG JAMCRC block checksum.
///
/// The checksum covers all bytes except the last 4, stored as LE u32 at the end.
pub fn validate_dsg(data: &[u8], fix: bool) -> (ChecksumState, Cow<'_, [u8]>) {
    if data.len() < 4 {
        return (ChecksumState::Failed, Cow::Borrowed(data));
    }

    let checksum_location = data.len() - 4;
    let stored = read_u32_le(data, checksum_location);

    // JAMCRC = NOT(CRC32(data))
    let crc = crc32fast::hash(&data[..checksum_location]);
    let calculated = 0xFFFF_FFFFu32 - crc;

    if calculated == stored {
        (ChecksumState::Valid, Cow::Borrowed(data))
    } else if fix {
        let mut fixed = data.to_vec();
        write_u32_le(&mut fixed, checksum_location, calculated);
        (ChecksumState::Fixed, Cow::Owned(fixed))
    } else {
        (ChecksumState::Invalid, Cow::Borrowed(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jamcrc_empty_body() {
        // 4-byte data: 0 bytes of content + 4 bytes checksum
        // CRC32 of [] = 0x00000000, JAMCRC = 0xFFFFFFFF
        let jamcrc_of_empty = 0xFFFF_FFFFu32 - crc32fast::hash(&[]);
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&jamcrc_of_empty.to_le_bytes());
        let (state, _) = validate_dsg(&data, false);
        assert_eq!(state, ChecksumState::Valid);
    }

    #[test]
    fn fix_mode() {
        let content = b"hello world";
        let crc = crc32fast::hash(content);
        let correct_checksum = 0xFFFF_FFFFu32 - crc;

        let mut data = content.to_vec();
        data.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]); // wrong checksum

        let (state, fixed) = validate_dsg(&data, true);
        assert_eq!(state, ChecksumState::Fixed);
        let stored = read_u32_le(&fixed, fixed.len() - 4);
        assert_eq!(stored, correct_checksum);
    }
}
