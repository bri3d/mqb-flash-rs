//! Haldex 16-bit checksum — NOT of u16 LE word sum.
//!
//! Block 1 (DRIVER) is always skipped.
//! Checksum stored as u16 LE at `checksum_block_location[block_num] + 0x08`.
//! The checksum covers all data except the 2-byte checksum and 8 preceding header bytes.

use std::borrow::Cow;
use mqb_modules::{ChecksumState, FlashInfo};

/// Validate (and optionally fix) a Haldex block 16-bit checksum.
pub fn validate_haldex<'a>(
    data: &'a [u8],
    block_num: u8,
    flash_info: &FlashInfo,
    fix: bool,
) -> (ChecksumState, Cow<'a, [u8]>) {
    // Block 1 (DRIVER) is always skipped — treat as valid rather than making a spurious clone
    if block_num == 1 {
        return (ChecksumState::Valid, Cow::Borrowed(data));
    }

    let Some(checksum_location) = flash_info.checksum_block_location(block_num) else {
        return (ChecksumState::Failed, Cow::Borrowed(data));
    };

    // Read current checksum at +0x8
    let stored_offset = checksum_location + 0x08;
    let stored = u16::from_le_bytes([data[stored_offset], data[stored_offset + 1]]);

    // Sum all u16 LE words, excluding the checksum block region [checksum_location .. checksum_location + 0xA]
    let mut sum: u16 = 0;
    for chunk in data[..checksum_location].chunks(2).chain(data[checksum_location + 0xA..].chunks(2)) {
        if chunk.len() == 2 {
            let word = u16::from_le_bytes([chunk[0], chunk[1]]);
            sum = sum.wrapping_add(word);
        }
    }
    // NOT the result
    let calculated = 0xFFFFu16 - sum;

    if calculated == stored {
        (ChecksumState::Valid, Cow::Borrowed(data))
    } else if fix {
        let mut fixed = data.to_vec();
        let bytes = calculated.to_le_bytes();
        fixed[stored_offset] = bytes[0];
        fixed[stored_offset + 1] = bytes[1];
        (ChecksumState::Fixed, Cow::Owned(fixed))
    } else {
        (ChecksumState::Invalid, Cow::Borrowed(data))
    }
}
