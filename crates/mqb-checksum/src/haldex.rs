//! Haldex 16-bit checksum — NOT of u16 LE word sum.
//!
//! Block 1 (DRIVER) is always skipped.
//! Checksum stored as u16 LE at `checksum_block_location[block_num] + 0x08`.
//! The checksum covers all data except the 2-byte checksum and 8 preceding header bytes.

use mqb_bytes::{read_u16_le, write_u16_le};
use mqb_modules::{ChecksumState, FlashInfo};
use std::borrow::Cow;

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
    if checksum_location + 0x0A > data.len() {
        return (ChecksumState::Failed, Cow::Borrowed(data));
    }
    let stored = read_u16_le(data, stored_offset);

    // Sum all u16 LE words, excluding the checksum block region [checksum_location .. checksum_location + 0xA]
    let mut sum: u16 = 0;
    for chunk in data[..checksum_location]
        .as_chunks::<2>()
        .0
        .iter()
        .chain(data[checksum_location + 0xA..].as_chunks::<2>().0)
    {
        let word = read_u16_le(chunk, 0);
        sum = sum.wrapping_add(word);
    }
    // NOT the result
    let calculated = 0xFFFFu16 - sum;

    if calculated == stored {
        (ChecksumState::Valid, Cow::Borrowed(data))
    } else if fix {
        let mut fixed = data.to_vec();
        write_u16_le(&mut fixed, stored_offset, calculated);
        (ChecksumState::Fixed, Cow::Owned(fixed))
    } else {
        (ChecksumState::Invalid, Cow::Borrowed(data))
    }
}
