//! DQ381 checksum — standard zlib CRC32 (reflected), stored big-endian.
//!
//! Start/end addresses at block offsets 0x38/0x3C (big-endian u32).
//! Checksum stored at offset 0x44 (big-endian u32).
//! Addresses are subtracted from the block's base address to get file offsets.

use mqb_bytes::{read_u32_be, write_u32_be};
use mqb_modules::ChecksumState;
use std::borrow::Cow;

/// Validate (and optionally fix) a DQ381 block CRC32 checksum.
///
/// `base_address` is the absolute base address of the block in ECU memory
/// (from `dq381::BLOCK_BASE_ADDRESSES`).
pub fn validate_dq381<'a>(
    data: &'a [u8],
    base_address: u32,
    fix: bool,
) -> (ChecksumState, Cow<'a, [u8]>) {
    let checksum_location = 0x44usize;
    let start_location = 0x38usize;
    let end_location = 0x3Cusize;

    if data.len() < checksum_location + 4 {
        return (ChecksumState::Failed, Cow::Borrowed(data));
    }

    let stored = read_u32_be(data, checksum_location);
    let abs_start = read_u32_be(data, start_location);
    let abs_end = read_u32_be(data, end_location);

    if abs_start < base_address || abs_end < base_address || abs_end < abs_start {
        return (ChecksumState::Failed, Cow::Borrowed(data));
    }
    let start = (abs_start - base_address) as usize;
    let end = (abs_end - base_address) as usize;

    if end >= data.len() {
        return (ChecksumState::Failed, Cow::Borrowed(data));
    }

    // Standard zlib CRC32 (reflected, 0xFFFFFFFF init/final XOR)
    let calculated = crc32fast::hash(&data[start..=end]);

    if calculated == stored {
        (ChecksumState::Valid, Cow::Borrowed(data))
    } else if fix {
        let mut fixed = data.to_vec();
        write_u32_be(&mut fixed, checksum_location, calculated);
        (ChecksumState::Fixed, Cow::Owned(fixed))
    } else {
        (ChecksumState::Invalid, Cow::Borrowed(data))
    }
}
