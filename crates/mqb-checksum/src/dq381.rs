//! DQ381 checksum — standard zlib CRC32 (reflected), stored big-endian.
//!
//! Start/end addresses at block offsets 0x38/0x3C (big-endian u32).
//! Checksum stored at offset 0x44 (big-endian u32).
//! Addresses are subtracted from the block's base address to get file offsets.

use std::borrow::Cow;
use mqb_modules::ChecksumState;

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

    let stored = u32::from_be_bytes([
        data[checksum_location],
        data[checksum_location + 1],
        data[checksum_location + 2],
        data[checksum_location + 3],
    ]);

    let abs_start = u32::from_be_bytes([
        data[start_location],
        data[start_location + 1],
        data[start_location + 2],
        data[start_location + 3],
    ]);
    let abs_end = u32::from_be_bytes([
        data[end_location],
        data[end_location + 1],
        data[end_location + 2],
        data[end_location + 3],
    ]);

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
        let bytes = calculated.to_be_bytes();
        fixed[checksum_location..checksum_location + 4].copy_from_slice(&bytes);
        (ChecksumState::Fixed, Cow::Owned(fixed))
    } else {
        (ChecksumState::Invalid, Cow::Borrowed(data))
    }
}
