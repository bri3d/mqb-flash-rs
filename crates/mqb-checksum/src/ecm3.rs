//! ECM3 monitor checksum — 64-bit pure sum of u32 LE words in CAL regions.
//!
//! The ECM3 process continuously checksums sections of CAL flash.
//! In newer ECUs, the area addresses are in ASW1; in older ECUs they're in CAL itself.

use std::collections::HashMap;
use mqb_modules::{BlockData, ChecksumState, FlashInfo};

/// CSV database of known CAL versions → ECM3 address ranges.
static BOX_CODES_CSV: &str = include_str!("../../../data/box_codes.csv");

/// ECM3 checksum header location in CAL (offset into CAL block).
const ECM3_CAL_MONITOR_CHECKSUM: usize = 0x400;
/// ECM3 address table location in ASW1 for standard ECUs.
const ECM3_CAL_MONITOR_ADDRESSES: usize = 0x520;
/// ECM3 address table location in ASW1 for early ECUs.
const ECM3_CAL_MONITOR_ADDRESSES_EARLY: usize = 0x540;
/// Cached address offset adjustment.
const ECM3_CAL_MONITOR_OFFSET_CACHED: i64 = 0x2000_0000;

/// Load ECM3 address range from the embedded box_codes.csv for a given CAL version string.
fn load_ecm3_from_csv(cal_version: &str) -> Option<(usize, usize)> {
    for line in BOX_CODES_CSV.lines().skip(1) {
        let mut fields = line.split(',');
        let version = fields.next()?.trim();
        let start_str = fields.next()?.trim();
        let end_str = fields.next()?.trim();
        if version == cal_version {
            let start = usize::from_str_radix(start_str.trim_start_matches("0x"), 16).ok()?;
            let end = usize::from_str_radix(end_str.trim_start_matches("0x"), 16).ok()?;
            return Some((start, end));
        }
    }
    None
}

/// Derive ECM3 address list from the CAL block's software version field + CSV lookup.
pub fn load_ecm3_location(cal_data: &[u8], flash_info: &FlashInfo) -> Option<Vec<usize>> {
    let cal_block_num = flash_info.block_to_number("CAL")?;
    let (v_start, v_end) = flash_info.software_version_location(cal_block_num)?;
    let version = std::str::from_utf8(&cal_data[v_start..v_end]).ok()?.trim_end_matches('\0');
    let (start, end) = load_ecm3_from_csv(version)?;
    let base = flash_info.base_address(cal_block_num)? as usize;
    Some(vec![start - base, end - base])
}

/// Locate ECM3 address list using ASW1 data (and falling back to early mode).
pub fn locate_ecm3_with_asw1(
    flash_info: &FlashInfo,
    blocks: &HashMap<u8, &BlockData>,
    is_early: bool,
) -> Option<Vec<usize>> {
    let asw1_num = flash_info.block_to_number("ASW1")?;
    let cal_num = flash_info.block_to_number("CAL")?;
    let asw1_data = &blocks.get(&asw1_num)?.block_bytes;
    let cal_data = &blocks.get(&cal_num)?.block_bytes;
    let base_address = flash_info.base_address(cal_num)? as i64;

    let checksum_loc = ECM3_CAL_MONITOR_CHECKSUM;

    if cal_data.len() < checksum_loc + 28 {
        return None;
    }

    let area_count = u32::from_le_bytes(
        cal_data[checksum_loc + 16..checksum_loc + 20].try_into().unwrap()
    ) as usize;

    // Check if addresses are embedded in CAL
    let cal_address = u32::from_le_bytes(
        cal_data[checksum_loc + 24..checksum_loc + 28].try_into().unwrap()
    );

    let (addr_data, addr_start) = if cal_address > 0 {
        (cal_data.as_slice(), checksum_loc + 24)
    } else {
        let offset = if is_early {
            ECM3_CAL_MONITOR_ADDRESSES_EARLY
        } else {
            ECM3_CAL_MONITOR_ADDRESSES
        };
        (asw1_data.as_slice(), offset)
    };

    let mut addresses = Vec::new();
    for i in 0..area_count * 2 {
        let off = addr_start + i * 4;
        if off + 4 > addr_data.len() {
            return None;
        }
        let abs_addr = u32::from_le_bytes(
            addr_data[off..off + 4].try_into().unwrap()
        ) as i64;

        let offset = abs_addr - base_address;
        let file_offset = if offset < 0 {
            (abs_addr + ECM3_CAL_MONITOR_OFFSET_CACHED - base_address) as usize
        } else {
            offset as usize
        };
        addresses.push(file_offset);
    }

    // If the first address is invalid (underflow → very large), retry with is_early=true
    if !is_early && addresses.first().copied().unwrap_or(usize::MAX) > cal_data.len() {
        return locate_ecm3_with_asw1(flash_info, blocks, true);
    }

    Some(addresses)
}

/// Validate (and optionally fix) the ECM3 64-bit monitor checksum in CAL.
///
/// The `addresses` slice alternates start/end file offsets (pairs).
pub fn validate_ecm3(
    addresses: &[usize],
    cal_data: &[u8],
    fix: bool,
) -> (ChecksumState, Vec<u8>) {
    let checksum_loc = ECM3_CAL_MONITOR_CHECKSUM;

    // Need at least checksum_loc + 60 bytes (alt checksum flag at +56, stored at +56..+64)
    if cal_data.len() < checksum_loc + 64 {
        return (ChecksumState::Failed, cal_data.to_vec());
    }

    // Read initial value (the starting seed for the summation)
    let init_hi = u32::from_le_bytes(cal_data[checksum_loc + 8..checksum_loc + 12].try_into().unwrap()) as u64;
    let init_lo = u32::from_le_bytes(cal_data[checksum_loc + 12..checksum_loc + 16].try_into().unwrap()) as u64;
    let mut checksum: u64 = (init_hi << 32) | init_lo;

    for pair in addresses.chunks(2) {
        let (start, end) = (pair[0], pair[1]);
        for chunk in cal_data[start..end].chunks_exact(4) {
            let word = u32::from_le_bytes(chunk.try_into().unwrap()) as u64;
            checksum = checksum.wrapping_add(word);
        }
    }

    // Oldschool ECM3: alternate checksum storage location
    let actual_checksum_loc = if cal_data[checksum_loc + 56] > 0 {
        checksum_loc + 56
    } else {
        checksum_loc
    };

    let stored_hi = u32::from_le_bytes(cal_data[actual_checksum_loc..actual_checksum_loc + 4].try_into().unwrap()) as u64;
    let stored_lo = u32::from_le_bytes(cal_data[actual_checksum_loc + 4..actual_checksum_loc + 8].try_into().unwrap()) as u64;
    let stored: u64 = (stored_hi << 32) | stored_lo;

    if checksum == stored {
        (ChecksumState::Valid, cal_data.to_vec())
    } else if fix {
        let mut fixed = cal_data.to_vec();
        let hi = ((checksum >> 32) as u32).to_le_bytes();
        let lo = (checksum as u32).to_le_bytes();
        fixed[actual_checksum_loc..actual_checksum_loc + 4].copy_from_slice(&hi);
        fixed[actual_checksum_loc + 4..actual_checksum_loc + 8].copy_from_slice(&lo);
        (ChecksumState::Fixed, fixed)
    } else {
        (ChecksumState::Invalid, cal_data.to_vec())
    }
}
