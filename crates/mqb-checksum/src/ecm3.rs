//! ECM3 monitor checksum — 64-bit pure sum of u32 LE words in CAL regions.
//!
//! The ECM3 process continuously checksums sections of CAL flash.
//! In newer ECUs, the area addresses are in ASW1; in older ECUs they're in CAL itself.

use mqb_bytes::{read_u32_le, write_u32_le};
use mqb_modules::{BlockData, ChecksumState, FlashInfo};
use std::collections::HashMap;

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

/// Column indices in `data/box_codes.csv`. The header is:
/// `box_code,box_version,engine_name,cboot_version,asw_version,cal_version,
///  ecm3_address_start,ecm3_address_end,allowed_boxcodes`
const CSV_COL_CAL_VERSION: usize = 5;
const CSV_COL_ECM3_START: usize = 6;
const CSV_COL_ECM3_END: usize = 7;
/// Number of comma-separated fields before the trailing quoted `allowed_boxcodes`
/// list. That last column embeds commas inside quotes, so the line is split into
/// at most this many + 1 pieces and the remainder is left untouched.
const CSV_FIELDS_BEFORE_QUOTED: usize = 8;

/// Load the ECM3 address range from the embedded `box_codes.csv` for a CAL version string.
///
/// The two address columns are **decimal** (the file contains no `0x` prefixes) and are
/// already CAL-block-relative file offsets for the Simos18 family, so they are returned
/// verbatim — matching the Python reference, which returns the raw strings and applies
/// `int(..)` base 10 in `validate_ecm3` without any base-address adjustment.
///
/// Some rows (Simos10, and a handful of malformed entries with negative numbers) carry
/// values that are not CAL-relative. Those cannot be used as slice indices, so a
/// non-parsing or negative value yields `None` rather than a panic; Python would silently
/// compute a garbage checksum from them.
fn load_ecm3_from_csv(cal_version: &str) -> Option<(usize, usize)> {
    for line in BOX_CODES_CSV.lines().skip(1) {
        let fields: Vec<&str> = line.splitn(CSV_FIELDS_BEFORE_QUOTED + 1, ',').collect();
        if fields.len() <= CSV_COL_ECM3_END {
            continue;
        }
        if fields[CSV_COL_CAL_VERSION].trim() != cal_version {
            continue;
        }
        let start = fields[CSV_COL_ECM3_START].trim().parse::<usize>().ok()?;
        let end = fields[CSV_COL_ECM3_END].trim().parse::<usize>().ok()?;
        return Some((start, end));
    }
    None
}

/// Derive the ECM3 address list from the CAL block's software version field + CSV lookup.
///
/// Used when no ASW1 block is available to read the address table from — see
/// `locate_ecm3_with_asw1`. The returned offsets index directly into the CAL block.
pub fn load_ecm3_location(cal_data: &[u8], flash_info: &FlashInfo) -> Option<Vec<usize>> {
    let cal_block_num = flash_info.block_to_number("CAL")?;
    let (v_start, v_end) = flash_info.software_version_location(cal_block_num)?;
    let version_bytes = cal_data.get(v_start..v_end)?;
    let version = std::str::from_utf8(version_bytes)
        .ok()?
        .trim_end_matches('\0');
    let (start, end) = load_ecm3_from_csv(version)?;
    Some(vec![start, end])
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

    let area_count = read_u32_le(cal_data, checksum_loc + 16) as usize;

    // Check if addresses are embedded in CAL
    let cal_address = read_u32_le(cal_data, checksum_loc + 24);

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
        let abs_addr = read_u32_le(addr_data, off) as i64;

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
pub fn validate_ecm3(addresses: &[usize], cal_data: &[u8], fix: bool) -> (ChecksumState, Vec<u8>) {
    let checksum_loc = ECM3_CAL_MONITOR_CHECKSUM;

    // Need at least checksum_loc + 60 bytes (alt checksum flag at +56, stored at +56..+64)
    if cal_data.len() < checksum_loc + 64 {
        return (ChecksumState::Failed, cal_data.to_vec());
    }

    // Read initial value (the starting seed for the summation)
    let init_hi = read_u32_le(cal_data, checksum_loc + 8) as u64;
    let init_lo = read_u32_le(cal_data, checksum_loc + 12) as u64;
    let mut checksum: u64 = (init_hi << 32) | init_lo;

    for &[start, end] in addresses.as_chunks::<2>().0 {
        if end > cal_data.len() {
            return (ChecksumState::Failed, cal_data.to_vec());
        }
        for chunk in cal_data[start..end].as_chunks::<4>().0 {
            let word = read_u32_le(chunk, 0) as u64;
            checksum = checksum.wrapping_add(word);
        }
    }

    // Oldschool ECM3: alternate checksum storage location
    let actual_checksum_loc = if cal_data[checksum_loc + 56] > 0 {
        checksum_loc + 56
    } else {
        checksum_loc
    };

    let stored_hi = read_u32_le(cal_data, actual_checksum_loc) as u64;
    let stored_lo = read_u32_le(cal_data, actual_checksum_loc + 4) as u64;
    let stored: u64 = (stored_hi << 32) | stored_lo;

    if checksum == stored {
        (ChecksumState::Valid, cal_data.to_vec())
    } else if fix {
        let mut fixed = cal_data.to_vec();
        write_u32_le(&mut fixed, actual_checksum_loc, (checksum >> 32) as u32);
        write_u32_le(&mut fixed, actual_checksum_loc + 4, checksum as u32);
        (ChecksumState::Fixed, fixed)
    } else {
        (ChecksumState::Invalid, cal_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mqb_modules::modules::simos18::S18_FLASH_INFO;

    /// Build a minimal CAL block carrying `version` at the Simos CAL software-version
    /// offset (block 5 → 0x23..0x2B).
    fn cal_with_version(version: &[u8; 8]) -> Vec<u8> {
        let mut cal = vec![0u8; 0x40];
        cal[0x23..0x2B].copy_from_slice(version);
        cal
    }

    #[test]
    fn csv_lookup_finds_8v0906259h_row() {
        // 8V0906259H,0001,2.0l R4 TFSI,SC8E0L20,SC8E0O20,SC800O20,55112,65400,"[...]"
        assert_eq!(load_ecm3_from_csv("SC800O20"), Some((55112, 65400)));
    }

    #[test]
    fn load_ecm3_location_reads_version_from_cal_and_returns_csv_pair() {
        let cal = cal_with_version(b"SC800O20");
        assert_eq!(
            load_ecm3_location(&cal, &S18_FLASH_INFO),
            Some(vec![55112, 65400])
        );
    }

    #[test]
    fn unknown_cal_version_returns_none() {
        let cal = cal_with_version(b"ZZ999Z99");
        assert_eq!(load_ecm3_from_csv("ZZ999Z99"), None);
        assert_eq!(load_ecm3_location(&cal, &S18_FLASH_INFO), None);
    }

    #[test]
    fn addresses_are_decimal_not_hex() {
        // 55112 read as hex would be 0x55112 = 348434, well past the 0x10000 CAL block.
        let (start, end) = load_ecm3_from_csv("SC800O20").unwrap();
        assert!(start < 0x1_0000 && end < 0x1_0000);
    }

    #[test]
    fn trailing_quoted_column_does_not_shift_fields() {
        // The allowed_boxcodes column contains commas inside quotes; a naive split would
        // still work here (it is last) but this pins the parse of a full real row.
        let row = "8V0906259H,0001,2.0l R4 TFSI,SC8E0L20,SC8E0O20,SC800O20,55112,65400,\
                   \"['06K907425E', '8V0906259B']\"";
        let fields: Vec<&str> = row.splitn(CSV_FIELDS_BEFORE_QUOTED + 1, ',').collect();
        assert_eq!(fields.len(), CSV_FIELDS_BEFORE_QUOTED + 1);
        assert_eq!(fields[CSV_COL_CAL_VERSION], "SC800O20");
        assert_eq!(fields[CSV_COL_ECM3_START], "55112");
        assert_eq!(fields[CSV_COL_ECM3_END], "65400");
    }
}
