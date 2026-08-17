//! Correcting a firmware image's internal checksums before it is flashed.
//!
//! Every block carries checksums the ECU verifies after the transfer. A block
//! that has been modified — a tune, or the CBOOT sample-mode patch — has stale
//! checksums and will be rejected, or worse, accepted into a state the ECU
//! cannot boot from. This module is the single place that fixes them, so the
//! CLI and the GUI cannot drift apart on the order of operations.
//!
//! The order matters and mirrors the Python reference
//! (`simos_flash_utils.py::checksum_and_patch_blocks`):
//!
//! 1. ECM3 monitor checksum over CAL (Simos only) — needs ASW1 if present.
//! 2. CBOOT sample-mode patch, if requested.
//! 3. Per-block checksum fix for every flashable block.
//!
//! Compression and encryption happen strictly **after** all of this: for the
//! modules whose UDS `0x0202` checksum is a CRC-32 of the plain block, that CRC
//! must be taken over the corrected bytes, so fixing a checksum afterwards
//! would make the two disagree.

use std::collections::HashMap;

use mqb_checksum::{validate_dq381, validate_dsg, validate_haldex, validate_simos_block};
use mqb_modules::{ChecksumKind, ChecksumState, FlashInfo};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FixupError {
    #[error("block {block}: checksum is invalid and could not be corrected")]
    Invalid { block: u8 },
    #[error("block {block}: the checksum algorithm failed")]
    Failed { block: u8 },
    #[error("CBOOT patch failed: {0}")]
    CbootPatch(String),
    #[error("this module has no CBOOT block, so --patch-cboot does not apply")]
    NoCbootBlock,
}

/// What [`checksum_and_patch_blocks`] did, for reporting to the user.
#[derive(Debug, Default, Clone)]
pub struct FixupReport {
    /// Human-readable lines, one per block acted on.
    pub notes: Vec<String>,
    /// Blocks whose bytes were modified.
    pub changed: Vec<u8>,
}

/// Fix internal checksums across a set of raw blocks, optionally applying the
/// CBOOT sample-mode patch first.
///
/// `blocks` is modified in place. Blocks the module marks as having no internal
/// checksum are left untouched — see [`FlashInfo::has_internal_checksum`].
pub fn checksum_and_patch_blocks(
    flash_info: &FlashInfo,
    blocks: &mut HashMap<u8, Vec<u8>>,
    patch_cboot: bool,
) -> Result<FixupReport, FixupError> {
    let mut report = FixupReport::default();

    // 1. ECM3 — the CAL block carries a second, monitor-level checksum that the
    //    per-block Simos CRC32 does not cover.
    if flash_info.checksum_kind == ChecksumKind::Simos {
        fix_ecm3(flash_info, blocks, &mut report);
    }

    // 2. CBOOT sample-mode patch. Must come before the per-block pass so the
    //    patched bytes are what gets checksummed.
    if patch_cboot {
        let cboot_num = flash_info
            .block_to_number("CBOOT")
            .ok_or(FixupError::NoCbootBlock)?;
        let raw = blocks.get(&cboot_num).ok_or(FixupError::NoCbootBlock)?;
        let patched =
            mqb_cboot::patch_cboot(raw).map_err(|e| FixupError::CbootPatch(e.to_string()))?;
        blocks.insert(cboot_num, patched);
        report.notes.push("CBOOT: sample-mode patch applied".into());
        report.changed.push(cboot_num);
    }

    // 3. Per-block internal checksums.
    let mut nums: Vec<u8> = blocks.keys().copied().collect();
    nums.sort_unstable();
    for num in nums {
        // Patch blocks (> 5) are raw payloads with no checksum region.
        if num > 5 {
            continue;
        }
        if !flash_info.has_internal_checksum(num) {
            report.notes.push(format!(
                "block {num}: skipped — this module supplies its checksum externally"
            ));
            continue;
        }
        let raw = match blocks.get(&num) {
            Some(r) => r.clone(),
            None => continue,
        };
        let (state, fixed) = validate_block(flash_info, &raw, num);
        match state {
            ChecksumState::Valid => {
                report
                    .notes
                    .push(format!("block {num}: checksum already valid"));
            }
            ChecksumState::Fixed => {
                blocks.insert(num, fixed);
                report
                    .notes
                    .push(format!("block {num}: checksum corrected"));
                report.changed.push(num);
            }
            ChecksumState::Invalid => return Err(FixupError::Invalid { block: num }),
            ChecksumState::Failed => return Err(FixupError::Failed { block: num }),
        }
    }

    Ok(report)
}

/// Dispatch a single block to its module's checksum algorithm.
pub fn validate_block(
    flash_info: &FlashInfo,
    raw: &[u8],
    block_num: u8,
) -> (ChecksumState, Vec<u8>) {
    match flash_info.checksum_kind {
        ChecksumKind::Simos => {
            let (s, f) = validate_simos_block(flash_info, raw, block_num, true);
            (s, f.into_owned())
        }
        ChecksumKind::Dq381 => {
            let base = mqb_modules::modules::dq381::BLOCK_BASE_ADDRESSES
                .iter()
                .find(|(n, _)| *n == block_num)
                .map(|(_, a)| *a)
                .unwrap_or(0);
            let (s, f) = validate_dq381(raw, base, true);
            (s, f.into_owned())
        }
        ChecksumKind::Dsg => {
            let (s, f) = validate_dsg(raw, true);
            (s, f.into_owned())
        }
        ChecksumKind::Haldex => {
            let (s, f) = validate_haldex(raw, block_num, flash_info, true);
            (s, f.into_owned())
        }
    }
}

/// Fix the ECM3 monitor checksum on the CAL block.
///
/// Best-effort: an image whose CAL version has no ECM3 row in `box_codes.csv`
/// simply has no ECM3 region to correct, which is not an error.
fn fix_ecm3(flash_info: &FlashInfo, blocks: &mut HashMap<u8, Vec<u8>>, report: &mut FixupReport) {
    let Some(cal_num) = flash_info.block_to_number("CAL") else {
        return;
    };
    let Some(cal) = blocks.get(&cal_num).cloned() else {
        return;
    };

    let addresses = mqb_checksum::load_ecm3_location(&cal, flash_info);
    let Some(addresses) = addresses else {
        report
            .notes
            .push("ECM3: no address range known for this calibration — skipped".into());
        return;
    };

    let (state, fixed) = mqb_checksum::validate_ecm3(&addresses, &cal, true);
    match state {
        ChecksumState::Fixed => {
            blocks.insert(cal_num, fixed);
            report
                .notes
                .push("CAL: ECM3 monitor checksum corrected".into());
            report.changed.push(cal_num);
        }
        ChecksumState::Valid => {
            report
                .notes
                .push("CAL: ECM3 monitor checksum already valid".into());
        }
        // ECM3 is a secondary monitor checksum; a failure here must not stop a
        // flash that is otherwise correct, but the user should be told.
        ChecksumState::Invalid | ChecksumState::Failed => {
            report
                .notes
                .push("CAL: ECM3 monitor checksum could not be corrected".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mqb_modules::modules::{
        dq250mqb::DQ250_FLASH_INFO, haldex4motion::HALDEX_FLASH_INFO, simos18::S18_FLASH_INFO,
    };

    /// DQ250's DRIVER block is only 0x80E bytes of real code. Running the DSG
    /// JAMCRC over it overwrites the last four bytes — a live brick path,
    /// because the documented workflow is `checksum` -> `split-bin` -> `flash`.
    #[test]
    fn dq250_driver_block_is_left_untouched() {
        assert!(!DQ250_FLASH_INFO.has_internal_checksum(2));

        let driver: Vec<u8> = (0..0x80Eu32).map(|i| (i % 251) as u8).collect();
        let mut blocks = HashMap::from([(2u8, driver.clone())]);
        let report = checksum_and_patch_blocks(&DQ250_FLASH_INFO, &mut blocks, false).unwrap();

        assert_eq!(blocks[&2], driver, "DRIVER bytes must be byte-identical");
        assert!(!report.changed.contains(&2));
        assert!(report.notes.iter().any(|n| n.contains("externally")));
    }

    /// Haldex's DRIVER block has no checksum region either.
    #[test]
    fn haldex_driver_block_is_left_untouched() {
        assert!(!HALDEX_FLASH_INFO.has_internal_checksum(1));
        assert!(HALDEX_FLASH_INFO.has_internal_checksum(2));

        let driver: Vec<u8> = vec![0x5Au8; 0x434];
        let mut blocks = HashMap::from([(1u8, driver.clone())]);
        checksum_and_patch_blocks(&HALDEX_FLASH_INFO, &mut blocks, false).unwrap();
        assert_eq!(blocks[&1], driver);
    }

    /// Every Simos block is checksummed; none is on the skip list.
    #[test]
    fn simos_checksums_every_block() {
        for b in 1..=5 {
            assert!(S18_FLASH_INFO.has_internal_checksum(b));
        }
    }

    /// Requesting the CBOOT patch on a module that has no CBOOT is an error,
    /// not a silent no-op — the old CLI accepted the flag and ignored it.
    #[test]
    fn patch_cboot_on_a_module_without_cboot_is_an_error() {
        let mut blocks = HashMap::from([(2u8, vec![0u8; 16])]);
        let err = checksum_and_patch_blocks(&DQ250_FLASH_INFO, &mut blocks, true);
        assert!(matches!(err, Err(FixupError::NoCbootBlock)));
    }

    /// Patch blocks (> 5) carry no checksum region and must be passed over.
    #[test]
    fn patch_blocks_are_skipped() {
        let patch = vec![0xABu8; 64];
        let mut blocks = HashMap::from([(9u8, patch.clone())]);
        let report = checksum_and_patch_blocks(&S18_FLASH_INFO, &mut blocks, false).unwrap();
        assert_eq!(blocks[&9], patch);
        assert!(report.changed.is_empty());
    }
}
