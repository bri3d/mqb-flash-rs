//! Integration tests: validates the binaries produced by FRF extraction have
//! correct Simos and ECM3 checksums; also tests that cboot-patched binaries
//! retain valid checksums after a checksum fix.
//!
//! The FRF files are manufacturer firmware and are not redistributable, so
//! they are not in this repository; they are read from `../../../frf/`. Each
//! case skips when its file is absent, so a clean checkout (CI included)
//! still passes.

use std::collections::HashMap;
use std::path::Path;

use mqb_checksum::{locate_ecm3_with_asw1, validate_ecm3, validate_haldex, validate_simos_block};
use mqb_modules::modules::haldex4motion::HALDEX_FLASH_INFO;
use mqb_modules::modules::simos18::S18_FLASH_INFO;
use mqb_modules::modules::simos1810::S1810_FLASH_INFO;
use mqb_modules::{BlockData, ChecksumKind, ChecksumState, FlashInfo};

// CARGO_MANIFEST_DIR = .../vw-flash-rs/crates/mqb-binfile  →  ../../../ = VW_Flash_Rewrite/
const FRF_S1810: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_5G0906259Q__0005.frf"
);
const FRF_S18_H1: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_8V0906259H__0001.frf"
);
const FRF_S18_H2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_8V0906259H__0002.frf"
);
const FRF_S18_A3: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_8V0906259A__0003.frf"
);
const FRF_S18_A4: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_8V0906259A__0004.frf"
);
const FRF_S18_E2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_8V0906259E__0002.frf"
);
const FRF_S18_J3: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_8V0906259J__0003.frf"
);
const FRF_S18_K3: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_8V0906259K__0003.frf"
);
const FRF_S18_06K: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_06K906071B__9066.frf"
);

const FRF_HALDEX_C: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_0CQ907554C__7755.frf"
);
const FRF_HALDEX_E: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frf/FL_0CQ907554E__8040.frf"
);

// Keep the old alias so the cboot-patch tests below still compile.
const FRF_S18: &str = FRF_S18_H1;

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Return `path` only if the firmware file is actually there, logging a skip
/// notice when it is not. Manufacturer firmware cannot ship with the repo, so
/// an absent file is an expected condition, not a failure.
fn firmware(path: &'static str) -> Option<&'static str> {
    if Path::new(path).exists() {
        Some(path)
    } else {
        eprintln!("SKIPPED: firmware not present at {path}");
        None
    }
}

fn extract_frf_to_bin(frf_path: &str, flash_info: &'static FlashInfo) -> Vec<u8> {
    let raw = mqb_binfile::load_raw_blocks(Path::new(frf_path), flash_info)
        .unwrap_or_else(|e| panic!("Could not load blocks from {frf_path}: {e}"));

    let blocks: HashMap<String, BlockData> = raw
        .into_iter()
        .map(|(num, bytes)| {
            let name = flash_info
                .block_number_to_name(num)
                .unwrap_or("UNKNOWN")
                .to_owned();
            (name.clone(), BlockData::with_name(num, bytes, &name))
        })
        .collect();

    mqb_binfile::bin_from_blocks(&blocks, flash_info)
}

fn assert_all_checksums_valid(bin: &[u8], flash_info: &'static FlashInfo) {
    let split = mqb_binfile::blocks_from_bytes(bin, flash_info);
    assert!(
        !split.is_empty(),
        "binary should contain at least one recognisable block"
    );
    for (name, block) in &split {
        let (state, _) =
            validate_simos_block(flash_info, &block.block_bytes, block.block_number, false);
        assert_eq!(
            state,
            ChecksumState::Valid,
            "block '{name}' should have valid Simos checksum(s)"
        );
    }
}

/// Extract all blocks from an FRF, check every Simos block checksum, and check ECM3.
fn assert_all_valid(frf_path: &str, flash_info: &'static FlashInfo) {
    let bin = extract_frf_to_bin(frf_path, flash_info);
    let by_name = mqb_binfile::blocks_from_bytes(&bin, flash_info);
    assert!(!by_name.is_empty(), "{frf_path}: no blocks extracted");

    for (name, block) in &by_name {
        let (state, _) =
            validate_simos_block(flash_info, &block.block_bytes, block.block_number, false);
        assert_eq!(
            state,
            ChecksumState::Valid,
            "{frf_path}: block '{name}' has invalid Simos checksum(s)"
        );
    }

    let by_num: HashMap<u8, &BlockData> = by_name.values().map(|b| (b.block_number, b)).collect();
    let addresses = locate_ecm3_with_asw1(flash_info, &by_num, false)
        .unwrap_or_else(|| panic!("{frf_path}: could not locate ECM3 address table"));
    let cal_num = flash_info
        .block_to_number("CAL")
        .unwrap_or_else(|| panic!("{frf_path}: module has no CAL block"));
    let (state, _) = validate_ecm3(&addresses, &by_num[&cal_num].block_bytes, false);
    assert_eq!(
        state,
        ChecksumState::Valid,
        "{frf_path}: ECM3 checksum is invalid"
    );
}

/// Extract all blocks from a Haldex FRF and check every block checksum.
fn assert_haldex_valid(frf_path: &str, flash_info: &'static FlashInfo) {
    assert_eq!(flash_info.checksum_kind, ChecksumKind::Haldex);
    let bin = extract_frf_to_bin(frf_path, flash_info);
    let by_name = mqb_binfile::blocks_from_bytes(&bin, flash_info);
    assert!(!by_name.is_empty(), "{frf_path}: no blocks extracted");

    for (name, block) in &by_name {
        let (state, _) = validate_haldex(&block.block_bytes, block.block_number, flash_info, false);
        assert_eq!(
            state,
            ChecksumState::Valid,
            "{frf_path}: block '{name}' has invalid Haldex checksum"
        );
    }
}

fn apply_cboot_patch_and_fix(bin: &mut [u8], flash_info: &'static FlashInfo) {
    let block_num = flash_info
        .block_to_number("CBOOT")
        .expect("module has a CBOOT block");
    let offset = flash_info
        .binfile_offset(block_num)
        .expect("CBOOT has a binfile offset");
    let length = flash_info
        .block_length(block_num)
        .expect("CBOOT has a block length");
    let end = offset + length;

    let patched = mqb_cboot::patch_cboot(&bin[offset..end])
        .expect("CBOOT patch should find exactly 2 needle matches");
    bin[offset..end].copy_from_slice(&patched);

    // Fix both primary and secondary (CBOOT_TEMP) checksums
    let (state, fixed) = validate_simos_block(flash_info, &bin[offset..end], block_num, true);
    assert_ne!(
        state,
        ChecksumState::Valid,
        "checksum should be invalid after patching"
    );
    let fixed = fixed.into_owned();
    bin[offset..end].copy_from_slice(&fixed);
}

// ── All FRF files: Simos block checksums + ECM3 ───────────────────────────────

#[test]
fn all_frf_files_checksums_valid() {
    let cases: &[(&'static str, &'static FlashInfo)] = &[
        (FRF_S1810, &S1810_FLASH_INFO),
        (FRF_S18_H1, &S18_FLASH_INFO),
        (FRF_S18_H2, &S18_FLASH_INFO),
        (FRF_S18_A3, &S18_FLASH_INFO),
        (FRF_S18_A4, &S18_FLASH_INFO),
        (FRF_S18_E2, &S18_FLASH_INFO),
        (FRF_S18_J3, &S18_FLASH_INFO),
        (FRF_S18_K3, &S18_FLASH_INFO),
        (FRF_S18_06K, &S18_FLASH_INFO),
    ];

    // Checked per file rather than all-or-nothing: a working tree that holds
    // some of the firmware still gets those files validated.
    let mut checked = 0;
    for &(path, info) in cases {
        if let Some(path) = firmware(path) {
            assert_all_valid(path, info);
            checked += 1;
        }
    }

    // Haldex FRFs (different checksum algorithm)
    for path in [FRF_HALDEX_C, FRF_HALDEX_E] {
        if let Some(path) = firmware(path) {
            assert_haldex_valid(path, &HALDEX_FLASH_INFO);
            checked += 1;
        }
    }

    if checked == 0 {
        eprintln!("SKIPPED: no firmware present, nothing was checked");
    }
}

// ── CBOOT patch: verify checksums survive patch + fix ─────────────────────────

#[test]
fn s1810_patched_cboot_bin_has_valid_checksums_after_fix() {
    let Some(path) = firmware(FRF_S1810) else {
        return;
    };
    let mut bin = extract_frf_to_bin(path, &S1810_FLASH_INFO);
    apply_cboot_patch_and_fix(&mut bin, &S1810_FLASH_INFO);
    assert_all_checksums_valid(&bin, &S1810_FLASH_INFO);
}

#[test]
fn s18_patched_cboot_bin_has_valid_checksums_after_fix() {
    let Some(path) = firmware(FRF_S18) else {
        return;
    };
    let mut bin = extract_frf_to_bin(path, &S18_FLASH_INFO);
    apply_cboot_patch_and_fix(&mut bin, &S18_FLASH_INFO);
    assert_all_checksums_valid(&bin, &S18_FLASH_INFO);
}
