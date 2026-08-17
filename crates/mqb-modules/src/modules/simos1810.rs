//! Simos18.10 ECU flash configuration.

use crate::crypto::AesCrypto;
use crate::types::{
    BlockPrep, ChecksumKind, FlashInfo, PatchInfo, UdsChecksumKind, ECU_CONTROL_MODULE_IDENTIFIER,
};

const S1810_PATCH_BYTES: &[u8] = include_bytes!("../../../../data/patch_1810.bin");
use super::{
    BLOCK_CHECKSUMS_SIMOS, BLOCK_IDENTIFIERS_SIMOS, BLOCK_NAME_TO_NUMBER_SIMOS,
    BLOCK_TRANSFER_SIZES_SIMOS, BOX_CODE_LOCATION_SIMOS, CHECKSUM_BLOCK_LOCATION_SIMOS,
    SOFTWARE_VERSION_LOCATION_SIMOS,
};

static S1810_CRYPTO: AesCrypto = AesCrypto::new(
    [
        0xAE, 0x54, 0x05, 0x02, 0xE4, 0x8E, 0x38, 0x54, 0xDB, 0xCA, 0x1A, 0x15, 0x45, 0xBA, 0x6F,
        0x33,
    ],
    [
        0x62, 0xF3, 0x13, 0xFA, 0x5C, 0x08, 0x53, 0x27, 0x98, 0xBC, 0xA4, 0x52, 0x47, 0x1D, 0x20,
        0xD5,
    ],
);

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x03, 0x81, 0x4A, 0x10, 0x68, 0x02, 0x93, 0x05, 0x05, 0x20, 0x15, 0x4A, 0x05, 0x87, 0x22,
    0x12, 0x19, 0x54, 0x82, 0x49, 0x93, 0xF4, 0x23, 0xBF, 0x7D, 0x82, 0x4A, 0x05, 0x87, 0x5A, 0x63,
    0xFC, 0x5E, 0x82, 0x4A, 0x01, 0x81, 0x49, 0x4C,
];

const BASE_ADDRESSES: &[(u8, u32)] = &[
    (0, 0x80000000),
    (1, 0x80800000),
    (2, 0x80020000),
    (3, 0x80100000),
    (4, 0x808C0000),
    (5, 0xA0820000),
    (6, 0x80880000),
];

const BLOCK_LENGTHS: &[(u8, usize)] = &[
    (1, 0x1FE00),
    (2, 0xDFC00),
    (3, 0xFFC00),
    (4, 0x13FC00),
    (5, 0x9FC00),
    (6, 0x1FE00),
];

const BLOCK_NAMES_FRF: &[(u8, &str)] = &[
    (1, "FD_01DATA"),
    (2, "FD_02DATA"),
    (3, "FD_03DATA"),
    (4, "FD_04DATA"),
    (5, "FD_05DATA"),
];

const BINFILE_LAYOUT: &[(u8, usize)] = &[
    (0, 0x000000),
    (1, 0x200000),
    (2, 0x020000),
    (3, 0x100000),
    (4, 0x2C0000),
    (5, 0x220000),
];

fn s1810_transfer_size_patch(block_num: u8, address: usize) -> usize {
    assert_eq!(
        block_num, 2,
        "Only Block 2 (ASW1) patching is supported for Simos18.10"
    );
    if address < 0x5CB00 {
        return 0x100;
    }
    if address < 0x5CC00 {
        return 0x8;
    }
    if address < 0xB3000 {
        return 0x100;
    }
    if address < 0xB3100 {
        return 0x8;
    }
    if address < 0xDFB00 {
        return 0x100;
    }
    0x8
}

pub static S1810_FLASH_INFO: FlashInfo = FlashInfo {
    base_addresses: BASE_ADDRESSES,
    block_lengths: BLOCK_LENGTHS,
    sa2_script: SA2_SCRIPT,
    block_names_frf: BLOCK_NAMES_FRF,
    block_identifiers: BLOCK_IDENTIFIERS_SIMOS,
    block_checksums: BLOCK_CHECKSUMS_SIMOS,
    control_module_identifier: ECU_CONTROL_MODULE_IDENTIFIER,
    software_version_location: SOFTWARE_VERSION_LOCATION_SIMOS,
    box_code_location: BOX_CODE_LOCATION_SIMOS,
    block_transfer_sizes: BLOCK_TRANSFER_SIZES_SIMOS,
    binfile_layout: BINFILE_LAYOUT,
    binfile_size: 4_194_304,
    project_name: "SCG",
    crypto: &S1810_CRYPTO,
    block_name_to_number: BLOCK_NAME_TO_NUMBER_SIMOS,
    checksum_block_location: CHECKSUM_BLOCK_LOCATION_SIMOS,
    patch_info: Some(PatchInfo {
        patch_box_code: "5G0906259Q__0005",
        patch_block_index: 2,
        patch_bytes: S1810_PATCH_BYTES,
        block_transfer_size_fn: s1810_transfer_size_patch,
    }),
    checksum_kind: ChecksumKind::Simos,
    lzss10_odx: false,
    dynamic_block_length_offsets: &[],
    compression_type: 0x0A,
    encryption_type: 0x0A,
    block_prep: BlockPrep::LzssAesBlock,
    no_erase_max_block: 0,
    uds_checksum_kind: UdsChecksumKind::Static,
    default_stmin_us: 400,
    no_internal_checksum_blocks: &[],
};
