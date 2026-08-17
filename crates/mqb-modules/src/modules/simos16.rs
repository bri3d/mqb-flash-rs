//! Simos16.11 ECU flash configuration.
//! Uses the same block_lengths as Simos18.1.

use super::{
    BLOCK_CHECKSUMS_SIMOS, BLOCK_IDENTIFIERS_SIMOS, BLOCK_NAME_TO_NUMBER_SIMOS,
    BLOCK_TRANSFER_SIZES_SIMOS, BOX_CODE_LOCATION_SIMOS, CHECKSUM_BLOCK_LOCATION_SIMOS,
    SOFTWARE_VERSION_LOCATION_SIMOS,
};
use crate::crypto::AesCrypto;
use crate::types::{
    BlockPrep, ChecksumKind, FlashInfo, UdsChecksumKind, ECU_CONTROL_MODULE_IDENTIFIER,
};

static S16_CRYPTO: AesCrypto = AesCrypto::new(
    [
        0x0A, 0xCF, 0xFB, 0x51, 0x3E, 0x95, 0x64, 0x4A, 0x39, 0x6A, 0x41, 0x32, 0x52, 0x35, 0xD9,
        0xA9,
    ],
    [
        0x01, 0xD1, 0x37, 0x42, 0x6B, 0x6B, 0x53, 0x6F, 0xB3, 0x33, 0x3F, 0x69, 0x1B, 0x36, 0x6D,
        0x34,
    ],
);

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x03, 0x93, 0x71, 0x2E, 0xAB, 0x7C, 0x4A, 0x05, 0x93, 0x14, 0x06, 0x20, 0x12, 0x49, 0x68,
    0x03, 0x87, 0x01, 0x12, 0x20, 0x12, 0x82, 0x82, 0x4A, 0x05, 0x84, 0xFD, 0x07, 0x3A, 0x5D, 0x49,
    0x4C,
];

const BASE_ADDRESSES: &[(u8, u32)] = &[
    (0, 0x80000000),
    (1, 0x80020000),
    (2, 0x80040000),
    (3, 0x80140000),
    (4, 0x80880000),
    (5, 0xA0800000),
    (6, 0x80840000),
];

// Same block lengths as Simos18
const BLOCK_LENGTHS: &[(u8, usize)] = &[
    (1, 0x23E00),
    (2, 0xFFC00),
    (3, 0xBFC00),
    (4, 0x7FC00),
    (5, 0x7FC00),
    (6, 0x23E00),
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
    (1, 0x020000),
    (2, 0x040000),
    (3, 0x140000),
    (4, 0x280000),
    (5, 0x200000),
];

pub static S16_FLASH_INFO: FlashInfo = FlashInfo {
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
    project_name: "SG1",
    crypto: &S16_CRYPTO,
    block_name_to_number: BLOCK_NAME_TO_NUMBER_SIMOS,
    checksum_block_location: CHECKSUM_BLOCK_LOCATION_SIMOS,
    patch_info: None,
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
