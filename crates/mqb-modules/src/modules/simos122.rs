//! Simos12.2 ECU flash configuration.

use super::{
    BLOCK_CHECKSUMS_SIMOS, BLOCK_IDENTIFIERS_SIMOS, BLOCK_NAME_TO_NUMBER_SIMOS,
    BLOCK_TRANSFER_SIZES_SIMOS, BOX_CODE_LOCATION_SIMOS, CHECKSUM_BLOCK_LOCATION_SIMOS,
    SOFTWARE_VERSION_LOCATION_SIMOS,
};
use crate::crypto::AesCrypto;
use crate::types::{
    BlockPrep, ChecksumKind, FlashInfo, UdsChecksumKind, ECU_CONTROL_MODULE_IDENTIFIER,
};

static S122_CRYPTO: AesCrypto = AesCrypto::new(
    [
        0x41, 0x32, 0x6D, 0x3F, 0x50, 0x61, 0x3D, 0x30, 0x6C, 0x4C, 0x36, 0x61, 0x6E, 0x34, 0x67,
        0x21,
    ],
    [
        0x70, 0x49, 0x34, 0x65, 0x72, 0x63, 0x45, 0x29, 0x64, 0x70, 0x55, 0x73, 0x33, 0x23, 0x53,
        0x79,
    ],
);

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x03, 0x81, 0x4A, 0x10, 0x68, 0x03, 0x93, 0x29, 0x07, 0x20, 0x09, 0x4A, 0x05, 0x87, 0x22,
    0x12, 0x19, 0x54, 0x82, 0x49, 0x93, 0x09, 0x01, 0x19, 0x53, 0x82, 0x4A, 0x05, 0x87, 0x30, 0x03,
    0x20, 0x09, 0x82, 0x4A, 0x01, 0x81, 0x49, 0x4C,
];

const BASE_ADDRESSES: &[(u8, u32)] = &[
    (0, 0x80000000),
    (1, 0x80020000),
    (2, 0x800C0000),
    (3, 0x80180000),
    (4, 0x80240000),
    (5, 0xA0040000),
    (6, 0x80080000),
];

const BLOCK_LENGTHS: &[(u8, usize)] = &[
    (1, 0x1FE00),
    (2, 0xBFC00),
    (3, 0xBFC00),
    (4, 0xBFC00),
    (5, 0x6FC00),
    (6, 0x1FE00),
];

const BLOCK_NAMES_FRF: &[(u8, &str)] = &[
    (1, "FD_0"),
    (2, "FD_1"),
    (3, "FD_2"),
    (4, "FD_3"),
    (5, "FD_4"),
];

const BINFILE_LAYOUT: &[(u8, usize)] = &[
    (0, 0x000000),
    (1, 0x020000),
    (2, 0x0C0000),
    (3, 0x180000),
    (4, 0x240000),
    (5, 0x040000),
];

pub static S122_FLASH_INFO: FlashInfo = FlashInfo {
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
    project_name: "SC2",
    crypto: &S122_CRYPTO,
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
