//! Simos10 ECU flash configuration.

use super::{BLOCK_CHECKSUMS_SIMOS, BLOCK_IDENTIFIERS_SIMOS, BLOCK_TRANSFER_SIZES_SIMOS};
use crate::crypto::SimosXorCrypto;
use crate::types::{
    BlockPrep, ChecksumKind, FlashInfo, UdsChecksumKind, ECU_CONTROL_MODULE_IDENTIFIER,
};

static S10_CRYPTO: SimosXorCrypto = SimosXorCrypto;

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x03, 0x82, 0x4A, 0x10, 0x68, 0x02, 0x84, 0x44, 0x39, 0x32, 0x24, 0x4A, 0x05, 0x87, 0x27,
    0x09, 0x20, 0x04, 0x81, 0x49, 0x93, 0x84, 0x25, 0x16, 0x48, 0x82, 0x4A, 0x05, 0x87, 0x12, 0x08,
    0x20, 0x01, 0x82, 0x4A, 0x01, 0x81, 0x49, 0x4C,
];

const BASE_ADDRESSES: &[(u8, u32)] = &[
    (1, 0x8000C000),
    (2, 0x80020000),
    (3, 0xA01C0000),
    (6, 0xA01C0000),
];

const BLOCK_LENGTHS: &[(u8, usize)] = &[(1, 0x13E00), (2, 0x19FA00), (3, 0x3C000)];

const BLOCK_NAMES_FRF: &[(u8, &str)] = &[(1, "FD_1"), (2, "FD_2"), (3, "FD_3")];

const BINFILE_LAYOUT: &[(u8, usize)] = &[(1, 0x00C000), (2, 0x020000), (3, 0x1C0000)];

const SOFTWARE_VERSION_LOCATION: &[(u8, (usize, usize))] =
    &[(1, (0x41F, 0x424)), (2, (0x627, 0x62F)), (3, (0x23, 0x2B))];

const BOX_CODE_LOCATION: &[(u8, (usize, usize))] =
    &[(1, (0x0, 0x0)), (2, (0x0, 0x0)), (3, (0x60, 0x6B))];

const CHECKSUM_BLOCK_LOCATION: &[(u8, usize)] =
    &[(0, 0x300), (1, 0x300), (2, 0x300), (3, 0x300), (6, 0x340)];

const BLOCK_NAME_TO_NUMBER: &[(&str, u8)] =
    &[("CBOOT", 1), ("ASW1", 2), ("CAL", 3), ("CBOOT_TEMP", 6)];

pub static S10_FLASH_INFO: FlashInfo = FlashInfo {
    base_addresses: BASE_ADDRESSES,
    block_lengths: BLOCK_LENGTHS,
    sa2_script: SA2_SCRIPT,
    block_names_frf: BLOCK_NAMES_FRF,
    block_identifiers: BLOCK_IDENTIFIERS_SIMOS,
    block_checksums: BLOCK_CHECKSUMS_SIMOS,
    control_module_identifier: ECU_CONTROL_MODULE_IDENTIFIER,
    software_version_location: SOFTWARE_VERSION_LOCATION,
    box_code_location: BOX_CODE_LOCATION,
    block_transfer_sizes: BLOCK_TRANSFER_SIZES_SIMOS,
    binfile_layout: BINFILE_LAYOUT,
    binfile_size: 2_097_152,
    project_name: "SA",
    crypto: &S10_CRYPTO,
    block_name_to_number: BLOCK_NAME_TO_NUMBER,
    checksum_block_location: CHECKSUM_BLOCK_LOCATION,
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
