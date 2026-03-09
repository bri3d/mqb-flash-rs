//! Simos8 ECU flash configuration.

use crate::crypto::SimosXorCrypto;
use crate::types::{ChecksumKind, FlashInfo, ECU_CONTROL_MODULE_IDENTIFIER};
use super::{BLOCK_CHECKSUMS_SIMOS, BLOCK_IDENTIFIERS_SIMOS, BLOCK_TRANSFER_SIZES_SIMOS};

static S8_CRYPTO: SimosXorCrypto = SimosXorCrypto;

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x05, 0x82, 0x4A, 0x10, 0x68, 0x04, 0x93, 0x30, 0x04, 0x19, 0x62, 0x4A, 0x05, 0x87,
    0x15, 0x10, 0x19, 0x70, 0x82, 0x49, 0x93, 0x24, 0x04, 0x19, 0x66, 0x82, 0x4A, 0x05, 0x87,
    0x02, 0x03, 0x19, 0x70, 0x82, 0x4A, 0x01, 0x81, 0x49, 0x4C,
];

const BASE_ADDRESSES: &[(u8, u32)] = &[
    (1, 0x80020000), (2, 0x80080000), (3, 0xA0040000), (6, 0xA0040000),
];

const BLOCK_LENGTHS: &[(u8, usize)] = &[
    (1, 0x13E00), (2, 0x17FE00), (3, 0x3C000),
];

const BLOCK_NAMES_FRF: &[(u8, &str)] = &[
    (1, "FD_0"), (2, "FD_1"), (3, "FD_2"),
];

const BINFILE_LAYOUT: &[(u8, usize)] = &[
    (1, 0x020000), (2, 0x080000), (3, 0x040000),
];

const SOFTWARE_VERSION_LOCATION: &[(u8, (usize, usize))] = &[
    (1, (0x437, 0x43F)), (2, (0x627, 0x62F)), (3, (0x23, 0x2B)),
];

const BOX_CODE_LOCATION: &[(u8, (usize, usize))] = &[
    (1, (0x0, 0x0)), (2, (0x0, 0x0)), (3, (0x60, 0x6B)),
];

const CHECKSUM_BLOCK_LOCATION: &[(u8, usize)] = &[
    (0, 0x300), (1, 0x300), (2, 0x300), (3, 0x300), (6, 0x340),
];

const BLOCK_NAME_TO_NUMBER: &[(&str, u8)] = &[
    ("CBOOT", 1), ("ASW1", 2), ("CAL", 3), ("CBOOT_TEMP", 6),
];

pub static S8_FLASH_INFO: FlashInfo = FlashInfo {
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
    project_name: "S85",
    crypto: &S8_CRYPTO,
    block_name_to_number: BLOCK_NAME_TO_NUMBER,
    checksum_block_location: CHECKSUM_BLOCK_LOCATION,
    patch_info: None,
    checksum_kind: ChecksumKind::Simos,
    lzss10_odx: false,
};
