//! Simos18.41 ECU flash configuration.
//! Uses the same base_addresses and block_lengths as Simos18.10.

use crate::crypto::AesCrypto;
use crate::types::{ChecksumKind, FlashInfo, PatchInfo, ECU_CONTROL_MODULE_IDENTIFIER};

const S184_PATCH_BYTES: &[u8] = include_bytes!("../../../../data/patch_1841.bin");
use super::{
    BLOCK_CHECKSUMS_SIMOS, BLOCK_IDENTIFIERS_SIMOS, BLOCK_NAME_TO_NUMBER_SIMOS,
    BLOCK_TRANSFER_SIZES_SIMOS, BOX_CODE_LOCATION_SIMOS, CHECKSUM_BLOCK_LOCATION_SIMOS,
    SOFTWARE_VERSION_LOCATION_SIMOS,
};
// Same addresses and block lengths as Simos18.10
const BASE_ADDRESSES: &[(u8, u32)] = &[
    (0, 0x80000000), (1, 0x80800000), (2, 0x80020000),
    (3, 0x80100000), (4, 0x808C0000), (5, 0xA0820000), (6, 0x80880000),
];
const BLOCK_LENGTHS: &[(u8, usize)] = &[
    (1, 0x1FE00), (2, 0xDFC00), (3, 0xFFC00), (4, 0x13FC00), (5, 0x9FC00), (6, 0x1FE00),
];

static S184_CRYPTO: AesCrypto = AesCrypto::new(
    [0x6E, 0x3F, 0xE0, 0x36, 0x19, 0xF1, 0x38, 0x79, 0x8C, 0xB4, 0xEC, 0xDC, 0xC7, 0x62, 0x00, 0x5F],
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
);

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x02, 0x81, 0x4A, 0x10, 0x68, 0x04, 0x93, 0xC1, 0x38, 0x7F, 0xA3, 0x4A, 0x05, 0x87,
    0x22, 0x12, 0x19, 0x54, 0x82, 0x49, 0x93, 0x18, 0x10, 0x20, 0x12, 0x82, 0x4A, 0x05, 0x87,
    0x28, 0x05, 0x19, 0x77, 0x82, 0x4A, 0x01, 0x81, 0x49, 0x4C,
];

const BLOCK_NAMES_FRF: &[(u8, &str)] = &[
    (1, "FD_01FLASHDATA"), (2, "FD_02FLASHDATA"), (3, "FD_03FLASHDATA"),
    (4, "FD_04FLASHDATA"), (5, "FD_05FLASHDATA"),
];

const BINFILE_LAYOUT: &[(u8, usize)] = &[
    (0, 0x000000), (1, 0x200000), (2, 0x020000),
    (3, 0x100000), (4, 0x2C0000), (5, 0x220000),
];

fn s184_transfer_size_patch(block_num: u8, address: usize) -> usize {
    assert_eq!(block_num, 2, "Only Block 2 (ASW1) patching is supported for Simos18.41");
    if address < 0x68500 { return 0x100; }
    if address < 0x68600 { return 0x8; }
    if address < 0xCB000 { return 0x100; }
    if address < 0xCB100 { return 0x8; }
    if address < 0xDFB00 { return 0x100; }
    0x8
}

pub static S184_FLASH_INFO: FlashInfo = FlashInfo {
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
    project_name: "SCB",
    crypto: &S184_CRYPTO,
    block_name_to_number: BLOCK_NAME_TO_NUMBER_SIMOS,
    checksum_block_location: CHECKSUM_BLOCK_LOCATION_SIMOS,
    patch_info: Some(PatchInfo {
        patch_box_code: "80A906259F__0008",
        patch_block_index: 2,
        patch_bytes: S184_PATCH_BYTES,
        block_transfer_size_fn: s184_transfer_size_patch,
    }),
    checksum_kind: ChecksumKind::Simos,
    lzss10_odx: false,
    dynamic_block_length_offsets: &[],
};
