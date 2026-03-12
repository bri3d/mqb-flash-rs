//! DQ381 transmission ECU flash configuration.

use crate::crypto::AesCrypto;
use crate::types::{ChecksumKind, ControlModuleIdentifier, FlashInfo};

static DQ381_CRYPTO: AesCrypto = AesCrypto::new(
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F],
    [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
);

const CONTROL_MODULE_IDENTIFIER: ControlModuleIdentifier =
    ControlModuleIdentifier { rxid: 0x7E9, txid: 0x7E1 };

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x06, 0x81, 0x4A, 0x05, 0x87, 0x6B, 0x5F, 0x7D, 0xD5, 0x49, 0x4C,
];

/// Base addresses used by dq381_checksum to locate data.
pub const BLOCK_BASE_ADDRESSES: &[(u8, u32)] = &[
    (1, 0x010200), (2, 0x030200), (3, 0x140200),
];

const BLOCK_LENGTHS: &[(u8, usize)] = &[
    (1, 0x1FE00),   // BOOT
    (2, 0x10FE00),  // ASW
    (3, 0x3FE00),   // CAL
];

const BLOCK_NAMES_FRF: &[(u8, &str)] = &[
    (1, "FD_01DATA"), (2, "FD_02DATA"), (3, "FD_03DATA"),
];

const BLOCK_IDENTIFIERS: &[(u8, u8)] = &[
    (1, 1), (2, 2), (3, 3),
];

const SOFTWARE_VERSION_LOCATION: &[(u8, (usize, usize))] = &[
    (1, (0x0, 0x0)), (2, (0x0, 0x0)), (3, (0x0, 0x0)),
];

const BOX_CODE_LOCATION: &[(u8, (usize, usize))] = &[
    (1, (0x0, 0x0)), (2, (0x0, 0x0)), (3, (0x0, 0x0)),
];

const BLOCK_TRANSFER_SIZES: &[(u8, usize)] = &[
    (1, 0xF0), (2, 0xF0), (3, 0xF0),
];

const BINFILE_LAYOUT: &[(u8, usize)] = &[
    (1, 0x010200), (2, 0x030200), (3, 0x140200),
];

const BLOCK_NAME_TO_NUMBER: &[(&str, u8)] = &[
    ("BOOT", 1), ("ASW", 2), ("CAL", 3),
];

pub static DQ381_FLASH_INFO: FlashInfo = FlashInfo {
    base_addresses: &[], // DQ381 checksum uses its own base addresses
    block_lengths: BLOCK_LENGTHS,
    sa2_script: SA2_SCRIPT,
    block_names_frf: BLOCK_NAMES_FRF,
    block_identifiers: BLOCK_IDENTIFIERS,
    block_checksums: &[], // No UDS checksums for DQ381
    control_module_identifier: CONTROL_MODULE_IDENTIFIER,
    software_version_location: SOFTWARE_VERSION_LOCATION,
    box_code_location: BOX_CODE_LOCATION,
    block_transfer_sizes: BLOCK_TRANSFER_SIZES,
    binfile_layout: BINFILE_LAYOUT,
    binfile_size: 0x180000,
    project_name: "F",
    crypto: &DQ381_CRYPTO,
    block_name_to_number: BLOCK_NAME_TO_NUMBER,
    checksum_block_location: &[], // DQ381 uses its own checksum logic
    patch_info: None,
    checksum_kind: ChecksumKind::Dq381,
    lzss10_odx: false,
    dynamic_block_length_offsets: &[],
};
