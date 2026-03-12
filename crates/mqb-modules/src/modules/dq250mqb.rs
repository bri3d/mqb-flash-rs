//! DQ250 MQB (DSG) transmission ECU flash configuration.

use crate::crypto::DsgCrypto;
use crate::types::{ChecksumKind, ControlModuleIdentifier, FlashInfo};

static DSG_CRYPTO: DsgCrypto = DsgCrypto;

const CONTROL_MODULE_IDENTIFIER: ControlModuleIdentifier =
    ControlModuleIdentifier { rxid: 0x7E9, txid: 0x7E1 };

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x02, 0x81, 0x49, 0x68, 0x05, 0x93, 0xA5, 0x5A, 0x55, 0xAA, 0x4A, 0x05, 0x87, 0x81,
    0x05, 0x95, 0x26, 0x82, 0x49, 0x84, 0x5A, 0xA5, 0xAA, 0x55, 0x87, 0x03, 0xF7, 0x80, 0x38,
    0x4C,
];

const BLOCK_LENGTHS: &[(u8, usize)] = &[
    (2, 0x80E),    // DRIVER
    (3, 0x130000), // ASW
    (4, 0x20000),  // CAL
];

const BLOCK_NAMES_FRF: &[(u8, &str)] = &[
    (2, "FD_2"), (3, "FD_3"), (4, "FD_4"),
];

const BLOCK_IDENTIFIERS: &[(u8, u8)] = &[
    (2, 0x30), (3, 0x50), (4, 0x51),
];

const BLOCK_CHECKSUMS: &[(u8, [u8; 4])] = &[
    (2, [0xF9, 0x74, 0x17, 0x6E]),
    (3, [0xFF, 0xFF, 0xFF, 0xFF]),
    (4, [0xFF, 0xFF, 0xFF, 0xFF]),
];

const SOFTWARE_VERSION_LOCATION: &[(u8, (usize, usize))] = &[
    (2, (0x0, 0x0)),
    (3, (0x3FFE0, 0x3FFE4)),
    (4, (0x1FFE0, 0x1FFE4)),
];

const BOX_CODE_LOCATION: &[(u8, (usize, usize))] = &[
    (2, (0x0, 0x0)), (3, (0x0, 0x0)), (4, (0x1FFC0, 0x1FFD3)),
];

const BLOCK_TRANSFER_SIZES: &[(u8, usize)] = &[
    (2, 0x4B0), (3, 0x800), (4, 0x800),
];

const BINFILE_LAYOUT: &[(u8, usize)] = &[
    (2, 0x000000), (3, 0x050000), (4, 0x030000),
];

const BLOCK_NAME_TO_NUMBER: &[(&str, u8)] = &[
    ("DRIVER", 2), ("ASW", 3), ("CAL", 4),
];

pub static DQ250_FLASH_INFO: FlashInfo = FlashInfo {
    base_addresses: &[], // DSG has no base address relative calculations
    block_lengths: BLOCK_LENGTHS,
    sa2_script: SA2_SCRIPT,
    block_names_frf: BLOCK_NAMES_FRF,
    block_identifiers: BLOCK_IDENTIFIERS,
    block_checksums: BLOCK_CHECKSUMS,
    control_module_identifier: CONTROL_MODULE_IDENTIFIER,
    software_version_location: SOFTWARE_VERSION_LOCATION,
    box_code_location: BOX_CODE_LOCATION,
    block_transfer_sizes: BLOCK_TRANSFER_SIZES,
    binfile_layout: BINFILE_LAYOUT,
    binfile_size: 1_572_864,
    project_name: "F",
    crypto: &DSG_CRYPTO,
    block_name_to_number: BLOCK_NAME_TO_NUMBER,
    checksum_block_location: &[], // No checksum block locations for DSG
    patch_info: None,
    checksum_kind: ChecksumKind::Dsg,
    lzss10_odx: true,
    dynamic_block_length_offsets: &[],
};
