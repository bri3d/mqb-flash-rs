//! Haldex 4Motion coupling ECU flash configuration.

use crate::crypto::NoCrypto;
use crate::types::{ChecksumKind, ControlModuleIdentifier, FlashInfo};

static HALDEX_CRYPTO: NoCrypto = NoCrypto;

const CONTROL_MODULE_IDENTIFIER: ControlModuleIdentifier =
    ControlModuleIdentifier { rxid: 0x779, txid: 0x70F };

const SA2_SCRIPT: &[u8] = &[
    0x68, 0x05, 0x81, 0x4A, 0x05, 0x87, 0x0A, 0x22, 0x12, 0x89, 0x49, 0x4C,
];

const BLOCK_LENGTHS: &[(u8, usize)] = &[
    (1, 0x434),    // DRIVER
    (2, 0x333E),   // CAL
    (3, 0x3DB80),  // ASW
    (4, 0xE),      // Version
];

const BLOCK_NAMES_FRF: &[(u8, &str)] = &[
    (1, "FD_0DRIVE"), (2, "FD_1DATA"), (3, "FD_2DATA"), (4, "FD_3DATA"),
];

const BLOCK_IDENTIFIERS: &[(u8, u8)] = &[
    (1, 0x30), (2, 0x02), (3, 0x01), (4, 0x03),
];

const SOFTWARE_VERSION_LOCATION: &[(u8, (usize, usize))] = &[
    (1, (0x0, 0x0)),
    (2, (0x0, 0x4)),
    (3, (0x3DB7C, 0x3DB80)),
    (4, (0xA, 0xE)),
];

const BOX_CODE_LOCATION: &[(u8, (usize, usize))] = &[
    (1, (0x0, 0x0)), (2, (0x4, 0xF)), (3, (0x0, 0x0)), (4, (0x0, 0x0)),
];

const BLOCK_TRANSFER_SIZES: &[(u8, usize)] = &[
    (1, 0x100), (2, 0x100), (3, 0x100), (4, 0x100),
];

const BINFILE_LAYOUT: &[(u8, usize)] = &[
    (1, 0x00000),  // DRIVER
    (2, 0x0B400),  // CAL
    (3, 0x10000),  // ASW
    (4, 0x4DC00),  // VERSION
];

/// Haldex-specific checksum header locations.
pub const CHECKSUM_BLOCK_LOCATION: &[(u8, usize)] = &[
    (1, 0x0),   // DRIVER (No CS)
    (2, 0x10),  // CAL
    (3, 0x200), // ASW
    (4, 0x0),   // Version
];

const BLOCK_NAME_TO_NUMBER: &[(&str, u8)] = &[
    ("DRIVER", 1), ("CAL", 2), ("ASW", 3), ("VERSION", 4),
];

pub static HALDEX_FLASH_INFO: FlashInfo = FlashInfo {
    base_addresses: &[], // No base addresses for Haldex
    block_lengths: BLOCK_LENGTHS,
    sa2_script: SA2_SCRIPT,
    block_names_frf: BLOCK_NAMES_FRF,
    block_identifiers: BLOCK_IDENTIFIERS,
    block_checksums: &[], // No UDS checksums
    control_module_identifier: CONTROL_MODULE_IDENTIFIER,
    software_version_location: SOFTWARE_VERSION_LOCATION,
    box_code_location: BOX_CODE_LOCATION,
    block_transfer_sizes: BLOCK_TRANSFER_SIZES,
    binfile_layout: BINFILE_LAYOUT,
    binfile_size: 327_680,
    project_name: "",
    crypto: &HALDEX_CRYPTO,
    block_name_to_number: BLOCK_NAME_TO_NUMBER,
    checksum_block_location: CHECKSUM_BLOCK_LOCATION,
    patch_info: None,
    checksum_kind: ChecksumKind::Haldex,
    lzss10_odx: false,
    dynamic_block_length_offsets: &[
        (2, 0x14),  // CAL: length at offset 0x14
        (3, 0x204), // ASW: length at offset 0x204
        (4, 0x04),  // VERSION: length at offset 0x04
    ],
};
