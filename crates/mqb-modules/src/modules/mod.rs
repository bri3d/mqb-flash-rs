//! Per-ECU FlashInfo configurations.

pub mod simos18;
pub mod simos122;
pub mod simos1810;
pub mod simos184;
pub mod simos16;
pub mod simos10;
pub mod simos8;
pub mod simos12;
pub mod dq250mqb;
pub mod dq381;
pub mod haldex4motion;

/// Shared Simos block identifiers (block_number → UDS identifier).
pub const BLOCK_IDENTIFIERS_SIMOS: &[(u8, u8)] = &[
    (1, 1), (2, 2), (3, 3), (4, 4), (5, 5),
];

/// Simos UDS checksums (all zeros — internally checksummed).
pub const BLOCK_CHECKSUMS_SIMOS: &[(u8, [u8; 4])] = &[
    (1, [0, 0, 0, 0]),
    (2, [0, 0, 0, 0]),
    (3, [0, 0, 0, 0]),
    (4, [0, 0, 0, 0]),
    (5, [0, 0, 0, 0]),
    (7, [0, 0, 0, 0]),
    (9, [0, 0, 0, 0]),
];

/// Standard Simos software version byte ranges.
pub const SOFTWARE_VERSION_LOCATION_SIMOS: &[(u8, (usize, usize))] = &[
    (1, (0x437, 0x43F)),
    (2, (0x627, 0x62F)),
    (3, (0x203, 0x20B)),
    (4, (0x203, 0x20B)),
    (5, (0x23, 0x2B)),
    (7, (0, 0)),
    (9, (0, 0)),
];

/// Standard Simos box code byte ranges.
pub const BOX_CODE_LOCATION_SIMOS: &[(u8, (usize, usize))] = &[
    (1, (0x0, 0x0)),
    (2, (0x0, 0x0)),
    (3, (0x0, 0x0)),
    (4, (0x0, 0x0)),
    (5, (0x60, 0x6B)),
    (7, (0, 0)),
    (9, (0x0, 0x0)),
];

/// Standard Simos transfer sizes (maximum ISO-TP payload).
pub const BLOCK_TRANSFER_SIZES_SIMOS: &[(u8, usize)] = &[
    (1, 0xFFD), (2, 0xFFD), (3, 0xFFD), (4, 0xFFD), (5, 0xFFD),
];

/// Standard Simos checksum header locations.
pub const CHECKSUM_BLOCK_LOCATION_SIMOS: &[(u8, usize)] = &[
    (0, 0x300), // SBOOT
    (1, 0x300), // CBOOT
    (2, 0x300), // ASW1
    (3, 0x000), // ASW2
    (4, 0x000), // ASW3
    (5, 0x300), // CAL
    (6, 0x340), // CBOOT_temp
];

/// Standard Simos block name → number mapping.
pub const BLOCK_NAME_TO_NUMBER_SIMOS: &[(&str, u8)] = &[
    ("CBOOT", 1),
    ("ASW1", 2),
    ("ASW2", 3),
    ("ASW3", 4),
    ("CAL", 5),
    ("CBOOT_TEMP", 6),
    ("PATCH_ASW1", 7),
    ("PATCH_ASW2", 8),
    ("PATCH_ASW3", 9),
];
