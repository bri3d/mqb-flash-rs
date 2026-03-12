//! Shared data types ported from lib/constants.py.

use crate::crypto::BlockCrypto;

// ── Private lookup helper ─────────────────────────────────────────────────────

/// Find the value associated with `block_num` in a `(block_num, value)` table.
fn lookup<T: Copy>(table: &[(u8, T)], block_num: u8) -> Option<T> {
    table.iter().find(|(n, _)| *n == block_num).map(|(_, v)| *v)
}

// ── Block data ────────────────────────────────────────────────────────────────

/// Which checksum algorithm the ECU uses.
///
/// Used by the CLI to dispatch to the correct validation function without
/// string-based module-name matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumKind {
    Simos,
    Dsg,
    Dq381,
    Haldex,
}

/// Raw block data as read from a binary or FRF/ODX file.
#[derive(Debug, Clone)]
pub struct BlockData {
    pub block_number: u8,
    pub block_bytes: Vec<u8>,
    pub block_name: Option<String>,
}

impl BlockData {
    pub fn with_name(block_number: u8, block_bytes: Vec<u8>, name: &str) -> Self {
        Self { block_number, block_bytes, block_name: Some(name.to_owned()) }
    }
}

/// A block prepared for flashing: compressed and/or encrypted, with metadata.
#[derive(Debug, Clone)]
pub struct PreparedBlockData {
    pub block_number: u8,
    pub block_encrypted_bytes: Vec<u8>,
    pub boxcode: String,
    pub encryption_type: u8,
    pub compression_type: u8,
    pub should_erase: bool,
    pub uds_checksum: [u8; 4],
    pub block_name: String,
}

/// Result of a checksum validation or fix attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumState {
    Valid,
    Invalid,
    Fixed,
    Failed,
}

/// A UDS Data Identifier (DID) with metadata for display.
pub struct DataRecord {
    pub address: u16,
    pub parse_type: u8,
    pub description: &'static str,
}

/// CAN identifiers for a specific ECU control module.
#[derive(Debug, Clone, Copy)]
pub struct ControlModuleIdentifier {
    pub rxid: u32,
    pub txid: u32,
}

/// Standard Simos ECU identifiers (0x7E8 / 0x7E0).
pub const ECU_CONTROL_MODULE_IDENTIFIER: ControlModuleIdentifier =
    ControlModuleIdentifier { rxid: 0x7E8, txid: 0x7E0 };

/// Information needed to patch an ASW block using WriteWithoutErase.
pub struct PatchInfo {
    pub patch_box_code: &'static str,
    pub patch_block_index: u8,
    pub patch_bytes: &'static [u8],
    /// Returns the transfer size to use given (block_num, current_address).
    pub block_transfer_size_fn: fn(block_num: u8, address: usize) -> usize,
}

/// All flash-related configuration for a specific ECU variant.
pub struct FlashInfo {
    /// `(block_number, base_address)` pairs — absolute address in ECU memory map.
    pub base_addresses: &'static [(u8, u32)],
    /// `(block_number, length_in_bytes)` pairs.
    pub block_lengths: &'static [(u8, usize)],
    /// The SA2 seed-key script bytecode.
    pub sa2_script: &'static [u8],
    /// `(block_number, frf_filename)` — FRF inner file names per block.
    pub block_names_frf: &'static [(u8, &'static str)],
    /// `(block_number, block_identifier)` — UDS block identifier per block.
    pub block_identifiers: &'static [(u8, u8)],
    /// `(block_number, uds_checksum_bytes)` — 4-byte UDS checksum per block.
    pub block_checksums: &'static [(u8, [u8; 4])],
    pub control_module_identifier: ControlModuleIdentifier,
    /// `(block_number, (start, end))` — byte range of the software version string.
    pub software_version_location: &'static [(u8, (usize, usize))],
    /// `(block_number, (start, end))` — byte range of the box code string.
    pub box_code_location: &'static [(u8, (usize, usize))],
    /// `(block_number, max_transfer_chunk_size)` for normal flashing.
    pub block_transfer_sizes: &'static [(u8, usize)],
    /// `(block_number, offset_in_full_bin_file)` for bin split/combine.
    pub binfile_layout: &'static [(u8, usize)],
    /// Total size of the assembled full binary image.
    pub binfile_size: usize,
    /// Short project name prefix (e.g. `"SC8"`) used to validate block compatibility.
    pub project_name: &'static str,
    /// The crypto implementation for this ECU.
    pub crypto: &'static dyn BlockCrypto,
    /// `(name, block_number)` — name-to-number mapping.
    pub block_name_to_number: &'static [(&'static str, u8)],
    /// `(block_number, byte_offset)` — location of the checksum header in each block.
    pub checksum_block_location: &'static [(u8, usize)],
    pub patch_info: Option<PatchInfo>,
    /// Which checksum algorithm this ECU uses (for CLI dispatch).
    pub checksum_kind: ChecksumKind,
    /// Whether the ODX for this ECU uses LZSS10 for all blocks regardless of
    /// the ENCRYPT-COMPRESS-METHOD field (required for DSG/DQ250).
    pub lzss10_odx: bool,
    /// `(block_number, header_offset)` — for modules with dynamic block lengths (Haldex),
    /// the offset within each block's data region where the actual length is stored as u32 LE.
    /// Empty for all other modules (static lengths only).
    pub dynamic_block_length_offsets: &'static [(u8, usize)],
}

impl FlashInfo {
    /// Look up a base address by block number.
    pub fn base_address(&self, block_num: u8) -> Option<u32> {
        lookup(self.base_addresses, block_num)
    }

    /// Look up a block length by block number (static).
    pub fn block_length(&self, block_num: u8) -> Option<usize> {
        lookup(self.block_lengths, block_num)
    }

    /// Resolve the actual block length, reading it from the binary data if this
    /// module has dynamic block lengths (Haldex). Falls back to the static length.
    pub fn resolve_block_length(&self, block_num: u8, full_bin: &[u8]) -> Option<usize> {
        if let Some(header_offset) = lookup(self.dynamic_block_length_offsets, block_num) {
            let binfile_offset = self.binfile_offset(block_num)?;
            let addr = binfile_offset + header_offset;
            if addr + 4 <= full_bin.len() {
                let len = u32::from_le_bytes(
                    full_bin[addr..addr + 4].try_into().unwrap(),
                ) as usize;
                if len > 0 && binfile_offset + len <= full_bin.len() {
                    return Some(len);
                }
            }
        }
        self.block_length(block_num)
    }

    /// Look up the FRF filename for a block number.
    pub fn block_name_frf(&self, block_num: u8) -> Option<&'static str> {
        lookup(self.block_names_frf, block_num)
    }

    /// Look up the UDS block identifier for a block number.
    pub fn block_identifier(&self, block_num: u8) -> Option<u8> {
        lookup(self.block_identifiers, block_num)
    }

    /// Look up a UDS checksum for a block number.
    pub fn block_checksum(&self, block_num: u8) -> Option<[u8; 4]> {
        lookup(self.block_checksums, block_num)
    }

    /// Look up the software version byte range for a block number.
    pub fn software_version_location(&self, block_num: u8) -> Option<(usize, usize)> {
        lookup(self.software_version_location, block_num)
    }

    /// Look up the box code byte range for a block number.
    pub fn box_code_location(&self, block_num: u8) -> Option<(usize, usize)> {
        lookup(self.box_code_location, block_num)
    }

    /// Look up the transfer size for a block number.
    pub fn block_transfer_size(&self, block_num: u8) -> Option<usize> {
        lookup(self.block_transfer_sizes, block_num)
    }

    /// Look up the binfile layout offset for a block number.
    pub fn binfile_offset(&self, block_num: u8) -> Option<usize> {
        lookup(self.binfile_layout, block_num)
    }

    /// Look up the checksum header offset for a block number.
    pub fn checksum_block_location(&self, block_num: u8) -> Option<usize> {
        lookup(self.checksum_block_location, block_num)
    }

    /// Convert a block name string or digit string to a block number.
    ///
    /// Accepts:
    /// - A bare integer (`"1"` → block 1)
    /// - A logical name (`"ASW1"` / `"asw1"`) from `block_name_to_number`
    /// - An FRF file name (`"FD_02DATA"`) from `block_names_frf`
    pub fn block_to_number(&self, name: &str) -> Option<u8> {
        if let Ok(n) = name.parse::<u8>() {
            return Some(n);
        }
        let upper = name.to_uppercase();
        if let Some(&(_, n)) = self.block_name_to_number.iter().find(|(s, _)| *s == upper) {
            return Some(n);
        }
        // Fall back to FRF names (e.g. "FD_01DATA" from ODX extraction)
        self.block_names_frf.iter().find(|(_, s)| s.to_uppercase() == upper).map(|(n, _)| *n)
    }

    /// Convert a block number to its canonical name.
    pub fn block_number_to_name(&self, num: u8) -> Option<&'static str> {
        self.block_name_to_number.iter().find(|(_, n)| *n == num).map(|(s, _)| *s)
    }
}

/// Well-known UDS Data Identifiers used across all VW ECUs.
pub static DATA_RECORDS: &[DataRecord] = &[
    DataRecord { address: 0xF190, parse_type: 0, description: "VIN Vehicle Identification Number" },
    DataRecord { address: 0xF19E, parse_type: 0, description: "ASAM/ODX File Identifier" },
    DataRecord { address: 0xF1A2, parse_type: 0, description: "ASAM/ODX File Version" },
    DataRecord { address: 0xF40D, parse_type: 1, description: "Vehicle Speed" },
    DataRecord { address: 0xF806, parse_type: 1, description: "Calibration Verification Numbers" },
    DataRecord { address: 0xF187, parse_type: 0, description: "VW Spare Part Number" },
    DataRecord { address: 0xF189, parse_type: 0, description: "VW Application Software Version Number" },
    DataRecord { address: 0xF191, parse_type: 0, description: "VW ECU Hardware Number" },
    DataRecord { address: 0xF1A3, parse_type: 0, description: "VW ECU Hardware Version Number" },
    DataRecord { address: 0xF197, parse_type: 0, description: "VW System Name Or Engine Type" },
    DataRecord { address: 0xF1AD, parse_type: 0, description: "Engine Code Letters" },
    DataRecord { address: 0xF1AA, parse_type: 0, description: "VW Workshop System Name" },
    DataRecord { address: 0x0405, parse_type: 1, description: "State Of Flash Memory" },
    DataRecord { address: 0x0407, parse_type: 1, description: "VW Logical Software Block Counter Of Programming Attempts" },
    DataRecord { address: 0x0408, parse_type: 1, description: "VW Logical Software Block Counter Of Successful Programming Attempts" },
    DataRecord { address: 0x0600, parse_type: 1, description: "VW Coding Value" },
    DataRecord { address: 0xF186, parse_type: 1, description: "Active Diagnostic Session" },
    DataRecord { address: 0xF18C, parse_type: 0, description: "ECU Serial Number" },
    DataRecord { address: 0xF17C, parse_type: 0, description: "VW FAZIT Identification String" },
    DataRecord { address: 0xF442, parse_type: 1, description: "Control Module Voltage" },
    DataRecord { address: 0xEF90, parse_type: 1, description: "Immobilizer Status SHE" },
    DataRecord { address: 0xF1F4, parse_type: 0, description: "Boot Loader Identification" },
    DataRecord { address: 0xF1DF, parse_type: 1, description: "ECU Programming Information" },
    DataRecord { address: 0xF1F1, parse_type: 1, description: "Tuning Protection SO2" },
    DataRecord { address: 0xF1E0, parse_type: 1, description: "" },
    DataRecord { address: 0x12FC, parse_type: 1, description: "" },
    DataRecord { address: 0x12FF, parse_type: 1, description: "" },
    DataRecord { address: 0xFD52, parse_type: 1, description: "" },
    DataRecord { address: 0xFD83, parse_type: 1, description: "" },
    DataRecord { address: 0xFDFA, parse_type: 1, description: "" },
    DataRecord { address: 0xFDFC, parse_type: 1, description: "" },
    DataRecord { address: 0x295A, parse_type: 1, description: "Vehicle Mileage" },
    DataRecord { address: 0x295B, parse_type: 1, description: "Control Module Mileage" },
    DataRecord { address: 0xF15B, parse_type: 1, description: "Fingerprint and Programming Date" },
    DataRecord { address: 0xF1A5, parse_type: 1, description: "VW Coding Repair Shop Code Or Serial Number (Coding Fingerprint)" },
    DataRecord { address: 0xF1AB, parse_type: 0, description: "VW Logical Software Block Version" },
    DataRecord { address: 0xF804, parse_type: 0, description: "Calibration ID" },
    DataRecord { address: 0xF17E, parse_type: 0, description: "ECU Production Change Number" },
];
