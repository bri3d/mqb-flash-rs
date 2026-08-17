//! Binary file splitting and combining for VW ECU flash images.

use anyhow::{bail, Context, Result};
use mqb_modules::{BlockData, FlashInfo};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BinfileError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Read a full binary image from a file and split it into blocks.
pub fn blocks_from_file(
    path: &Path,
    flash_info: &FlashInfo,
) -> Result<HashMap<String, BlockData>, BinfileError> {
    let data = fs::read(path)?;
    Ok(blocks_from_bytes(&data, flash_info))
}

/// Split a binary image into named blocks using the FlashInfo layout.
pub fn blocks_from_bytes(data: &[u8], flash_info: &FlashInfo) -> HashMap<String, BlockData> {
    let mut blocks = HashMap::new();

    for &(block_num, frf_name) in flash_info.block_names_frf {
        let Some(offset) = flash_info.binfile_offset(block_num) else {
            continue;
        };
        let Some(length) = flash_info.resolve_block_length(block_num, data) else {
            continue;
        };

        if offset + length > data.len() {
            continue;
        }

        // Prefer the logical name (e.g. "ASW1") over the FRF name ("FD_02DATA") so that
        // split-bin output can be fed directly into checksum/prepare without renaming.
        let name = flash_info
            .block_number_to_name(block_num)
            .unwrap_or(frf_name);
        let block_bytes = data[offset..offset + length].to_vec();
        blocks.insert(
            name.to_owned(),
            BlockData::with_name(block_num, block_bytes, name),
        );
    }

    filter_blocks(blocks, flash_info)
}

/// Assemble blocks into a full binary image.
pub fn bin_from_blocks(blocks: &HashMap<String, BlockData>, flash_info: &FlashInfo) -> Vec<u8> {
    let mut output = vec![0u8; flash_info.binfile_size];

    for block in blocks.values() {
        let block_num = block.block_number;
        let Some(offset) = flash_info.binfile_offset(block_num) else {
            continue;
        };

        let copy_len = block
            .block_bytes
            .len()
            .min(output.len().saturating_sub(offset));
        output[offset..offset + copy_len].copy_from_slice(&block.block_bytes[..copy_len]);
    }

    output
}

// ── Multi-format firmware loading ─────────────────────────────────────────────

/// Load raw (decrypted, decompressed) block bytes from a firmware file.
///
/// The file type is inferred from the extension:
/// - `.frf` — decrypt FRF envelope, extract embedded ODX, parse + decrypt
/// - `.odx` — parse + decrypt standalone ODX
/// - `.bin` — split assembled binary by block layout from `flash_info`
///
/// Returns a map of block number → raw bytes.
pub fn load_raw_blocks(path: &Path, flash_info: &FlashInfo) -> Result<HashMap<u8, Vec<u8>>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("frf") => load_raw_blocks_frf(path, flash_info),
        Some("odx") => load_raw_blocks_odx(path, flash_info),
        Some("bin") => load_raw_blocks_bin(path, flash_info),
        _ => bail!(
            "Unsupported file type (expected .frf, .odx, or .bin): {}",
            path.display()
        ),
    }
}

fn load_raw_blocks_frf(path: &Path, flash_info: &FlashInfo) -> Result<HashMap<u8, Vec<u8>>> {
    let data = fs::read(path).with_context(|| format!("Reading FRF: {}", path.display()))?;
    let frf_contents = mqb_frf::extract_frf(&data).with_context(|| "Extracting FRF ZIP")?;

    let (_, odx_bytes) = frf_contents
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase().ends_with(".odx"))
        .with_context(|| "FRF does not contain an ODX file (SGO format not yet supported)")?;

    let xml = std::str::from_utf8(odx_bytes).with_context(|| "ODX entry is not valid UTF-8")?;
    map_odx_blocks(xml, flash_info)
}

fn load_raw_blocks_odx(path: &Path, flash_info: &FlashInfo) -> Result<HashMap<u8, Vec<u8>>> {
    let xml =
        fs::read_to_string(path).with_context(|| format!("Reading ODX: {}", path.display()))?;
    map_odx_blocks(&xml, flash_info)
}

fn map_odx_blocks(xml: &str, flash_info: &FlashInfo) -> Result<HashMap<u8, Vec<u8>>> {
    let (odx_blocks, _boxcodes) =
        mqb_odx::extract_odx(xml, flash_info).with_context(|| "Parsing ODX")?;
    anyhow::ensure!(!odx_blocks.is_empty(), "ODX contains no flash blocks");

    let mut result = HashMap::new();
    for (name, bytes) in odx_blocks {
        if let Some(num) = flash_info.block_to_number(&name) {
            result.insert(num, bytes);
        }
    }
    Ok(result)
}

fn load_raw_blocks_bin(path: &Path, flash_info: &FlashInfo) -> Result<HashMap<u8, Vec<u8>>> {
    let blocks = blocks_from_file(path, flash_info)
        .with_context(|| format!("Reading BIN: {}", path.display()))?;
    Ok(blocks
        .into_values()
        .map(|bd| (bd.block_number, bd.block_bytes))
        .collect())
}

// ── Block filtering ───────────────────────────────────────────────────────────

/// Filter out blocks whose software version prefix does not match the ECU's project name.
pub fn filter_blocks(
    blocks: HashMap<String, BlockData>,
    flash_info: &FlashInfo,
) -> HashMap<String, BlockData> {
    let project = flash_info.project_name;
    if project.is_empty() {
        return blocks;
    }

    blocks
        .into_iter()
        .filter(|(filename, block)| {
            let block_num = block.block_number;
            let version_range = flash_info.software_version_location(block_num);

            match version_range {
                Some((start, end)) if end > start => {
                    // There is a version location — check the prefix
                    if end > block.block_bytes.len() {
                        tracing::warn!("Discarding {filename}: block too short for version check");
                        return false;
                    }
                    match std::str::from_utf8(&block.block_bytes[start..end]) {
                        Ok(version) if version.starts_with(project) => true,
                        Ok(version) => {
                            tracing::warn!(
                                "Discarding {filename}: version '{version}' does not start with '{project}'"
                            );
                            false
                        }
                        Err(_) => {
                            tracing::warn!("Discarding {filename}: version field is not valid UTF-8");
                            false
                        }
                    }
                }
                _ => {
                    // No version check for this block — keep it
                    true
                }
            }
        })
        .collect()
}
