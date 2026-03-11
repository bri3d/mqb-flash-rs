//! ODX XML parsing, decryption, and decompression for VW ECU flash data.
//!
//! Parses the `FLASHDATA` elements from an ODX file, decrypts and decompresses
//! each block according to the two-character `ENCRYPT-COMPRESS-METHOD` type code,
//! and returns a map of block ID → decompressed data.

use std::collections::HashMap;
use thiserror::Error;
use mqb_modules::{BlockCrypto, FlashInfo};
use mqb_lzss::{decompress_legacy, decompress_lzss10};

#[derive(Debug, Error)]
pub enum OdxError {
    #[error("XML parse error: {0}")]
    Xml(#[from] roxmltree::Error),
    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Missing required XML element: {0}")]
    MissingElement(&'static str),
    #[error("Could not find UNCOMPRESSED-SIZE for FLASHDATA ID '{0}'")]
    MissingSize(String),
}

/// Map of block ID → decompressed data, plus list of allowed box codes.
pub type OdxBlocks = (HashMap<String, Vec<u8>>, Vec<String>);

/// Extract, decrypt, and decompress all flash data blocks from an ODX XML string.
///
/// Returns `(block_id → data, allowed_boxcodes)`.
pub fn extract_odx(xml: &str, flash_info: &FlashInfo) -> Result<OdxBlocks, OdxError> {
    extract_odx_with(xml, flash_info.crypto, flash_info.lzss10_odx)
}

fn extract_odx_with(
    xml: &str,
    crypto: &dyn BlockCrypto,
    lzss10_odx: bool,
) -> Result<OdxBlocks, OdxError> {
    let doc = roxmltree::Document::parse(xml)?;
    let root = doc.root_element();

    // Single pass: collect box codes, size map, and flash data nodes
    let mut allowed_boxcodes = Vec::new();
    let mut size_map: HashMap<String, usize> = HashMap::new();
    let mut flash_data_nodes = Vec::new();

    for node in root.descendants() {
        match node.tag_name().name() {
            "IDENT-VALUE" => {
                if let Some(text) = node.text() {
                    allowed_boxcodes.push(text.trim_end().to_owned());
                }
            }
            "FLASHDATA-REF" => {
                let id_ref = node.attribute("ID-REF").unwrap_or("").to_owned();
                // parent = DATABLOCK; search its descendants for UNCOMPRESSED-SIZE
                if let Some(datablock) = node.parent() {
                    let size = datablock
                        .descendants()
                        .find(|n| n.tag_name().name() == "UNCOMPRESSED-SIZE")
                        .and_then(|n| n.text())
                        .and_then(|t| t.trim().parse::<usize>().ok());
                    if let Some(sz) = size {
                        size_map.insert(id_ref, sz);
                    }
                }
            }
            "FLASHDATA" => {
                flash_data_nodes.push(node);
            }
            _ => {}
        }
    }

    // Process each FLASHDATA element
    let mut all_data = HashMap::new();

    for node in flash_data_nodes {

        let data_id = node.attribute("ID").unwrap_or("").to_owned();

        let data_content = node
            .children()
            .find(|n| n.tag_name().name() == "DATA")
            .and_then(|n| n.text())
            .ok_or(OdxError::MissingElement("DATA"))?;

        let ec_type = node
            .children()
            .find(|n| n.tag_name().name() == "ENCRYPT-COMPRESS-METHOD")
            .and_then(|n| n.text())
            .ok_or(OdxError::MissingElement("ENCRYPT-COMPRESS-METHOD"))?;

        // Skip erase blocks (only 2 hex chars = 1 byte)
        if data_content.len() <= 2 {
            continue;
        }

        let compression_type = ec_type.chars().next().unwrap_or('0');
        let encryption_type = ec_type.chars().nth(1).unwrap_or('0');

        let raw_bytes = hex::decode(data_content.trim())?;

        // Decrypt
        let decrypted = if encryption_type == '0' {
            raw_bytes
        } else {
            crypto.decrypt(&raw_bytes)
        };

        // Get decompressed size
        let decompressed_size = size_map
            .get(&data_id)
            .copied()
            .ok_or_else(|| OdxError::MissingSize(data_id.clone()))?;

        // Decompress
        let decompressed = match compression_type {
            'A' | 'a' => decompress_lzss10(&decrypted, decompressed_size),
            '1' => decompress_legacy(&decrypted),
            _ if lzss10_odx => decompress_lzss10(&decrypted, decompressed_size),
            _ => decrypted, // '0' = no compression
        };

        // The block name is the first child element's text (DATA's text was used for content,
        // first child is typically the SHORT-NAME)
        let block_name = node
            .children()
            .find(|n| n.tag_name().name() == "SHORT-NAME")
            .and_then(|n| n.text())
            .unwrap_or(&data_id)
            .to_owned();

        all_data.insert(block_name, decompressed);
    }

    Ok((all_data, allowed_boxcodes))
}
