//! mqb-flash CLI — VW/Audi ECU flash tool.

mod modules;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

use mqb_flash_uds::{FlashOptions, Interface};
use mqb_modules::FlashInfo;

// ── CLI argument types ────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "mqb-flash", about = "VW/Audi ECU flash tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decrypt an FRF file (no ZIP extraction)
    DecryptFrf {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = ".")]
        outdir: PathBuf,
    },
    /// Decrypt an FRF file and assemble a full binary image
    ExtractFrf {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        module: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Parse an ODX file and extract flash data blocks
    ExtractOdx {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        module: String,
        #[arg(long, default_value = ".")]
        outdir: PathBuf,
    },
    /// Split a full binary image into named block files
    SplitBin {
        #[arg(long)]
        module: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = ".")]
        outdir: PathBuf,
    },
    /// Combine named block files into a full binary image
    CombineBin {
        #[arg(long)]
        module: String,
        /// Block files in `name:path` format (e.g. `CAL:/path/to/cal.bin`)
        #[arg(long = "block", value_name = "NAME:FILE")]
        blocks: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Fix checksums in a full binary image and write a corrected copy
    Checksum {
        #[arg(long)]
        module: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Patch CBOOT to enable sample mode before fixing checksums
        #[arg(long)]
        patch_cboot: bool,
    },
    /// Flash block files to a connected ECU
    Flash {
        #[arg(long)]
        module: String,
        /// Interface string: `socketcan:<ifname>`, `panda`, `j2534[:<dll>]`, or `fake:<fixture.can>`
        #[arg(long)]
        interface: String,
        #[arg(long = "block", value_name = "NAME:FILE")]
        blocks: Vec<String>,
        #[arg(long)]
        patch_cboot: bool,
    },
    /// Unlock ECU sample mode by flashing patch from FRF, ODX, or BIN
    Unlock {
        /// Firmware file (.frf, .odx, or .bin — auto-detected by extension)
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        module: String,
        /// Interface string: `socketcan:<ifname>`, `panda`, `j2534[:<dll>]`, or `fake:<fixture.can>`
        #[arg(long)]
        interface: String,
    },
    /// Read ECU data records
    ReadEcu {
        #[arg(long)]
        module: String,
        #[arg(long)]
        interface: String,
    },
    /// Read stored DTCs from the ECU
    ReadDtcs {
        #[arg(long)]
        module: String,
        #[arg(long)]
        interface: String,
    },
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive("mqb_flash=info".parse()?)
                .from_env_lossy(),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::DecryptFrf { file, outdir } => cmd_decrypt_frf(&file, &outdir),
        Commands::ExtractFrf { file, module, output } => {
            cmd_extract_frf(&file, &module, &output)
        }
        Commands::ExtractOdx { file, module, outdir } => {
            cmd_extract_odx(&file, &module, &outdir)
        }
        Commands::SplitBin { module, file, outdir } => cmd_split_bin(&module, &file, &outdir),
        Commands::CombineBin { module, blocks, output } => {
            cmd_combine_bin(&module, &blocks, &output)
        }
        Commands::Checksum { module, file, output, patch_cboot } => {
            cmd_checksum(&module, &file, &output, patch_cboot)
        }
        Commands::Flash { module, interface, blocks, patch_cboot } => {
            cmd_flash(&module, &interface, &blocks, patch_cboot).await
        }
        Commands::Unlock { file, module, interface } => {
            cmd_unlock(&file, &module, &interface).await
        }
        Commands::ReadEcu { module, interface } => cmd_read_ecu(&module, &interface).await,
        Commands::ReadDtcs { module, interface } => cmd_read_dtcs(&module, &interface).await,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_flash_info(module: &str) -> Result<&'static FlashInfo> {
    modules::get_flash_info(module).ok_or_else(|| {
        let valid = modules::module_names().join(", ");
        anyhow::anyhow!("Unknown module: '{module}'. Valid modules: {valid}")
    })
}

fn parse_block_args(block_args: &[String]) -> Result<HashMap<String, PathBuf>> {
    let mut blocks = HashMap::new();
    for arg in block_args {
        let (name, path_str) = arg.split_once(':').with_context(|| {
            format!("Block argument '{arg}' must be in 'NAME:PATH' format")
        })?;
        blocks.insert(name.to_owned(), PathBuf::from(path_str));
    }
    Ok(blocks)
}


// ── Command implementations ───────────────────────────────────────────────────

fn cmd_decrypt_frf(file: &Path, outdir: &Path) -> Result<()> {
    let encrypted = std::fs::read(file)
        .with_context(|| format!("Reading FRF file: {}", file.display()))?;
    let decrypted = mqb_frf::decrypt_frf(&encrypted);

    std::fs::create_dir_all(outdir)?;
    let stem = file.file_stem().unwrap_or_default();
    let out_path = outdir.join(format!("{}.zip", stem.to_string_lossy()));
    std::fs::write(&out_path, &decrypted)?;
    println!("Decrypted FRF written to: {}", out_path.display());
    Ok(())
}

fn cmd_extract_frf(file: &Path, module: &str, output: &Path) -> Result<()> {
    let flash_info = get_flash_info(module)?;
    let data = std::fs::read(file)
        .with_context(|| format!("Reading FRF: {}", file.display()))?;

    let frf_contents = mqb_frf::extract_frf(&data)
        .with_context(|| "Extracting FRF ZIP")?;

    let (_, odx_bytes) = frf_contents.iter()
        .find(|(k, _)| k.to_ascii_lowercase().ends_with(".odx"))
        .with_context(|| "FRF does not contain an ODX file (SGO format not yet supported)")?;

    let xml = std::str::from_utf8(odx_bytes)
        .with_context(|| "ODX entry is not valid UTF-8")?;
    let (odx_blocks, _boxcodes) = mqb_odx::extract_odx(xml, flash_info)
        .with_context(|| "Parsing ODX")?;

    anyhow::ensure!(!odx_blocks.is_empty(), "ODX contains no flash blocks");

    let mut blocks = HashMap::new();
    for (name, bytes) in odx_blocks {
        let block_num = flash_info.block_to_number(&name)
            .with_context(|| format!("Unknown ODX block '{name}'"))?;
        println!("{name}: {} bytes", bytes.len());
        blocks.insert(name.clone(), mqb_modules::BlockData::with_name(block_num, bytes, &name));
    }

    let bin = mqb_binfile::bin_from_blocks(&blocks, flash_info);
    std::fs::write(output, &bin)
        .with_context(|| format!("Writing {}", output.display()))?;
    println!("Written {} bytes to {}", bin.len(), output.display());
    Ok(())
}

fn cmd_extract_odx(file: &Path, module: &str, outdir: &Path) -> Result<()> {
    let flash_info = get_flash_info(module)?;
    let xml = std::fs::read_to_string(file)
        .with_context(|| format!("Reading ODX file: {}", file.display()))?;

    let (data_blocks, allowed_boxcodes) = mqb_odx::extract_odx(&xml, flash_info)
        .with_context(|| "Parsing ODX")?;

    println!("Allowed box codes: {}", allowed_boxcodes.join(", "));

    std::fs::create_dir_all(outdir)?;
    for (name, data) in &data_blocks {
        let out_path = outdir.join(format!("{name}.bin"));
        std::fs::write(&out_path, data)?;
        println!("Extracted: {} ({} bytes)", out_path.display(), data.len());
    }
    Ok(())
}

fn cmd_split_bin(module: &str, file: &Path, outdir: &Path) -> Result<()> {
    let flash_info = get_flash_info(module)?;
    let blocks = mqb_binfile::blocks_from_file(file, flash_info)
        .with_context(|| "Splitting binary")?;

    std::fs::create_dir_all(outdir)?;
    for (name, block) in &blocks {
        let out_path = outdir.join(format!("{name}.bin"));
        std::fs::write(&out_path, &block.block_bytes)?;
        println!("Block {}: {} ({} bytes)", block.block_number, out_path.display(), block.block_bytes.len());
    }
    Ok(())
}

fn cmd_combine_bin(module: &str, block_args: &[String], output: &Path) -> Result<()> {
    let flash_info = get_flash_info(module)?;
    let block_files = parse_block_args(block_args)?;

    let mut blocks = HashMap::new();
    for (name, path) in &block_files {
        let data = std::fs::read(path)
            .with_context(|| format!("Reading block file: {}", path.display()))?;
        let block_num = flash_info.block_to_number(name)
            .with_context(|| format!("Unknown block name: '{name}' for module '{module}'"))?;
        blocks.insert(
            name.clone(),
            mqb_modules::BlockData::with_name(block_num, data, name),
        );
    }

    let bin = mqb_binfile::bin_from_blocks(&blocks, flash_info);
    std::fs::write(output, &bin)?;
    println!("Written {} bytes to {}", bin.len(), output.display());
    Ok(())
}

fn cmd_checksum(module: &str, file: &Path, output: &Path, patch_cboot: bool) -> Result<()> {
    use mqb_checksum::{validate_dq381, validate_dsg, validate_haldex, validate_simos};
    use mqb_modules::{ChecksumKind, ChecksumState};

    let flash_info = get_flash_info(module)?;

    let mut data = std::fs::read(file)
        .with_context(|| format!("Reading binary: {}", file.display()))?;

    if patch_cboot {
        let block_num = flash_info.block_to_number("CBOOT")
            .ok_or_else(|| anyhow::anyhow!("Module '{module}' has no CBOOT block"))?;
        let offset = flash_info.binfile_offset(block_num)
            .ok_or_else(|| anyhow::anyhow!("No binfile offset for CBOOT block"))?;
        let length = flash_info.block_length(block_num)
            .ok_or_else(|| anyhow::anyhow!("No block length for CBOOT block"))?;
        let end = offset + length;
        anyhow::ensure!(end <= data.len(), "CBOOT block extends beyond binary");
        let patched = mqb_cboot::patch_cboot(&data[offset..end])
            .with_context(|| "CBOOT patch failed")?;
        data[offset..end].copy_from_slice(&patched);
        println!("CBOOT: sample mode patch applied");
    }

    let blocks = mqb_binfile::blocks_from_bytes(&data, flash_info);
    let mut any_failed = false;

    for (name, block) in &blocks {
        let block_num = block.block_number;

        let (state, fixed) = match flash_info.checksum_kind {
            ChecksumKind::Dq381 => {
                let base = mqb_modules::modules::dq381::BLOCK_BASE_ADDRESSES
                    .iter()
                    .find(|(n, _)| *n == block_num)
                    .map(|(_, a)| *a)
                    .unwrap_or(0);
                validate_dq381(&block.block_bytes, base, true)
            }
            ChecksumKind::Dsg => validate_dsg(&block.block_bytes, true),
            ChecksumKind::Haldex => validate_haldex(&block.block_bytes, block_num, flash_info, true),
            ChecksumKind::Simos => validate_simos(flash_info, &block.block_bytes, block_num, true),
        };

        match state {
            ChecksumState::Valid => println!("{name}: valid"),
            ChecksumState::Fixed => {
                println!("{name}: fixed");
                if let Some(offset) = flash_info.binfile_offset(block_num) {
                    let len = fixed.len().min(data.len().saturating_sub(offset));
                    data[offset..offset + len].copy_from_slice(&fixed[..len]);
                }
            }
            ChecksumState::Invalid => { any_failed = true; println!("{name}: invalid (could not fix)"); }
            ChecksumState::Failed  => { any_failed = true; println!("{name}: failed"); }
        }
    }

    if any_failed {
        bail!("One or more blocks could not be checksummed");
    }

    std::fs::write(output, &data)?;
    println!("Written {} bytes to {}", data.len(), output.display());
    Ok(())
}

async fn cmd_flash(
    module: &str,
    interface_str: &str,
    block_args: &[String],
    patch_cboot: bool,
) -> Result<()> {
    use mqb_modules::PreparedBlockData;

    let flash_info = get_flash_info(module)?;
    let interface: Interface = interface_str.parse().map_err(anyhow::Error::msg)?;
    let block_files = parse_block_args(block_args)?;

    // Load, compress, and encrypt each block
    let mut blocks: Vec<PreparedBlockData> = Vec::new();
    for (name, path) in &block_files {
        let data = std::fs::read(path)
            .with_context(|| format!("Reading block: {}", path.display()))?;
        let block_num = flash_info.block_to_number(name)
            .with_context(|| format!("Unknown block: '{name}'"))?;

        let encrypted = if block_num <= 5 {
            mqb_flash_uds::prepare_block_for_flash(&data, flash_info.crypto)
        } else {
            mqb_flash_uds::prepare_patch_for_flash(&data, flash_info.crypto)
        };

        blocks.push(PreparedBlockData {
            block_number: block_num,
            block_encrypted_bytes: encrypted,
            boxcode: String::new(),
            encryption_type: 0x0A,
            compression_type: 0x0A,
            should_erase: block_num <= 5,
            uds_checksum: flash_info.block_checksum(block_num).unwrap_or([0; 4]),
            block_name: name.clone(),
        });
    }

    // Flash in block-number order
    blocks.sort_by_key(|b| b.block_number);

    let opts = FlashOptions {
        interface,
        patch_cboot,
        stmin_override: None,
        workshop_code: [0x20, 0x04, 0x20, 0x42, 0x04, 0x20, 0x42, 0xB1, 0x3D],
        progress_tx: None,
    };

    mqb_flash_uds::flash_blocks(flash_info, blocks, opts).await
        .with_context(|| "Flash failed")?;

    Ok(())
}

async fn cmd_unlock(firmware_path: &Path, module: &str, interface_str: &str) -> Result<()> {
    use mqb_modules::PreparedBlockData;

    let flash_info = get_flash_info(module)?;
    let interface: Interface = interface_str.parse().map_err(anyhow::Error::msg)?;

    let patch_info = flash_info.patch_info.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Module '{module}' does not support unlock (no patch_info)"))?;

    // Extract raw block data — auto-detect file type by extension
    let raw_blocks = mqb_binfile::load_raw_blocks(firmware_path, flash_info)?;

    // Validate box code from CAL (block 5)
    let cal_bytes = raw_blocks.get(&5)
        .ok_or_else(|| anyhow::anyhow!("FRF does not contain CAL (block 5)"))?;

    let (box_start, box_end) = flash_info.box_code_location(5)
        .ok_or_else(|| anyhow::anyhow!("No box_code_location for block 5"))?;
    anyhow::ensure!(box_end <= cal_bytes.len(), "Box code range out of bounds in CAL block");

    let file_box_code = std::str::from_utf8(&cal_bytes[box_start..box_end])
        .with_context(|| "Box code bytes are not valid UTF-8")?
        .trim();

    let expected_prefix = patch_info.patch_box_code.split('_').next().unwrap_or("");
    if file_box_code != expected_prefix {
        bail!(
            "Box code mismatch: file has '{file_box_code}' but unlock patch requires '{expected_prefix}' \
             (full patch_box_code: '{}')",
            patch_info.patch_box_code
        );
    }
    println!("Box code validated: {file_box_code}");

    // Build blocks in unlock order: [1, 2, 3, 4, pbi+5, 5]
    let patch_block_num = patch_info.patch_block_index + 5;
    let normal_order: &[u8] = &[1, 2, 3, 4];

    let mut blocks: Vec<PreparedBlockData> = Vec::new();

    // Blocks 1–4
    for &block_num in normal_order {
        let raw = raw_blocks.get(&block_num)
            .ok_or_else(|| anyhow::anyhow!("FRF is missing block {block_num}"))?;
        let encrypted = mqb_flash_uds::prepare_block_for_flash(raw, flash_info.crypto);
        let name = flash_info.block_number_to_name(block_num)
            .unwrap_or("UNKNOWN")
            .to_owned();
        println!("Prepared block {block_num} ({name}): {} bytes compressed+encrypted", encrypted.len());
        blocks.push(PreparedBlockData {
            block_number: block_num,
            block_encrypted_bytes: encrypted,
            boxcode: String::new(),
            encryption_type: 0x0A,
            compression_type: 0x0A,
            should_erase: true,
            uds_checksum: flash_info.block_checksum(block_num).unwrap_or([0; 4]),
            block_name: name,
        });
    }

    // Patch block (pbi+5)
    let patch_encrypted = mqb_flash_uds::prepare_patch_for_flash(patch_info.patch_bytes, flash_info.crypto);
    println!("Prepared patch block {patch_block_num}: {} bytes encrypted", patch_encrypted.len());
    blocks.push(PreparedBlockData {
        block_number: patch_block_num,
        block_encrypted_bytes: patch_encrypted,
        boxcode: String::new(),
        encryption_type: 0x0A,
        compression_type: 0x0A,
        should_erase: false,
        uds_checksum: [0; 4],
        block_name: "UNLOCK_PATCH".to_owned(),
    });

    // CAL (block 5)
    let cal_encrypted = mqb_flash_uds::prepare_block_for_flash(cal_bytes, flash_info.crypto);
    println!("Prepared block 5 (CAL): {} bytes compressed+encrypted", cal_encrypted.len());
    blocks.push(PreparedBlockData {
        block_number: 5,
        block_encrypted_bytes: cal_encrypted,
        boxcode: file_box_code.to_owned(),
        encryption_type: 0x0A,
        compression_type: 0x0A,
        should_erase: true,
        uds_checksum: flash_info.block_checksum(5).unwrap_or([0; 4]),
        block_name: "CAL".to_owned(),
    });

    let opts = FlashOptions {
        interface,
        patch_cboot: false,
        stmin_override: None,
        workshop_code: [0x20, 0x04, 0x20, 0x42, 0x04, 0x20, 0x42, 0xB1, 0x3D],
        progress_tx: None,
    };

    mqb_flash_uds::flash_blocks(flash_info, blocks, opts).await
        .with_context(|| "Unlock flash failed")?;

    println!("Unlock complete");
    Ok(())
}

async fn cmd_read_ecu(module: &str, interface_str: &str) -> Result<()> {
    let flash_info = get_flash_info(module)?;
    let interface: Interface = interface_str.parse().map_err(anyhow::Error::msg)?;

    let data = mqb_flash_uds::read_ecu_data(flash_info, interface).await
        .with_context(|| "Reading ECU data")?;

    for (key, value) in &data {
        println!("{key}: {value}");
    }
    Ok(())
}

async fn cmd_read_dtcs(module: &str, interface_str: &str) -> Result<()> {
    let _flash_info = get_flash_info(module)?;
    let _interface: Interface = interface_str.parse().map_err(anyhow::Error::msg)?;
    println!("read-dtcs: not yet implemented");
    Ok(())
}
