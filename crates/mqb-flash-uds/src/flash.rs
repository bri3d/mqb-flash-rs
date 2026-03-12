//! UDS flash sequence implementation.
//!
//! Steps:
//! 0. OBD-II mode 04 (Clear DTCs) on 0x700 → 0x7E8 — required by VW ECUs before
//!    programming precondition; uses a separate ISO-TP channel, not the UDS channel.
//! 1. DiagnosticSessionControl → extended session (0x03)
//! 2. Read VIN (DID 0xF190)
//! 3. StartRoutine(0x0203) — check programming precondition
//! 4. TesterPresent
//! 5. DiagnosticSessionControl → programming session (0x02); SwitchPatch fallback
//! 6. TesterPresent
//! 7. SecurityAccess level 0x11/0x12 (SA2 seed-key)
//! 8. TesterPresent
//! 9. WriteDataByIdentifier(0xF15A) — workshop code
//! 10. TesterPresent
//! 11. Flash each block in caller-supplied order
//! 12. StartRoutine(0xFF01) — verify programming dependencies
//! 13. TesterPresent
//! 14. ECUReset — hard reset

use std::collections::HashMap;
use thiserror::Error;

use automotive::can::{AsyncCanAdapter, Identifier};
use automotive::isotp::{IsoTPAdapter, IsoTPConfig};
use automotive::uds::{RoutineControlType, UDSClient};
use automotive::{IsoTpTransport, StreamExt};

use mqb_modules::{BlockCrypto, FlashInfo, PreparedBlockData};
use mqb_sa2::Sa2Vm;

use crate::fake_adapter::FakeCanAdapter;
use crate::interface::Interface;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FlashError {
    #[error("UDS negative response: service={service}, code=0x{code:02X}")]
    NegativeResponse { service: String, code: u8 },
    #[error("Timeout waiting for ECU response")]
    Timeout,
    #[error("Interface error: {0}")]
    Interface(String),
    #[error("SA2 seed-key authentication failed")]
    AuthFailed,
    #[error("Block configuration error: {0}")]
    Config(String),
}

impl From<automotive::Error> for FlashError {
    fn from(e: automotive::Error) -> Self {
        match e {
            automotive::Error::Timeout => FlashError::Timeout,
            other => FlashError::Interface(other.to_string()),
        }
    }
}

// ── Progress reporting ────────────────────────────────────────────────────────

/// Progress events emitted during a flash sequence.
///
/// Sent via [`FlashOptions::progress_tx`] if one is configured.
#[derive(Debug, Clone)]
pub enum ProgressUpdate {
    /// Step 0: OBD-II DTC clear before programming.
    ClearingDtcs,
    /// Step 1: Opening extended diagnostic session.
    Connecting,
    /// VIN was read from the ECU.
    ReadVin { vin: String },
    /// Step 3: Checking programming precondition.
    CheckingPreconditions,
    /// Step 5: Upgrading to programming session.
    ProgrammingSession,
    /// Step 7: SA2 seed-key authentication.
    Authenticating,
    /// Step 9: Writing workshop code.
    WritingWorkshopCode,
    /// Starting to flash a block (overall progress).
    FlashingBlock { name: String, index: usize, total: usize },
    /// Sub-step: erasing the block.
    BlockErasing { name: String },
    /// Sub-step: requesting download.
    BlockDownloading { name: String },
    /// Sub-step: transfer data progress (bytes_sent / bytes_total).
    BlockTransferProgress { name: String, bytes_sent: usize, bytes_total: usize },
    /// Sub-step: verifying block checksum.
    BlockChecksum { name: String },
    /// Block finished.
    BlockComplete { index: usize },
    /// Step 12: Verifying programming dependencies.
    Verifying,
    /// Step 14: Resetting ECU.
    EcuReset,
    /// Flash sequence finished successfully.
    Complete,
    /// Flash sequence failed.
    Error(String),
}

// ── Options ───────────────────────────────────────────────────────────────────

/// Options for the flash operation.
#[derive(Debug, Clone)]
pub struct FlashOptions {
    /// Whether to apply the CBOOT patch (WriteWithoutErase mode).
    pub patch_cboot: bool,
    /// Physical interface to use.
    pub interface: Interface,
    /// Optional STmin override in microseconds.
    pub stmin_override: Option<u32>,
    /// 9-byte workshop code written to DID 0xF15A.
    pub workshop_code: [u8; 9],
    /// Optional channel for streaming progress updates to a caller.
    pub progress_tx: Option<tokio::sync::mpsc::UnboundedSender<ProgressUpdate>>,
}

// ── Block preparation helpers ─────────────────────────────────────────────────

/// LZSS-compress then AES-encrypt a raw binary block (normal blocks ≤ 5).
pub fn prepare_block_for_flash(data: &[u8], crypto: &dyn BlockCrypto) -> Vec<u8> {
    let compressed = mqb_lzss::encode(data, mqb_lzss::Padding::AesBlock);
    crypto.encrypt(&compressed)
}

/// AES-encrypt a raw binary without LZSS (for patch blocks > 5).
pub fn prepare_patch_for_flash(data: &[u8], crypto: &dyn BlockCrypto) -> Vec<u8> {
    crypto.encrypt(data)
}

// ── Windows timer resolution ─────────────────────────────────────────────────

/// RAII guard that sets the Windows multimedia timer resolution to 1 ms for the
/// duration of the flash sequence.  Without this, `std::thread::sleep` and
/// `tokio::time::sleep` on Windows quantize to the default system tick of
/// ~15.625 ms, making software ISO-TP (which sleeps for STmin between each
/// consecutive frame) roughly 30× slower than necessary.
///
/// On non-Windows platforms this is a no-op.
#[cfg(windows)]
struct HighResTimerGuard;

#[cfg(windows)]
impl HighResTimerGuard {
    fn activate() -> Self {
        #[link(name = "winmm")]
        extern "system" {
            fn timeBeginPeriod(uPeriod: u32) -> u32;
        }
        let ret = unsafe { timeBeginPeriod(1) };
        if ret == 0 {
            tracing::debug!("timeBeginPeriod(1) OK — timer resolution set to 1 ms");
        } else {
            tracing::warn!("timeBeginPeriod(1) returned {ret}");
        }
        Self
    }
}

#[cfg(windows)]
impl Drop for HighResTimerGuard {
    fn drop(&mut self) {
        #[link(name = "winmm")]
        extern "system" {
            fn timeEndPeriod(uPeriod: u32) -> u32;
        }
        let ret = unsafe { timeEndPeriod(1) };
        tracing::debug!("timeEndPeriod(1) returned {ret}");
    }
}

#[cfg(not(windows))]
struct HighResTimerGuard;

#[cfg(not(windows))]
impl HighResTimerGuard {
    fn activate() -> Self { Self }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Flash a set of prepared blocks to an ECU.
///
/// Blocks are flashed in the order provided by the caller — no internal
/// reordering is performed.  For normal flashing, sort by block number.
/// For unlock, provide blocks in unlock order: [1, 2, 3, 4, patch, 5].
pub async fn flash_blocks(
    flash_info: &FlashInfo,
    blocks: Vec<PreparedBlockData>,
    opts: FlashOptions,
) -> Result<(), FlashError> {
    // Raise timer resolution for the duration of the flash so that sub-ms
    // sleeps (STmin, process-loop yield) don't round up to 15.625 ms.
    let _timer_guard = HighResTimerGuard::activate();

    tracing::info!(
        interface = %opts.interface,
        project = flash_info.project_name,
        block_count = blocks.len(),
        "Starting flash sequence"
    );

    match &opts.interface {
        Interface::Fake(fixture_path) => {
            let fake = FakeCanAdapter::new(fixture_path.as_path())
                .map_err(|e| FlashError::Interface(format!("Fixture load error: {e}")))?;
            let adapter = AsyncCanAdapter::new(fake);
            run_with_adapter(&adapter, flash_info, &blocks, &opts).await
        }
        Interface::SocketCan(iface) => {
            flash_via_socketcan(iface, flash_info, &blocks, &opts).await
        }
        Interface::Panda => {
            flash_via_panda(flash_info, &blocks, &opts).await
        }
        Interface::J2534 { dll, bitrate, native_isotp } => {
            flash_via_j2534(dll.as_deref(), *bitrate, *native_isotp, flash_info, &blocks, &opts).await
        }
    }
}

// ── SocketCAN dispatch ────────────────────────────────────────────────────────

#[cfg(feature = "socketcan")]
async fn flash_via_socketcan(
    iface: &str,
    flash_info: &FlashInfo,
    blocks: &[PreparedBlockData],
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    let sc = automotive::socketcan::SocketCanAdapter::open(iface)
        .map_err(|e| FlashError::Interface(format!("SocketCAN open error: {e}")))?;
    let adapter = AsyncCanAdapter::new(sc);
    run_with_adapter(&adapter, flash_info, blocks, opts).await
}

#[cfg(not(feature = "socketcan"))]
async fn flash_via_socketcan(
    _iface: &str,
    _flash_info: &FlashInfo,
    _blocks: &[PreparedBlockData],
    _opts: &FlashOptions,
) -> Result<(), FlashError> {
    Err(FlashError::Interface(
        "SocketCAN support is not enabled. \
         Recompile with `--features mqb-flash-uds/socketcan` on Linux."
            .into(),
    ))
}

// ── Panda dispatch ────────────────────────────────────────────────────────────

async fn flash_via_panda(
    flash_info: &FlashInfo,
    blocks: &[PreparedBlockData],
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    let panda = automotive::panda::Panda::new()
        .map_err(|e| FlashError::Interface(format!("Panda open error: {e}")))?;
    let adapter = AsyncCanAdapter::new(panda);
    run_with_adapter(&adapter, flash_info, blocks, opts).await
}

// ── J2534 dispatch ────────────────────────────────────────────────────────────

#[cfg(feature = "j2534")]
async fn flash_via_j2534(
    dll: Option<&str>,
    bitrate: u32,
    native_isotp: bool,
    flash_info: &FlashInfo,
    blocks: &[PreparedBlockData],
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    if native_isotp {
        // Open the J2534 device once; the OBD DTC-clear channel and the main
        // flash channel share the same device handle so we never call
        // PassThruClose between channels (which disconnects the USB device
        // and prevents a subsequent PassThruOpen from succeeding).
        let mut device = automotive::j2534::open_device(dll)
            .map_err(|e| FlashError::Interface(format!("J2534 open error: {e}")))?;

        // VW ECUs require an OBD-II DTC clear before the programming
        // precondition check.  Open a temporary ISO 15765 channel on the
        // OBD-II IDs, send mode 04, then disconnect the channel (keeping
        // the device open) before opening the main flash channel.
        send_progress(opts, ProgressUpdate::ClearingDtcs);
        match automotive::j2534::J2534NativeIsoTpTransport::open_on_device(
            device, bitrate,
            Identifier::Standard(0x700),
            Identifier::Standard(0x7E8),
            None,
        ) {
            Ok(obd) => {
                send_obd_dtc_clear(&obd).await;
                // Disconnect the OBD channel and recover the device handle.
                device = tokio::task::spawn_blocking(move || obd.into_device())
                    .await
                    .map_err(|e| FlashError::Interface(format!("OBD channel teardown failed: {e}")))?;
            }
            Err((e, dev)) => {
                tracing::warn!("OBD DTC clear channel open failed: {e} (continuing)");
                device = dev;
            }
        }

        let tx_id = Identifier::from(flash_info.control_module_identifier.txid);
        let rx_id = Identifier::from(flash_info.control_module_identifier.rxid);
        let transport = automotive::j2534::J2534NativeIsoTpTransport::open_on_device(
            device,
            bitrate,
            tx_id,
            rx_id,
            opts.stmin_override,
        )
        .map_err(|(e, _dev)| FlashError::Interface(format!("J2534 ISO15765 open error: {e}")))?;
        let result = run_with_transport(&transport, flash_info, blocks, opts).await;

        // After the ECU reboots, clear emission DTCs again (best-effort).
        // Recover the device handle, open a temporary OBD channel, clear, then close.
        if result.is_ok() {
            let dev = tokio::task::spawn_blocking(move || transport.into_device())
                .await
                .map_err(|e| FlashError::Interface(format!("Flash channel teardown failed: {e}")))?;
            match automotive::j2534::J2534NativeIsoTpTransport::open_on_device(
                dev, bitrate,
                Identifier::Standard(0x700),
                Identifier::Standard(0x7E8),
                None,
            ) {
                Ok(obd) => {
                    send_obd_dtc_clear(&obd).await;
                    tokio::task::spawn_blocking(move || drop(obd));
                }
                Err((e, dev)) => {
                    tracing::warn!("Post-reset OBD DTC clear channel open failed: {e} (continuing)");
                    tokio::task::spawn_blocking(move || drop(dev));
                }
            }
        } else {
            tokio::task::spawn_blocking(move || drop(transport));
        }

        result
    } else {
        let j = automotive::j2534::J2534CanAdapter::open(dll, bitrate)
            .map_err(|e| FlashError::Interface(format!("J2534 open error: {e}")))?;
        let adapter = AsyncCanAdapter::new(j);
        let result = run_with_adapter(&adapter, flash_info, blocks, opts).await;
        tokio::task::spawn_blocking(move || drop(adapter));
        result
    }
}

#[cfg(not(feature = "j2534"))]
async fn flash_via_j2534(
    _dll: Option<&str>,
    _bitrate: u32,
    _native_isotp: bool,
    _flash_info: &FlashInfo,
    _blocks: &[PreparedBlockData],
    _opts: &FlashOptions,
) -> Result<(), FlashError> {
    Err(FlashError::Interface(
        "J2534 support is not enabled. \
         Recompile with `--features mqb-flash-uds/j2534`."
            .into(),
    ))
}

// ── ISO-TP config ─────────────────────────────────────────────────────────────

fn make_isotp_config(flash_info: &FlashInfo) -> IsoTPConfig {
    let mut config = IsoTPConfig::new_from_tx_rx(
        0,
        Identifier::from(flash_info.control_module_identifier.txid),
        Identifier::from(flash_info.control_module_identifier.rxid),
    );
    // Default is 100 ms; ECUs in programming mode can take several seconds to respond.
    config.timeout = std::time::Duration::from_secs(5);
    config
}

// ── Generic transport runner ──────────────────────────────────────────────────

/// Run the flash sequence over any [`IsoTpTransport`] implementation.
///
/// Used by both the software ISO-TP path (via [`run_with_adapter`]) and the
/// native J2534 ISO 15765 path.
async fn run_with_transport<T: IsoTpTransport>(
    transport: &T,
    flash_info: &FlashInfo,
    blocks: &[PreparedBlockData],
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    let uds = UDSClient::new(transport);
    run_flash_sequence(&uds, flash_info, blocks, opts).await
}

// ── Software ISO-TP adapter runner ────────────────────────────────────────────

/// Wrap a raw [`AsyncCanAdapter`] in software ISO-TP and call [`run_with_transport`].
async fn run_with_adapter(
    adapter: &AsyncCanAdapter,
    flash_info: &FlashInfo,
    blocks: &[PreparedBlockData],
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    // VW ECUs require an OBD-II DTC clear before programming precondition check.
    // This must be sent on a separate channel (0x700 → 0x7E8) before the UDS session.
    send_progress(opts, ProgressUpdate::ClearingDtcs);
    send_obd_dtc_clear_via_adapter(adapter).await;

    let mut config = make_isotp_config(flash_info);
    let stmin_us = opts.stmin_override.unwrap_or(500);
    config.separation_time_min = Some(std::time::Duration::from_micros(stmin_us as u64));
    let isotp = IsoTPAdapter::new(adapter, config);
    let result = run_with_transport(&isotp, flash_info, blocks, opts).await;

    // After the ECU reboots, clear emission DTCs again (best-effort).
    if result.is_ok() {
        send_obd_dtc_clear_via_adapter(adapter).await;
    }

    result
}

// ── Progress helper ───────────────────────────────────────────────────────────

fn send_progress(opts: &FlashOptions, update: ProgressUpdate) {
    if let Some(tx) = &opts.progress_tx {
        let _ = tx.send(update);
    }
}

// ── OBD-II DTC clear ──────────────────────────────────────────────────────────

/// Send OBD-II mode 04 (Clear Emission-Related DTCs) using the supplied transport.
///
/// Sends the single byte `0x04` as an ISO-TP PDU and waits for the positive
/// response (`0x44`).  The ECU may send one or more NRC 0x78
/// (requestCorrectlyReceivedResponsePending) before the final answer — these
/// are consumed transparently.  Each pending response resets the 5 s timeout.
/// Errors and timeouts are logged and ignored — a failed DTC clear must not
/// abort the flash sequence.
async fn send_obd_dtc_clear<T: IsoTpTransport>(transport: &T) {
    tracing::info!("Sending OBD-II mode 04 (Clear DTCs) [tester=0x700, ECU=0x7E8]");
    if let Err(e) = transport.send(&[0x04]).await {
        tracing::warn!("OBD DTC clear send failed: {e} (continuing)");
        return;
    }
    let mut stream = transport.recv();
    let timeout = std::time::Duration::from_secs(5);
    loop {
        match tokio::time::timeout(timeout, stream.next()).await {
            Ok(Some(Ok(resp))) => {
                // NRC 0x78 = responsePending: ECU is still processing, keep waiting.
                if resp.len() >= 3 && resp[0] == 0x7F && resp[2] == 0x78 {
                    tracing::debug!("OBD DTC clear: response pending (NRC 0x78), waiting…");
                    continue;
                }
                tracing::debug!("OBD DTC clear response: {:02X?}", resp);
                return;
            }
            Ok(Some(Err(e))) => {
                tracing::debug!("OBD DTC clear: response error {e} (OK)");
                return;
            }
            Ok(None) => {
                tracing::debug!("OBD DTC clear: stream ended");
                return;
            }
            Err(_) => {
                tracing::debug!("OBD DTC clear: no response within {} s (OK)", timeout.as_secs());
                return;
            }
        }
    }
}

/// Convenience wrapper for CAN-adapter–based paths.
///
/// Creates a temporary [`IsoTPAdapter`] on the shared adapter with the
/// fixed OBD-II IDs (tester TX = 0x700, ECU RX = 0x7E8), calls
/// [`send_obd_dtc_clear`], then discards the adapter.
async fn send_obd_dtc_clear_via_adapter(adapter: &AsyncCanAdapter) {
    let mut config = IsoTPConfig::new_from_tx_rx(
        0,
        Identifier::from(0x700u32),
        Identifier::from(0x7E8u32),
    );
    config.timeout = std::time::Duration::from_secs(2);
    let isotp = IsoTPAdapter::new(adapter, config);
    send_obd_dtc_clear(&isotp).await;
}

// ── Core flash sequence ───────────────────────────────────────────────────────

async fn run_flash_sequence<T: IsoTpTransport>(
    uds: &UDSClient<'_, T>,
    flash_info: &FlashInfo,
    blocks: &[PreparedBlockData],
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    // 1. Extended diagnostic session
    send_progress(opts, ProgressUpdate::Connecting);
    tracing::info!("Opening extended diagnostic session");
    uds.diagnostic_session_control(0x03).await?;

    // 2. Read VIN
    let vin = match uds.read_data_by_identifier(0xF190).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => {
            tracing::warn!(err = %e, "VIN read failed");
            "(unknown)".to_owned()
        }
    };
    tracing::info!(%vin, "Connected");
    send_progress(opts, ProgressUpdate::ReadVin { vin });

    // 3. Check programming precondition
    send_progress(opts, ProgressUpdate::CheckingPreconditions);
    tracing::info!("Checking programming precondition (0x0203)");
    uds.routine_control(RoutineControlType::Start, 0x0203, None).await?;

    // 4. TesterPresent before session upgrade
    uds.tester_present().await?;

    // 5. Upgrade to programming session
    //    SwitchPatch fallback: if the normal request is refused, send `3E 10 02`
    //    (a CBOOT-patch trick that bypasses session conditions).
    send_progress(opts, ProgressUpdate::ProgrammingSession);
    tracing::info!("Upgrading to programming session");
    if let Err(e) = uds.diagnostic_session_control(0x02).await {
        tracing::warn!("Normal programming session request failed ({e}), trying SwitchPatch");
        uds.request(0x3E, None, Some(&[0x10, 0x02])).await
            .map_err(|_| e)?;  // surface original error if fallback also fails
    }

    // 6. TesterPresent
    uds.tester_present().await?;

    // 7. Security access — SA2 seed-key at level 0x11
    send_progress(opts, ProgressUpdate::Authenticating);
    tracing::info!("Performing SA2 seed-key authentication");
    let seed_bytes = uds.security_access(0x11, None).await?;
    if seed_bytes.len() < 4 {
        return Err(FlashError::AuthFailed);
    }
    let seed = mqb_bytes::read_u32_be(&seed_bytes, 0);
    let vm  = Sa2Vm::new(flash_info.sa2_script);
    let key  = vm.execute(seed);
    tracing::debug!("SA2: seed=0x{seed:08X}, key=0x{key:08X}");
    let key_bytes = key.to_be_bytes();
    uds.security_access(0x12, Some(&key_bytes)).await
        .map_err(|_| FlashError::AuthFailed)?;

    // 8. TesterPresent
    uds.tester_present().await?;

    // 9. Write workshop code
    send_progress(opts, ProgressUpdate::WritingWorkshopCode);
    tracing::info!("Writing workshop code to DID 0xF15A");
    uds.write_data_by_identifier(0xF15A, &opts.workshop_code).await?;

    // 10. TesterPresent
    uds.tester_present().await?;

    // 11. Flash blocks in caller-supplied order
    let total = blocks.len();
    for (index, block) in blocks.iter().enumerate() {
        send_progress(opts, ProgressUpdate::FlashingBlock {
            name: block.block_name.clone(),
            index,
            total,
        });
        if block.block_number <= 5 {
            flash_normal_block(uds, flash_info, block, opts).await?;
        } else {
            flash_patch_block(uds, flash_info, block, opts).await?;
        }
        send_progress(opts, ProgressUpdate::BlockComplete { index });
        uds.tester_present().await?;
    }

    // 12. Verify programming dependencies
    send_progress(opts, ProgressUpdate::Verifying);
    tracing::info!("Verifying programming dependencies (0xFF01)");
    uds.routine_control(RoutineControlType::Start, 0xFF01, None).await?;

    // 13. TesterPresent
    uds.tester_present().await?;

    // 14. Wait for the ECU to finish internal verification (e.g. patched periodic
    //     tasks) before issuing the hard reset.
    tracing::info!("Waiting 5 s for ECU internal verification…");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // 15. ECU reset — the ECU hard-resets immediately and typically does not
    //     send a response before power-cycling, so a timeout is expected and OK.
    send_progress(opts, ProgressUpdate::EcuReset);
    tracing::info!("Resetting ECU");
    match uds.ecu_reset(0x01).await {
        Ok(_) => {}
        Err(automotive::Error::Timeout) => {
            tracing::debug!("ECUReset: no response received (expected — ECU is rebooting)");
        }
        Err(e) => return Err(FlashError::from(e)),
    }

    tracing::info!("Flash sequence complete");
    Ok(())
}

// ── Normal block (1–5) ────────────────────────────────────────────────────────

async fn flash_normal_block<T: IsoTpTransport>(
    uds: &UDSClient<'_, T>,
    flash_info: &FlashInfo,
    block: &PreparedBlockData,
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    let block_id = flash_info
        .block_identifier(block.block_number)
        .ok_or_else(|| FlashError::Config(format!("No block_identifier for block {}", block.block_number)))?;

    tracing::info!(
        block = block.block_number,
        name  = %block.block_name,
        bytes = block.block_encrypted_bytes.len(),
        "Flashing block"
    );

    // Erase
    if block.should_erase {
        send_progress(opts, ProgressUpdate::BlockErasing { name: block.block_name.clone() });
        tracing::debug!(block = block.block_number, "Erasing (0xFF00)");
        uds.routine_control(
            RoutineControlType::Start,
            0xFF00,
            Some(&[0x01, block_id]),
        ).await?;
    }

    // Request download: 1-byte address (block_id), 4-byte size (uncompressed block length)
    let block_len = flash_info
        .block_length(block.block_number)
        .ok_or_else(|| FlashError::Config(format!("No block_length for block {}", block.block_number)))?;
    let size_be = (block_len as u32).to_be_bytes();

    send_progress(opts, ProgressUpdate::BlockDownloading { name: block.block_name.clone() });
    tracing::debug!(block = block.block_number, "RequestDownload");
    let max_chunk = uds.request_download(
        block.compression_type,
        block.encryption_type,
        &[block_id],
        &size_be,
    ).await?;

    // Transfer data
    let transfer_size = flash_info
        .block_transfer_size(block.block_number)
        .unwrap_or(0xFFD)
        .min(max_chunk);

    tracing::debug!(
        block = block.block_number,
        data_len = block.block_encrypted_bytes.len(),
        chunk = transfer_size,
        "TransferData"
    );

    let data = &block.block_encrypted_bytes;
    let data_len = data.len();
    let mut counter: u8 = 1;
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + transfer_size).min(data.len());
        uds.transfer_data(counter, Some(&data[offset..end])).await?;
        counter = counter.wrapping_add(1);
        offset = end;
        send_progress(opts, ProgressUpdate::BlockTransferProgress {
            name: block.block_name.clone(),
            bytes_sent: offset,
            bytes_total: data_len,
        });
    }

    // Exit transfer
    uds.request_transfer_exit(None).await?;

    // Checksum routine: data = [0x01, block_id, 0x00, 0x04, <4-byte UDS checksum>]
    send_progress(opts, ProgressUpdate::BlockChecksum { name: block.block_name.clone() });
    let mut checksum_data = vec![0x01u8, block_id, 0x00, 0x04];
    checksum_data.extend_from_slice(&block.uds_checksum);
    tracing::debug!(block = block.block_number, "Checksum routine (0x0202)");
    uds.routine_control(
        RoutineControlType::Start,
        0x0202,
        Some(&checksum_data),
    ).await?;

    tracing::info!(block = block.block_number, "Block flashed successfully");
    Ok(())
}

// ── Patch block (>5, WriteWithoutErase) ───────────────────────────────────────

const MAX_PATCH_RETRIES: usize = 10;

async fn flash_patch_block<T: IsoTpTransport>(
    uds: &UDSClient<'_, T>,
    flash_info: &FlashInfo,
    block: &PreparedBlockData,
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    // Patch block N+5 targets actual block N (e.g. block 7 → target block 2).
    let target_num = block.block_number - 5;

    tracing::info!(
        patch_block = block.block_number,
        target_block = target_num,
        "Patching block (WriteWithoutErase)"
    );

    // Step 1: Erase CAL (block 5) before patching
    send_progress(opts, ProgressUpdate::BlockErasing { name: block.block_name.clone() });
    let cal_id = flash_info
        .block_identifier(5)
        .ok_or_else(|| FlashError::Config("No block_identifier for CAL (block 5)".into()))?;
    uds.routine_control(
        RoutineControlType::Start,
        0xFF00,
        Some(&[0x01, cal_id]),
    ).await?;

    // Step 2: RequestDownload for the target block; encryption 0xA, compression 0x0
    send_progress(opts, ProgressUpdate::BlockDownloading { name: block.block_name.clone() });
    let block_len = flash_info
        .block_length(target_num)
        .ok_or_else(|| FlashError::Config(format!("No block_length for target block {target_num}")))?;
    let size_be = (block_len as u32).to_be_bytes();

    uds.request_download(
        0x00,  // no compression
        0x0A,  // AES encryption
        &[target_num],
        &size_be,
    ).await?;

    // Step 3: Transfer with variable chunk sizes from patch_info, with retry on negative response
    let patch_info = flash_info.patch_info.as_ref()
        .ok_or_else(|| FlashError::Config("No patch_info for this ECU".into()))?;

    let data = &block.block_encrypted_bytes;
    let data_len = data.len();
    let mut counter: u8 = 1;
    let mut offset = 0;
    while offset < data.len() {
        let chunk_size = (patch_info.block_transfer_size_fn)(target_num, offset);
        let end = (offset + chunk_size).min(data.len());
        let mut success = false;
        for attempt in 0..MAX_PATCH_RETRIES {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            match uds.transfer_data(counter, Some(&data[offset..end])).await {
                Ok(_) => {
                    counter = counter.wrapping_add(1);
                    success = true;
                    break;
                }
                Err(_) if attempt + 1 < MAX_PATCH_RETRIES => {
                    tracing::debug!(attempt, offset, "Patch TransferData retry");
                    counter = counter.wrapping_add(1);
                }
                Err(e) => return Err(FlashError::from(e)),
            }
        }
        if !success {
            return Err(FlashError::Config("Patch TransferData retries exhausted".into()));
        }
        offset = end;
        send_progress(opts, ProgressUpdate::BlockTransferProgress {
            name: block.block_name.clone(),
            bytes_sent: offset,
            bytes_total: data_len,
        });
    }

    // Step 4: Exit transfer (no checksum for patch blocks)
    uds.request_transfer_exit(None).await?;

    tracing::info!(target_block = target_num, "Patch complete");
    Ok(())
}

// ── Read ECU data ─────────────────────────────────────────────────────────────

/// Read ECU data records from a connected ECU.
pub async fn read_ecu_data(
    flash_info: &FlashInfo,
    interface: Interface,
) -> Result<HashMap<String, String>, FlashError> {
    tracing::info!(interface = %interface, "Reading ECU data");

    match &interface {
        Interface::Fake(fixture_path) => {
            let fake = FakeCanAdapter::new(fixture_path.as_path())
                .map_err(|e| FlashError::Interface(format!("Fixture load error: {e}")))?;
            let adapter = AsyncCanAdapter::new(fake);
            read_ecu_with_adapter(&adapter, flash_info).await
        }
        Interface::SocketCan(iface) => {
            read_ecu_via_socketcan(iface, flash_info).await
        }
        Interface::Panda => {
            let panda = automotive::panda::Panda::new()
                .map_err(|e| FlashError::Interface(format!("Panda open error: {e}")))?;
            let adapter = AsyncCanAdapter::new(panda);
            read_ecu_with_adapter(&adapter, flash_info).await
        }
        Interface::J2534 { dll, bitrate, native_isotp } => {
            read_ecu_via_j2534(dll.as_deref(), *bitrate, *native_isotp, flash_info).await
        }
    }
}

#[cfg(feature = "j2534")]
async fn read_ecu_via_j2534(
    dll: Option<&str>,
    bitrate: u32,
    native_isotp: bool,
    flash_info: &FlashInfo,
) -> Result<HashMap<String, String>, FlashError> {
    if native_isotp {
        let tx_id = Identifier::from(flash_info.control_module_identifier.txid);
        let rx_id = Identifier::from(flash_info.control_module_identifier.rxid);
        let transport = automotive::j2534::J2534NativeIsoTpTransport::open(
            dll,
            bitrate,
            tx_id,
            rx_id,
            None, // no stmin override needed for read-only ECU data queries
        )
        .map_err(|e| FlashError::Interface(format!("J2534 ISO15765 open error: {e}")))?;
        let result = read_ecu_with_transport(&transport).await;
        // Drop on a blocking thread so the J2534 thread joins don't block
        // the async runtime (which would freeze the GUI for seconds).
        tokio::task::spawn_blocking(move || drop(transport));
        result
    } else {
        let j = automotive::j2534::J2534CanAdapter::open(dll, bitrate)
            .map_err(|e| FlashError::Interface(format!("J2534 open error: {e}")))?;
        let adapter = AsyncCanAdapter::new(j);
        let result = read_ecu_with_adapter(&adapter, flash_info).await;
        tokio::task::spawn_blocking(move || drop(adapter));
        result
    }
}

#[cfg(not(feature = "j2534"))]
async fn read_ecu_via_j2534(
    _dll: Option<&str>,
    _bitrate: u32,
    _native_isotp: bool,
    _flash_info: &FlashInfo,
) -> Result<HashMap<String, String>, FlashError> {
    Err(FlashError::Interface(
        "J2534 support is not enabled. \
         Recompile with `--features mqb-flash-uds/j2534`."
            .into(),
    ))
}

#[cfg(feature = "socketcan")]
async fn read_ecu_via_socketcan(
    iface: &str,
    flash_info: &FlashInfo,
) -> Result<HashMap<String, String>, FlashError> {
    let sc = automotive::socketcan::SocketCanAdapter::open(iface)
        .map_err(|e| FlashError::Interface(format!("SocketCAN open error: {e}")))?;
    let adapter = AsyncCanAdapter::new(sc);
    read_ecu_with_adapter(&adapter, flash_info).await
}

#[cfg(not(feature = "socketcan"))]
async fn read_ecu_via_socketcan(
    _iface: &str,
    _flash_info: &FlashInfo,
) -> Result<HashMap<String, String>, FlashError> {
    Err(FlashError::Interface(
        "SocketCAN support is not enabled. \
         Recompile with `--features mqb-flash-uds/socketcan` on Linux."
            .into(),
    ))
}

async fn read_ecu_with_adapter(
    adapter: &AsyncCanAdapter,
    flash_info: &FlashInfo,
) -> Result<HashMap<String, String>, FlashError> {
    let isotp = IsoTPAdapter::new(adapter, make_isotp_config(flash_info));
    read_ecu_with_transport(&isotp).await
}

async fn read_ecu_with_transport<T: IsoTpTransport>(
    transport: &T,
) -> Result<HashMap<String, String>, FlashError> {
    let uds = UDSClient::new(transport);

    uds.diagnostic_session_control(0x03).await?;

    let mut result = HashMap::new();
    for record in mqb_modules::DATA_RECORDS {
        match uds.read_data_by_identifier(record.address).await {
            Ok(bytes) => {
                let value = if record.parse_type == 0 {
                    String::from_utf8_lossy(&bytes).into_owned()
                } else {
                    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
                };
                result.insert(record.description.to_owned(), value);
            }
            Err(e) => {
                tracing::debug!("DID 0x{:04X} ({}) error: {e}", record.address, record.description);
            }
        }
    }
    Ok(result)
}
