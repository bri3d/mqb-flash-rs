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
use automotive::{StreamExt, TransportLayer};

use mqb_modules::{FlashInfo, PreparedBlockData};
use mqb_sa2::Sa2Vm;

use mqb_transport::Interface;

use crate::session::{clear_obd_dtcs, obd_clear_needs_own_device, Session};

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
    /// What that clear did, whether or not it worked.
    DtcsCleared(DtcClearOutcome),
    /// Step 1: Opening extended diagnostic session.
    Connecting,
    /// VIN was read from the ECU.
    ReadVin { vin: String },
    /// Step 3: Checking programming precondition.
    CheckingPreconditions,
    /// Step 5: Upgrading to programming session.
    ProgrammingSession,
    /// The normal programming-session request was refused and the SwitchPatch
    /// fallback (`3E 10 02`) was accepted.
    ///
    /// **Not** evidence that the ECU is unlocked: this tool does not apply
    /// SwitchPatch, so the fallback's success says nothing about our CBOOT
    /// sample-mode patch. Unlock state comes from
    /// [`crate::unlock::probe_unlock_state`].
    SwitchPatchUsed,
    /// Step 7: SA2 seed-key authentication.
    Authenticating,
    /// Step 9: Writing workshop code.
    WritingWorkshopCode,
    /// Starting to flash a block (overall progress).
    FlashingBlock {
        name: String,
        index: usize,
        total: usize,
    },
    /// Sub-step: erasing the block.
    BlockErasing { name: String },
    /// Sub-step: requesting download.
    BlockDownloading { name: String },
    /// Sub-step: transfer data progress (bytes_sent / bytes_total).
    BlockTransferProgress {
        name: String,
        bytes_sent: usize,
        bytes_total: usize,
    },
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

// Block preparation lives in `crate::prepare` — it is per-module policy, not
// protocol, and both the CLI and the GUI need it without a transport.

// ── Windows timer resolution ─────────────────────────────────────────────────

/// Raises the Windows multimedia timer resolution to 1 ms for the duration of
/// the flash. Without it, `sleep` quantizes to the ~15.625 ms system tick,
/// making software ISO-TP (which sleeps for STmin between consecutive frames)
/// roughly 30× slower than necessary. No-op on other platforms.
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
    fn activate() -> Self {
        Self
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Flash a set of prepared blocks to an ECU.
///
/// Blocks are flashed in the order provided — no internal reordering. Sort by
/// block number for a normal flash; for unlock use [1, 2, 3, 4, patch, 5].
///
/// Opens and closes the connection. Callers doing several operations should
/// open a [`Session`] once and call [`Session::flash_blocks`] instead.
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

    // The DTC clear is step 0 of the process, not of the session: on the
    // hardware ISO 15765 path it needs its own channel and the driver will not
    // open the device while the flash channel holds it, so it runs before the
    // session is opened and after it is closed.
    let own_device = obd_clear_needs_own_device(&opts.interface);
    send_progress(&opts, ProgressUpdate::ClearingDtcs);
    if own_device {
        let outcome = clear_obd_dtcs(&opts.interface).await;
        send_progress(&opts, ProgressUpdate::DtcsCleared(outcome));
    }

    let session = Session::open(&opts.interface, flash_info, opts.stmin_override)?;
    if !own_device {
        // Raw CAN: one adapter carries both ID pairs.
        let outcome = session.clear_obd_dtcs().await;
        send_progress(&opts, ProgressUpdate::DtcsCleared(outcome));
    }

    let result = session.flash_blocks(flash_info, &blocks, &opts).await;

    // Clear again after the reboot, under the same ordering rule.
    if result.is_ok() && !own_device {
        let outcome = session.clear_obd_dtcs().await;
        send_progress(&opts, ProgressUpdate::DtcsCleared(outcome));
    }
    session.close().await;
    if result.is_ok() && own_device {
        let outcome = clear_obd_dtcs(&opts.interface).await;
        send_progress(&opts, ProgressUpdate::DtcsCleared(outcome));
    }

    result
}

// ── ISO-TP config ─────────────────────────────────────────────────────────────

/// Response timeout for an ECU that is known to be there.
///
/// The upstream default is 100 ms. Erasing a 1 MB ASW block, or the block
/// checksum routine, can run for many seconds between response-pending frames.
pub const FLASH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Response timeout for finding out *whether* an ECU is there.
///
/// A scan walks three channels and normally finds one; [`FLASH_TIMEOUT`] would
/// charge 30 s of dead time per silent address, which reads as a hang. One
/// second is still a wide margin over UDS P2_server (50 ms nominal), and
/// `UDSClient` gives every responsePending a fresh window, so a slow-but-present
/// module is not cut off — only a silent address is.
pub const IDENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// ISO-TP configuration for a module's diagnostic channel.
///
/// `pub` so the wizard can open one transport and reuse it across
/// identification, immobilizer pre-flight and flashing.
pub fn make_isotp_config(flash_info: &FlashInfo) -> IsoTPConfig {
    make_isotp_config_with_timeout(flash_info, FLASH_TIMEOUT)
}

/// [`make_isotp_config`] with an explicit response timeout.
///
/// Separate because how long to wait is a property of the *question* being
/// asked, not of the module: see [`FLASH_TIMEOUT`] and [`IDENT_TIMEOUT`].
pub fn make_isotp_config_with_timeout(
    flash_info: &FlashInfo,
    timeout: std::time::Duration,
) -> IsoTPConfig {
    let mut config = IsoTPConfig::new_from_tx_rx(
        0,
        Identifier::from(flash_info.control_module_identifier.txid),
        Identifier::from(flash_info.control_module_identifier.rxid),
    );
    config.timeout = timeout;
    // VW testers pad with 0x55. The upstream default is 0xAA.
    config.padding = Some(TX_PADDING_BYTE);
    config
}

/// ISO-TP TX padding byte used by the VW tester on every connection.
const TX_PADDING_BYTE: u8 = 0x55;

// ── Generic transport runner ──────────────────────────────────────────────────

/// Run the flash sequence over any [`TransportLayer`] implementation.
///
/// Used by both the software ISO-TP path (via [`run_with_adapter`]) and the
/// native J2534 ISO 15765 path.
pub(crate) async fn run_with_transport<T: TransportLayer>(
    transport: &T,
    flash_info: &FlashInfo,
    blocks: &[PreparedBlockData],
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    let uds = UDSClient::new(transport);
    run_flash_sequence(&uds, transport, flash_info, blocks, opts).await
}

/// Send the SwitchPatch programming-session request (`3E 10 02`) raw.
///
/// This cannot go through [`UDSClient`]: a patched ASW answers with `50 02 …`,
/// but `UDSClient` would enforce a `0x7E` echo for a `0x3E` request and reject
/// it as `InvalidServiceId`. Both `0x7E` and `0x50` are accepted here.
pub(crate) async fn send_switchpatch<T: TransportLayer>(transport: &T) -> Result<(), FlashError> {
    // Subscribe before sending — see `send_obd_dtc_clear`.
    let mut stream = transport.recv();
    transport
        .send(&[0x3E, 0x10, 0x02])
        .await
        .map_err(FlashError::from)?;

    let timeout = std::time::Duration::from_secs(5);
    loop {
        match tokio::time::timeout(timeout, stream.next()).await {
            Ok(Some(Ok(resp))) if resp.is_empty() => continue,
            Ok(Some(Ok(resp))) => {
                // responsePending — keep waiting, refreshing the timeout.
                if resp.len() >= 3 && resp[0] == 0x7F && resp[2] == 0x78 {
                    continue;
                }
                return match resp[0] {
                    0x7E | 0x50 => {
                        tracing::info!("SwitchPatch accepted (response SID 0x{:02X})", resp[0]);
                        Ok(())
                    }
                    0x7F => Err(FlashError::NegativeResponse {
                        service: "SwitchPatch (3E 10 02)".into(),
                        code: *resp.get(2).unwrap_or(&0),
                    }),
                    other => Err(FlashError::Interface(format!(
                        "SwitchPatch: unexpected response SID 0x{other:02X}"
                    ))),
                };
            }
            Ok(Some(Err(e))) => return Err(FlashError::Interface(e.to_string())),
            Ok(None) => return Err(FlashError::Timeout),
            Err(_) => return Err(FlashError::Timeout),
        }
    }
}

// ── Progress helper ───────────────────────────────────────────────────────────

pub(crate) fn send_progress(opts: &FlashOptions, update: ProgressUpdate) {
    if let Some(tx) = &opts.progress_tx {
        let _ = tx.send(update);
    }
}

// ── OBD-II DTC clear ──────────────────────────────────────────────────────────

/// The OBD-II tester address used for the emission DTC clear.
pub(crate) const OBD_TESTER_ID: u32 = 0x700;
/// The OBD-II ECU address used for the emission DTC clear.
pub(crate) const OBD_ECU_ID: u32 = 0x7E8;

/// What the OBD-II emission DTC clear did.
///
/// Best effort — a failure never aborts a flash — but never silent: an ECU
/// refuses the programming precondition (`0x0203`) with conditionsNotCorrect
/// while emission DTCs are stored, so a clear that did not happen is the usual
/// cause of a flash that will not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtcClearOutcome {
    /// The ECU answered `0x44`.
    Cleared,
    /// The ECU answered a negative response other than `0x78`.
    Refused { nrc: u8 },
    /// Something answered, but not to the service we asked about.
    Unexpected(Vec<u8>),
    /// Nothing answered before the timeout.
    Silent,
    /// The clear could not be sent at all — no channel, or the send failed.
    Failed(String),
}

impl std::fmt::Display for DtcClearOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DtcClearOutcome::Cleared => write!(f, "emission DTCs cleared"),
            DtcClearOutcome::Refused { nrc } => {
                write!(f, "the ECU refused the DTC clear (NRC 0x{nrc:02X})")
            }
            DtcClearOutcome::Unexpected(resp) => {
                write!(f, "unexpected answer to the DTC clear: {resp:02X?}")
            }
            DtcClearOutcome::Silent => write!(f, "no answer to the DTC clear"),
            DtcClearOutcome::Failed(why) => write!(f, "could not send the DTC clear: {why}"),
        }
    }
}

impl DtcClearOutcome {
    /// Whether the ECU confirmed the clear.
    pub fn is_cleared(&self) -> bool {
        matches!(self, DtcClearOutcome::Cleared)
    }
}

/// Send OBD-II mode 04 (Clear Emission-Related DTCs) over the supplied transport.
///
/// Sends `0x04` and waits for `0x44`. NRC 0x78 (responsePending) is consumed
/// transparently, each one resetting the 5 s timeout: ECUs commonly send
/// `7F 04 78` first, and consuming only one response would leak the `44` into
/// whatever runs next.
pub(crate) async fn send_obd_dtc_clear<T: TransportLayer>(transport: &T) -> DtcClearOutcome {
    tracing::info!(
        "Sending OBD-II mode 04 (Clear DTCs) [tester=0x{OBD_TESTER_ID:03X}, ECU=0x{OBD_ECU_ID:03X}]"
    );
    // Subscribe before sending: the receive stream is a broadcast subscription
    // and does not replay, so a response that arrives before this point is lost.
    let mut stream = transport.recv();
    if let Err(e) = transport.send(&[0x04]).await {
        return DtcClearOutcome::Failed(e.to_string());
    }
    let timeout = std::time::Duration::from_secs(5);
    loop {
        let outcome = match tokio::time::timeout(timeout, stream.next()).await {
            Ok(Some(Ok(resp))) => {
                // NRC 0x78 = responsePending: ECU is still processing, keep waiting.
                if resp.len() >= 3 && resp[0] == 0x7F && resp[2] == 0x78 {
                    tracing::debug!("OBD DTC clear: response pending (NRC 0x78), waiting…");
                    continue;
                }
                tracing::debug!("OBD DTC clear response: {:02X?}", resp);
                match resp.first() {
                    Some(0x44) => DtcClearOutcome::Cleared,
                    Some(0x7F) if resp.len() >= 3 && resp[1] == 0x04 => {
                        DtcClearOutcome::Refused { nrc: resp[2] }
                    }
                    _ => DtcClearOutcome::Unexpected(resp),
                }
            }
            Ok(Some(Err(e))) => DtcClearOutcome::Failed(e.to_string()),
            Ok(None) => DtcClearOutcome::Failed("the transport closed".to_owned()),
            Err(_) => DtcClearOutcome::Silent,
        };
        if outcome.is_cleared() {
            tracing::info!("{outcome}");
        } else {
            // Not an error, but it explains a conditionsNotCorrect later on.
            tracing::warn!("{outcome}");
        }
        return outcome;
    }
}

/// Convenience wrapper for CAN-adapter–based paths: builds a temporary
/// [`IsoTPAdapter`] on the fixed OBD-II IDs (TX 0x700, RX 0x7E8), calls
/// [`send_obd_dtc_clear`], then discards it.
pub(crate) async fn send_obd_dtc_clear_via_adapter(adapter: &AsyncCanAdapter) -> DtcClearOutcome {
    let mut config = IsoTPConfig::new_from_tx_rx(
        0,
        Identifier::from(OBD_TESTER_ID),
        Identifier::from(OBD_ECU_ID),
    );
    config.timeout = std::time::Duration::from_secs(2);
    let isotp = IsoTPAdapter::new(adapter, config);
    send_obd_dtc_clear(&isotp).await
}

// ── Core flash sequence ───────────────────────────────────────────────────────

async fn run_flash_sequence<T: TransportLayer>(
    uds: &UDSClient<'_, T>,
    transport: &T,
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
    uds.routine_control(RoutineControlType::Start, 0x0203, None)
        .await?;

    // 4. TesterPresent before session upgrade
    uds.tester_present().await?;

    // 5. Upgrade to programming session
    //    SwitchPatch fallback: if the normal request is refused, send `3E 10 02`
    //    (a CBOOT-patch trick that bypasses session conditions).
    send_progress(opts, ProgressUpdate::ProgrammingSession);
    tracing::info!("Upgrading to programming session");
    if let Err(e) = uds.diagnostic_session_control(0x02).await {
        tracing::warn!("Normal programming session request failed ({e}), trying SwitchPatch");
        match send_switchpatch(transport).await {
            Ok(()) => send_progress(opts, ProgressUpdate::SwitchPatchUsed),
            Err(fallback_err) => {
                // The refusal explains why we fell back; the fallback error
                // explains why that did not save us.
                tracing::warn!("SwitchPatch also failed: {fallback_err}");
                return Err(FlashError::Interface(format!(
                    "Could not enter programming session. \
                     Normal request: {e}. SwitchPatch fallback: {fallback_err}"
                )));
            }
        }
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
    let vm = Sa2Vm::new(flash_info.sa2_script);
    let key = vm.execute(seed);
    tracing::debug!("SA2: seed=0x{seed:08X}, key=0x{key:08X}");
    let key_bytes = key.to_be_bytes();
    uds.security_access(0x12, Some(&key_bytes))
        .await
        .map_err(|_| FlashError::AuthFailed)?;

    // 8. TesterPresent
    uds.tester_present().await?;

    // 9. Write workshop code
    send_progress(opts, ProgressUpdate::WritingWorkshopCode);
    tracing::info!("Writing workshop code to DID 0xF15A");
    uds.write_data_by_identifier(0xF15A, &opts.workshop_code)
        .await?;

    // 10. TesterPresent
    uds.tester_present().await?;

    // 11. Flash blocks in caller-supplied order
    let total = blocks.len();
    for (index, block) in blocks.iter().enumerate() {
        send_progress(
            opts,
            ProgressUpdate::FlashingBlock {
                name: block.block_name.clone(),
                index,
                total,
            },
        );
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
    uds.routine_control(RoutineControlType::Start, 0xFF01, None)
        .await?;

    // The flash itself is written and verified at this point. Everything below is
    // teardown: a keep-alive and a hard reset. An ECU that has already started
    // rebooting — or that has dropped out of the programming session on its own —
    // can answer these with a timeout or an NRC (`ServiceNotSupported` is the
    // common one), and reporting that as a failed flash sends the user chasing a
    // problem that does not exist. Log and continue instead; a genuine write or
    // verify failure has already returned `Err` above.

    // 13. TesterPresent
    if let Err(e) = uds.tester_present().await {
        tracing::warn!("TesterPresent after verification failed ({e}) — flash already verified");
    }

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
        Err(e) => {
            tracing::warn!(
                "ECUReset was not acknowledged ({e}) — the flash is complete and verified; \
                 cycle the ignition if the ECU does not restart on its own"
            );
        }
    }

    tracing::info!("Flash sequence complete");
    Ok(())
}

// ── Normal block (1–5) ────────────────────────────────────────────────────────

async fn flash_normal_block<T: TransportLayer>(
    uds: &UDSClient<'_, T>,
    flash_info: &FlashInfo,
    block: &PreparedBlockData,
    opts: &FlashOptions,
) -> Result<(), FlashError> {
    let block_id = flash_info
        .block_identifier(block.block_number)
        .ok_or_else(|| {
            FlashError::Config(format!(
                "No block_identifier for block {}",
                block.block_number
            ))
        })?;

    tracing::info!(
        block = block.block_number,
        name  = %block.block_name,
        bytes = block.block_encrypted_bytes.len(),
        "Flashing block"
    );

    // Erase
    if block.should_erase {
        send_progress(
            opts,
            ProgressUpdate::BlockErasing {
                name: block.block_name.clone(),
            },
        );
        tracing::debug!(block = block.block_number, "Erasing (0xFF00)");
        uds.routine_control(RoutineControlType::Start, 0xFF00, Some(&[0x01, block_id]))
            .await?;
    }

    // Request download: 1-byte address (block_id), 4-byte uncompressed length.
    // From the prepared block, not the static table: modules with dynamic block
    // lengths (Haldex) store the real length in the block header, differing by
    // up to 0x1B18 bytes on real firmware.
    let size_be = block.announced_length.to_be_bytes();

    send_progress(
        opts,
        ProgressUpdate::BlockDownloading {
            name: block.block_name.clone(),
        },
    );
    tracing::debug!(block = block.block_number, "RequestDownload");
    let max_chunk = uds
        .request_download(
            block.compression_type,
            block.encryption_type,
            &[block_id],
            &size_be,
        )
        .await?;

    // Transfer data. Per ISO 14229 the ECU's `maxNumberOfBlockLength` counts
    // the TransferData SID and blockSequenceCounter, so the usable payload is
    // 2 bytes less. Inert on Simos18 (0xFFD vs 0xFFF reported), but it bites
    // the strict transmission ECUs, configured at 0xF0 / 0x100.
    let transfer_size = flash_info
        .block_transfer_size(block.block_number)
        .unwrap_or(0xFFD)
        .min(max_chunk.saturating_sub(2));
    if transfer_size == 0 {
        return Err(FlashError::Config(format!(
            "ECU reported maxNumberOfBlockLength {max_chunk}, leaving no room for a payload"
        )));
    }

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
        send_progress(
            opts,
            ProgressUpdate::BlockTransferProgress {
                name: block.block_name.clone(),
                bytes_sent: offset,
                bytes_total: data_len,
            },
        );
    }

    // Exit transfer
    uds.request_transfer_exit(None).await?;

    // Checksum routine: data = [0x01, block_id, 0x00, 0x04, <4-byte UDS checksum>]
    send_progress(
        opts,
        ProgressUpdate::BlockChecksum {
            name: block.block_name.clone(),
        },
    );
    let mut checksum_data = vec![0x01u8, block_id, 0x00, 0x04];
    checksum_data.extend_from_slice(&block.uds_checksum);
    tracing::debug!(block = block.block_number, "Checksum routine (0x0202)");
    uds.routine_control(RoutineControlType::Start, 0x0202, Some(&checksum_data))
        .await?;

    tracing::info!(block = block.block_number, "Block flashed successfully");
    Ok(())
}

// ── Patch block (>5, WriteWithoutErase) ───────────────────────────────────────

/// WriteWithoutErase resends a chunk until the flash controller's assembly page
/// is ready, so a negative response is a routine part of the handshake. Python
/// loops unbounded; this cap only stops a wedged ECU spinning forever.
const MAX_PATCH_RETRIES: usize = 200;

async fn flash_patch_block<T: TransportLayer>(
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
    send_progress(
        opts,
        ProgressUpdate::BlockErasing {
            name: block.block_name.clone(),
        },
    );
    let cal_id = flash_info
        .block_identifier(5)
        .ok_or_else(|| FlashError::Config("No block_identifier for CAL (block 5)".into()))?;
    uds.routine_control(RoutineControlType::Start, 0xFF00, Some(&[0x01, cal_id]))
        .await?;

    // Step 2: RequestDownload for the target block; encryption 0xA, compression 0x0
    send_progress(
        opts,
        ProgressUpdate::BlockDownloading {
            name: block.block_name.clone(),
        },
    );
    let size_be = block.announced_length.to_be_bytes();

    uds.request_download(
        block.compression_type,
        block.encryption_type,
        &[target_num],
        &size_be,
    )
    .await?;

    // Step 3: Transfer with variable chunk sizes from patch_info, with retry on negative response
    let patch_info = flash_info
        .patch_info
        .as_ref()
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
                // Only a negative response means "not ready, send it again". A
                // timeout or transport error means the link is broken, so
                // retrying burns the budget and leaves the block half-written.
                Err(automotive::Error::UDSError(automotive::uds::Error::NegativeResponse(nrc)))
                    if attempt + 1 < MAX_PATCH_RETRIES =>
                {
                    tracing::debug!(attempt, offset, ?nrc, "Patch TransferData retry");
                    counter = counter.wrapping_add(1);
                }
                Err(e) => return Err(FlashError::from(e)),
            }
        }
        if !success {
            return Err(FlashError::Config(
                "Patch TransferData retries exhausted".into(),
            ));
        }
        offset = end;
        send_progress(
            opts,
            ProgressUpdate::BlockTransferProgress {
                name: block.block_name.clone(),
                bytes_sent: offset,
                bytes_total: data_len,
            },
        );
    }

    // Step 4: Exit transfer (no checksum for patch blocks)
    uds.request_transfer_exit(None).await?;

    tracing::info!(target_block = target_num, "Patch complete");
    Ok(())
}

// ── Read-only probes ──────────────────────────────────────────────────────────

/// A read-only question to ask an ECU over an interface.
#[derive(Debug, Clone)]
pub enum ProbeKind {
    /// Identify which supported module answers on the channel the supplied
    /// `FlashInfo`'s CAN identifiers belong to.
    Identify,
    /// Determine whether the ECU's CBOOT is patched (unlocked).
    ///
    /// Leaves the ECU in the bootloader — see [`crate::unlock`].
    UnlockState,
    /// Read the immobilizer snapshot (Simos only).
    Immobilizer(crate::immo::ImmoSupport),
    /// Reset the ECU, e.g. to bring it out of the bootloader.
    Reset,
}

/// The answer to a [`ProbeKind`].
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    Identify(Option<crate::identify::ChannelIdentification>),
    UnlockState(crate::unlock::UnlockProbe),
    Immobilizer(crate::immo::ImmoSnapshot),
    Reset,
}

/// Run one read-only probe against an ECU.
///
/// Opens and closes the physical device. A caller asking several questions in a
/// row should open a [`Session`] once and call [`Session::probe`].
pub async fn probe(
    interface: &Interface,
    flash_info: &'static FlashInfo,
    what: ProbeKind,
) -> Result<ProbeOutcome, FlashError> {
    // The unlock probe enters the programming session, so it needs the clear
    // too — on the hardware path, before anything else is open.
    if matches!(what, ProbeKind::UnlockState) && obd_clear_needs_own_device(interface) {
        let outcome = clear_obd_dtcs(interface).await;
        tracing::info!(%outcome, "OBD-II DTC clear before the unlock probe");
    }

    let session = Session::open(interface, flash_info, None)?;
    let result = session.probe(flash_info, what).await;
    session.close().await;
    result
}

pub(crate) async fn run_probe<T: TransportLayer>(
    transport: &T,
    flash_info: &'static FlashInfo,
    what: ProbeKind,
) -> Result<ProbeOutcome, FlashError> {
    match what {
        ProbeKind::Identify => Ok(ProbeOutcome::Identify(
            crate::identify::identify_on_channel(transport, flash_info).await,
        )),
        ProbeKind::UnlockState => Ok(ProbeOutcome::UnlockState(
            crate::unlock::probe_unlock_state(transport, flash_info).await?,
        )),
        ProbeKind::Immobilizer(support) => Ok(ProbeOutcome::Immobilizer(
            crate::immo::read_immo_snapshot(transport, support).await,
        )),
        ProbeKind::Reset => {
            crate::unlock::leave_bootloader(transport).await?;
            Ok(ProbeOutcome::Reset)
        }
    }
}

// ── Read ECU data ─────────────────────────────────────────────────────────────

/// Read ECU data records from a connected ECU.
///
/// Opens the device, reads, and closes it again. Use [`Session::read_ecu_data`]
/// when the connection is already open.
pub async fn read_ecu_data(
    flash_info: &FlashInfo,
    interface: Interface,
) -> Result<HashMap<String, String>, FlashError> {
    tracing::info!(interface = %interface, "Reading ECU data");
    let session = Session::open(&interface, flash_info, None)?;
    let result = session.read_ecu_data(flash_info).await;
    session.close().await;
    result
}

/// Read the standard data-record sweep, keyed by human description.
///
/// Collapses the records whose `description` is empty — prefer [`read_dids`]
/// when you need raw bytes for a specific DID.
pub async fn read_ecu_with_transport<T: TransportLayer>(
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
                    bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                // Seven DATA_RECORDS entries have an empty description.
                let key = if record.description.is_empty() {
                    format!("DID 0x{:04X}", record.address)
                } else {
                    record.description.to_owned()
                };
                result.insert(key, value);
            }
            Err(e) => {
                tracing::debug!(
                    "DID 0x{:04X} ({}) error: {e}",
                    record.address,
                    record.description
                );
            }
        }
    }
    Ok(result)
}

/// Read a specific set of DIDs over an already-open transport, keyed by DID.
///
/// Unlike [`read_ecu_data`] this neither opens the device nor sweeps all 38
/// records — a scan across three candidate modules would otherwise cost three
/// open/close cycles and 114 requests. Refused DIDs are simply absent from the
/// map; that is normal, and itself an identification signal.
/// itself a useful identification signal.
pub async fn read_dids<T: TransportLayer>(transport: &T, dids: &[u16]) -> HashMap<u16, Vec<u8>> {
    let uds = UDSClient::new(transport);
    let mut out = HashMap::new();
    for &did in dids {
        match uds.read_data_by_identifier(did).await {
            Ok(bytes) => {
                out.insert(did, bytes);
            }
            Err(e) => tracing::debug!("DID 0x{did:04X} not readable: {e}"),
        }
    }
    out
}

/// Write one DID over an already-open transport.
///
/// Unlike [`read_dids`] this reports failure: a refused write is something the
/// caller has to know about.
pub async fn write_did<T: TransportLayer>(
    transport: &T,
    did: u16,
    value: &[u8],
) -> Result<(), FlashError> {
    let uds = UDSClient::new(transport);
    uds.write_data_by_identifier(did, value).await?;
    Ok(())
}

/// Open the default (`0x03`) diagnostic session over an already-open transport.
pub async fn open_extended_session<T: TransportLayer>(transport: &T) -> Result<(), FlashError> {
    let uds = UDSClient::new(transport);
    uds.diagnostic_session_control(0x03).await?;
    Ok(())
}
