//! SAE J2534 PassThru **ISO 15765** (native ISO-TP) transport for `UDSClient`.
//!
//! Opens a `PROTOCOL_ISO15765` channel so the adapter firmware handles all
//! ISO-TP framing, flow-control negotiation, and STmin timing in hardware.
//! The host only ever exchanges complete UDS PDUs.
//!
//! # Threading model
//!
//! Two dedicated background threads run concurrently:
//!
//! * **TX thread** — receives [`J2534IsoTpCmd::Send`] commands and calls
//!   `PassThruWriteMsgs` with a 60-second timeout.  This covers worst-case
//!   multi-frame transfers at 500 kbps with large ECU STmin values.
//! * **RX thread** — blocks on `PassThruReadMsgs` with a 500 ms fallback
//!   timeout and broadcasts complete UDS PDUs via a [`tokio::sync::broadcast`]
//!   channel.
//!
//! Both threads call the DLL concurrently on the same ISO 15765 channel.
//! Modern J2534 DLLs support concurrent `PassThruReadMsgs` /
//! `PassThruWriteMsgs` on the same channel; this is a documented precondition.
//!
//! [`Drop`] calls `PassThruDisconnect` before joining the threads so that any
//! in-flight `PassThruWriteMsgs` (up to 60 s) is interrupted promptly.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use async_stream::stream;
use tokio::sync::{broadcast, oneshot};

use automotive::IsoTpTransport;

use crate::j2534_common::{
    self, FnPassThruConnect, FnPassThruDisconnect, FnPassThruIoctl, FnPassThruClose,
    FnPassThruOpen, FnPassThruReadMsgs, FnPassThruStartMsgFilter, FnPassThruWriteMsgs,
    PassThruMsg, STATUS_NOERROR, ERR_BUFFER_EMPTY, ERR_TIMEOUT,
};

// ── Protocol / filter constants ────────────────────────────────────────────

const PROTOCOL_ISO15765: u32 = 6;

/// `TxFlags` flag: pad outbound CAN frames to DLC = 8.
const ISO15765_FRAME_PAD: u32 = 0x0040;

/// `PassThruStartMsgFilter` filter type: ISO 15765 flow-control filter.
const FILTER_FLOW_CONTROL: u32 = 3;

/// J2534-2 channel parameter: minimum separation time for **transmitted**
/// consecutive frames (`STMIN_TX = 0x23`).  The `value` field must be the
/// ISO 15765-2 STmin encoded byte (see [`us_to_stmin_byte`]).
pub const IOCTL_PARAM_STMIN_TX: u32 = 0x23;

/// J2534 channel parameter: ISO 15765 separation time for received frames
/// (`ISO15765_STMIN = 0x1F`).
const IOCTL_PARAM_ISO15765_STMIN: u32 = 0x1F;

/// `PassThruIoctl` ID to clear the channel receive buffer.
const IOCTL_CLEAR_RX_BUFFER: u32 = 0x08;

/// Encode a separation-time value in microseconds to the ISO 15765-2 STmin byte.
///
/// Encoding (ISO 15765-2 §9.6.5.4 / Table 5):
/// - 0 µs → `0x00` (no delay)
/// - 1 000–127 000 µs (1–127 ms, step 1 ms) → `0x01`–`0x7F`
/// - 100–900 µs (step 100 µs) → `0xF1`–`0xF9`
/// - Values below 100 µs (other than 0) or above 127 ms → nearest boundary.
pub fn us_to_stmin_byte(us: u32) -> u8 {
    if us == 0 {
        0x00
    } else if us < 1_000 {
        let steps = us / 100;
        if steps == 0 {
            0x00
        } else {
            0xF0 + steps.min(9) as u8
        }
    } else {
        let ms = us / 1_000;
        ms.min(127) as u8
    }
}

// ── Internal channel types ─────────────────────────────────────────────────

/// Commands sent from the public struct to the TX thread.
enum J2534IsoTpCmd {
    /// Transmit one UDS PDU; `done` is resolved with the result.
    Send(Vec<u8>, oneshot::Sender<Result<(), String>>),
}

/// Events broadcast from the RX thread.
#[derive(Clone)]
enum J2534IsoTpEvt {
    Pdu(Vec<u8>),
    Disconnected,
}

// ── Public transport struct ────────────────────────────────────────────────

/// J2534 ISO 15765 (native ISO-TP) transport.
///
/// Implements [`IsoTpTransport`] so it plugs directly into `UDSClient`
/// without going through `automotive`'s software ISO-TP layer.
///
/// All fields are [`Send`] + [`Sync`], so the struct is `Send + Sync` without
/// any `unsafe` impl.
pub struct J2534NativeIsoTpTransport {
    /// Commands to the TX thread (drop to stop it).
    tx_cmd: Option<SyncSender<J2534IsoTpCmd>>,
    /// Broadcast sender kept alive so callers can subscribe.
    rx_bcast: broadcast::Sender<J2534IsoTpEvt>,
    /// Signals the RX thread to exit.
    stop_rx: Arc<AtomicBool>,
    tx_thread: Option<thread::JoinHandle<()>>,
    rx_thread: Option<thread::JoinHandle<()>>,
    // ── Cleanup state (used in Drop after threads are joined) ──────────────
    channel_id: u32,
    device_id: u32,
    pass_thru_disconnect: FnPassThruDisconnect,
    pass_thru_close: FnPassThruClose,
    /// Keeps the PassThru DLL loaded for the lifetime of this transport.
    _lib: libloading::Library,
}

impl J2534NativeIsoTpTransport {
    /// Open a J2534 ISO 15765 channel and start the TX/RX background threads.
    ///
    /// # Parameters
    /// * `dll_path` — path to the PassThru DLL, or `None` to auto-discover
    ///   the first 64-bit driver from `HKLM\SOFTWARE\PassThruSupport.04.04`.
    /// * `bitrate` — CAN bus bitrate in bits/sec (typically `500_000`).
    /// * `tx_id` — CAN ID for tester-to-ECU frames.
    /// * `rx_id` — CAN ID for ECU-to-tester frames.
    /// * `stmin_tx_us` — if `Some(n)`, encodes `n` µs as the ISO 15765-2
    ///   STmin byte and applies it via `PassThruIoctl(SET_CONFIG, STMIN_TX)`.
    pub fn open(
        dll_path: Option<&str>,
        bitrate: u32,
        tx_id: u32,
        rx_id: u32,
        stmin_tx_us: Option<u32>,
    ) -> Result<Self, String> {
        let path = crate::j2534_adapter::resolve_dll_path(dll_path)?;

        // ── Load DLL ──────────────────────────────────────────────────────
        let lib = match unsafe { libloading::Library::new(&path) } {
            Ok(l) => l,
            Err(e) => return Err(format!("Cannot load {path}: {e}")),
        };

        macro_rules! sym {
            ($name:literal, $ty:ty) => {
                match unsafe { lib.get::<$ty>($name) } {
                    Ok(s) => *s,
                    Err(e) => {
                        return Err(format!(
                            "Symbol {} not found in {path}: {e}",
                            std::str::from_utf8($name).unwrap_or("?")
                        ));
                    }
                }
            };
        }

        let pass_thru_open     = sym!(b"PassThruOpen\0",           FnPassThruOpen);
        let pass_thru_close    = sym!(b"PassThruClose\0",          FnPassThruClose);
        let pass_thru_connect  = sym!(b"PassThruConnect\0",        FnPassThruConnect);
        let pass_thru_disconnect = sym!(b"PassThruDisconnect\0",   FnPassThruDisconnect);
        let pass_thru_read     = sym!(b"PassThruReadMsgs\0",       FnPassThruReadMsgs);
        let pass_thru_write    = sym!(b"PassThruWriteMsgs\0",      FnPassThruWriteMsgs);
        let pass_thru_filter   = sym!(b"PassThruStartMsgFilter\0", FnPassThruStartMsgFilter);
        let pass_thru_ioctl    = sym!(b"PassThruIoctl\0",          FnPassThruIoctl);

        // ── Open device ────────────────────────────────────────────────────
        let mut device_id: u32 = 0;
        let ret = unsafe { pass_thru_open(std::ptr::null(), &mut device_id) };
        tracing::debug!(ret = j2534_common::status_str(ret), device_id, "PassThruOpen");
        if ret != STATUS_NOERROR {
            return Err(format!(
                "PassThruOpen failed: 0x{ret:02X} ({})",
                j2534_common::status_str(ret)
            ));
        }

        // ── Open ISO 15765 channel ─────────────────────────────────────────
        // Flags = 0: frame padding is controlled per-message via TxFlags.
        let mut channel_id: u32 = 0;
        let ret = unsafe {
            pass_thru_connect(device_id, PROTOCOL_ISO15765, 0, bitrate, &mut channel_id)
        };
        tracing::debug!(
            ret = j2534_common::status_str(ret),
            channel_id,
            bitrate,
            "PassThruConnect ISO15765"
        );
        if ret != STATUS_NOERROR {
            unsafe { pass_thru_close(device_id) };
            return Err(format!(
                "PassThruConnect (ISO15765, {bitrate} bps) failed: 0x{ret:02X} ({})",
                j2534_common::status_str(ret)
            ));
        }

        // ── Set up flow-control filter ─────────────────────────────────────
        // Pattern (ECU → tester) = rx_id; flow-control (tester → ECU) = tx_id.
        // Mask 0xFFFFFFFF = exact ID match.  ISO15765_FRAME_PAD on all three
        // messages so the adapter pads auto-generated flow-control frames.
        let mut mask_msg    = PassThruMsg::new(PROTOCOL_ISO15765, 0xFFFF_FFFF, &[]);
        let mut pattern_msg = PassThruMsg::new(PROTOCOL_ISO15765, rx_id, &[]);
        let mut fc_msg      = PassThruMsg::new(PROTOCOL_ISO15765, tx_id, &[]);
        mask_msg.tx_flags    = ISO15765_FRAME_PAD;
        pattern_msg.tx_flags = ISO15765_FRAME_PAD;
        fc_msg.tx_flags      = ISO15765_FRAME_PAD;

        let mut filter_id: u32 = 0;
        let ret = unsafe {
            pass_thru_filter(
                channel_id,
                FILTER_FLOW_CONTROL,
                &mask_msg,
                &pattern_msg,
                &fc_msg,
                &mut filter_id,
            )
        };
        tracing::debug!(
            ret = j2534_common::status_str(ret),
            filter_id,
            tx_id = format_args!("{tx_id:08X}"),
            rx_id = format_args!("{rx_id:08X}"),
            "PassThruStartMsgFilter (FLOW_CONTROL)"
        );
        if ret != STATUS_NOERROR {
            unsafe { pass_thru_disconnect(channel_id) };
            unsafe { pass_thru_close(device_id) };
            return Err(format!(
                "PassThruStartMsgFilter failed: 0x{ret:02X} ({})",
                j2534_common::status_str(ret)
            ));
        }

        // ── Clear RX buffer after filter setup ─────────────────────────────
        let ret = unsafe {
            pass_thru_ioctl(
                channel_id,
                IOCTL_CLEAR_RX_BUFFER,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        tracing::debug!(ret = j2534_common::status_str(ret), "PassThruIoctl CLEAR_RX_BUFFER");

        // ── Set ISO15765_STMIN = 0 ─────────────────────────────────────────
        let ret = j2534_common::set_config(
            pass_thru_ioctl,
            channel_id,
            IOCTL_PARAM_ISO15765_STMIN,
            0,
        );
        tracing::debug!(
            ret = j2534_common::status_str(ret),
            "PassThruIoctl SET_CONFIG ISO15765_STMIN=0"
        );

        // ── Optional STMIN_TX ioctl ────────────────────────────────────────
        if let Some(stmin_us) = stmin_tx_us {
            let stmin_byte = us_to_stmin_byte(stmin_us) as u32;
            let ret = j2534_common::set_config(
                pass_thru_ioctl,
                channel_id,
                IOCTL_PARAM_STMIN_TX,
                stmin_byte,
            );
            tracing::debug!(
                ret = j2534_common::status_str(ret),
                stmin_us,
                stmin_byte,
                "PassThruIoctl SET_CONFIG STMIN_TX"
            );
            if ret != STATUS_NOERROR {
                tracing::warn!(
                    "STMIN_TX ioctl failed: 0x{ret:02X} ({}) — \
                     adapter will use its default separation time",
                    j2534_common::status_str(ret)
                );
            }
        }

        // ── Create channels and spawn threads ─────────────────────────────
        let (tx_cmd, rx_cmd) = mpsc::sync_channel::<J2534IsoTpCmd>(64);
        let (bcast_tx, bcast_rx) = broadcast::channel::<J2534IsoTpEvt>(256);
        let stop_rx = Arc::new(AtomicBool::new(false));

        // Drop the initial receiver; callers subscribe via bcast_tx.
        drop(bcast_rx);

        let tx_thread = {
            let bcast = bcast_tx.clone();
            let stop = stop_rx.clone();
            thread::Builder::new()
                .name("j2534-isotp-tx".to_owned())
                .spawn(move || isotp_tx_thread(channel_id, tx_id, pass_thru_write, rx_cmd, bcast, stop))
                .map_err(|e| format!("Failed to spawn J2534 ISO-TP TX thread: {e}"))?
        };

        let rx_thread = {
            let bcast = bcast_tx.clone();
            let stop = stop_rx.clone();
            thread::Builder::new()
                .name("j2534-isotp-rx".to_owned())
                .spawn(move || isotp_rx_thread(channel_id, pass_thru_read, bcast, stop))
                .map_err(|e| format!("Failed to spawn J2534 ISO-TP RX thread: {e}"))?
        };

        Ok(Self {
            tx_cmd: Some(tx_cmd),
            rx_bcast: bcast_tx,
            stop_rx,
            tx_thread: Some(tx_thread),
            rx_thread: Some(rx_thread),
            channel_id,
            device_id,
            pass_thru_disconnect,
            pass_thru_close,
            _lib: lib,
        })
    }
}

impl Drop for J2534NativeIsoTpTransport {
    fn drop(&mut self) {
        // Signal TX thread to stop (its recv() will return Err).
        drop(self.tx_cmd.take());
        // Signal RX thread to stop.
        self.stop_rx.store(true, Ordering::Release);
        // Disconnect interrupts any in-flight PassThruWriteMsgs (up to 60 s)
        // so the TX thread exits promptly.
        let ret = unsafe { (self.pass_thru_disconnect)(self.channel_id) };
        tracing::trace!(ret = j2534_common::status_str(ret), "PassThruDisconnect");
        let ret = unsafe { (self.pass_thru_close)(self.device_id) };
        tracing::trace!(ret = j2534_common::status_str(ret), "PassThruClose");
        if let Some(h) = self.tx_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.rx_thread.take() {
            let _ = h.join();
        }
    }
}

impl IsoTpTransport for J2534NativeIsoTpTransport {
    /// Send a UDS PDU via the J2534 ISO 15765 channel.
    ///
    /// Waits until the adapter firmware has completed the full multi-frame
    /// transfer (i.e. `PassThruWriteMsgs` returns on the TX thread).
    fn send<'a>(&'a self, data: &'a [u8]) -> impl std::future::Future<Output = automotive::Result<()>> + 'a {
        let pdu = data.to_vec();
        async move {
            let Some(tx) = &self.tx_cmd else {
                return Err(automotive::Error::Disconnected);
            };
            let (done_tx, done_rx) = oneshot::channel();
            tx.send(J2534IsoTpCmd::Send(pdu, done_tx))
                .map_err(|_| automotive::Error::Disconnected)?;
            done_rx
                .await
                .map_err(|_| automotive::Error::Disconnected)?
                .map_err(|_| automotive::Error::Disconnected)
        }
    }

    /// Stream of UDS PDUs received from the ECU.
    ///
    /// Each call creates an independent subscriber so multiple concurrent
    /// streams are safe.
    fn recv(&self) -> impl automotive::Stream<Item = automotive::Result<Vec<u8>>> + Unpin + '_ {
        let mut rx = self.rx_bcast.subscribe();
        Box::pin(stream! {
            loop {
                match rx.recv().await {
                    Ok(J2534IsoTpEvt::Pdu(pdu)) => yield Ok(pdu),
                    Ok(J2534IsoTpEvt::Disconnected) => {
                        yield Err(automotive::Error::Disconnected);
                        return;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        yield Err(automotive::Error::Disconnected);
                        return;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            dropped = n,
                            "J2534 ISO15765 RX lagged — PDU(s) dropped"
                        );
                    }
                }
            }
        })
    }
}

// ── TX background thread ───────────────────────────────────────────────────

/// Transmit thread: writes PDUs to the ISO 15765 channel with a 60-second
/// timeout to accommodate worst-case multi-frame transfers.
///
/// [`Drop`] calls `PassThruDisconnect` before joining this thread, so the
/// in-flight `PassThruWriteMsgs` returns quickly even during a large transfer.
fn isotp_tx_thread(
    channel_id: u32,
    tx_id: u32,
    write: FnPassThruWriteMsgs,
    rx_cmds: Receiver<J2534IsoTpCmd>,
    _bcast: broadcast::Sender<J2534IsoTpEvt>,
    stop_rx: Arc<AtomicBool>,
) {
    while let Ok(J2534IsoTpCmd::Send(pdu, done)) = rx_cmds.recv() {
        tracing::debug!(
            len = pdu.len(),
            payload = %hex::encode(&pdu[..pdu.len().min(16)]),
            "J2534 ISO15765 TX"
        );
        let mut msg = PassThruMsg::new(PROTOCOL_ISO15765, tx_id, &pdu);
        msg.tx_flags = ISO15765_FRAME_PAD;
        let mut count: u32 = 1;
        // 60-second timeout: covers worst-case multi-frame transfer.
        // Drop's PassThruDisconnect will interrupt this call if the adapter
        // is torn down mid-transfer.
        let ret = unsafe { write(channel_id, &mut msg, &mut count, 60_000) };
        tracing::debug!(ret = j2534_common::status_str(ret), "PassThruWriteMsgs ISO15765");
        let result = if ret == STATUS_NOERROR {
            Ok(())
        } else {
            Err(format!(
                "ISO15765 TX failed: 0x{ret:02X} ({})",
                j2534_common::status_str(ret)
            ))
        };
        done.send(result).ok();
    }
    // rx_cmds disconnected — signal the RX thread to stop.
    stop_rx.store(true, Ordering::Release);
}

// ── RX background thread ───────────────────────────────────────────────────

/// Receive thread: blocks on `PassThruReadMsgs` waiting for one reassembled
/// UDS PDU at a time, then broadcasts it.
///
/// For ISO 15765, the adapter delivers one complete multi-frame PDU per
/// message, so count=1 is the natural unit.  A long blocking timeout means
/// the thread is truly idle in the DLL when there is nothing to receive,
/// rather than spinning.  `Drop` calls `PassThruDisconnect`
/// which interrupts any blocked read immediately.  The 500ms fallback
/// timeout handles DLLs that do not interrupt on disconnect.
fn isotp_rx_thread(
    channel_id: u32,
    read: FnPassThruReadMsgs,
    bcast: broadcast::Sender<J2534IsoTpEvt>,
    stop: Arc<AtomicBool>,
) {
    let mut msg = PassThruMsg::default();

    loop {
        let mut count: u32 = 1;
        // Block until one PDU arrives or 500 ms elapse (fallback).
        // A shorter timeout means the thread checks the stop flag more frequently,
        // so Drop completes in at most ~500 ms even when PassThruDisconnect does
        // not interrupt the blocked read.
        let ret = unsafe { read(channel_id, &mut msg, &mut count, 500) };

        match ret {
            STATUS_NOERROR if count > 0 => {
                let len = msg.data_size as usize;
                if len < 4 {
                    continue;
                }
                // rx_status != 0: TX confirmation / loopback echo — not a received PDU.
                if msg.rx_status != 0 {
                    tracing::debug!(
                        rx_status = format_args!("0x{:04X}", msg.rx_status),
                        "J2534 ISO15765 skipping non-data frame"
                    );
                    continue;
                }
                // Bytes 0–3: source CAN ID; bytes 4..: reassembled PDU payload.
                let pdu = msg.data[4..len].to_vec();
                tracing::debug!(
                    src_id = format_args!(
                        "{:08X}",
                        mqb_bytes::read_u32_be(&msg.data, 0)
                    ),
                    len = pdu.len(),
                    payload = %hex::encode(&pdu[..pdu.len().min(16)]),
                    "J2534 ISO15765 RX"
                );
                bcast.send(J2534IsoTpEvt::Pdu(pdu)).ok();
            }
            ERR_TIMEOUT | ERR_BUFFER_EMPTY | STATUS_NOERROR => {
                // Timeout (no PDU) or buffer empty — check stop flag.
                if stop.load(Ordering::Acquire) {
                    return;
                }
            }
            _ => {
                // Fatal error (e.g. ERR_INVALID_CHANNEL_ID after PassThruDisconnect).
                tracing::debug!(
                    ret = j2534_common::status_str(ret),
                    "J2534 ISO15765 RX error — channel disconnected, exiting"
                );
                bcast.send(J2534IsoTpEvt::Disconnected).ok();
                return;
            }
        }
    }
}
