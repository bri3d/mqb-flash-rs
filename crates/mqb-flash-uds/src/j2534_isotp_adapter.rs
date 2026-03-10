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
//! On [`Drop`], `PassThruDisconnect` is called to interrupt any in-flight DLL
//! calls, then both threads are joined before `PassThruClose` releases the
//! device.  This avoids use-after-free in the DLL.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use async_stream::stream;
use tokio::sync::{broadcast, oneshot};

use automotive::IsoTpTransport;

use crate::j2534_common::{
    self, FnPassThruDisconnect, FnPassThruReadMsgs, FnPassThruWriteMsgs,
    J2534Device, PassThruMsg, STATUS_NOERROR, ERR_BUFFER_EMPTY, ERR_TIMEOUT,
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
    pass_thru_disconnect: FnPassThruDisconnect,
    /// Owns the device handle + DLL; `None` after [`into_device`].
    device: Option<J2534Device>,
}

impl J2534NativeIsoTpTransport {
    /// Open a J2534 ISO 15765 channel and start the TX/RX background threads.
    ///
    /// Opens a new device via `PassThruOpen`.  To reuse an already-open
    /// device (e.g. after an OBD DTC-clear channel), use
    /// [`open_on_device`](Self::open_on_device) instead.
    pub fn open(
        dll_path: Option<&str>,
        bitrate: u32,
        tx_id: u32,
        rx_id: u32,
        stmin_tx_us: Option<u32>,
    ) -> Result<Self, String> {
        let device = j2534_common::open_device(dll_path)?;
        Self::open_on_device(device, bitrate, tx_id, rx_id, stmin_tx_us)
            .map_err(|(msg, _device)| msg)
    }

    /// Open an ISO 15765 channel on an already-open [`J2534Device`].
    ///
    /// This avoids closing and reopening the physical device when switching
    /// channels (e.g. from OBD DTC-clear to the main flash channel).
    ///
    /// On error, the [`J2534Device`] is returned alongside the error message
    /// so the caller can reuse it.
    pub(crate) fn open_on_device(
        device: J2534Device,
        bitrate: u32,
        tx_id: u32,
        rx_id: u32,
        stmin_tx_us: Option<u32>,
    ) -> Result<Self, (String, J2534Device)> {
        let device_id = device.device_id;
        let pass_thru_connect = device.connect;
        let pass_thru_disconnect = device.disconnect;
        let pass_thru_read = device.read;
        let pass_thru_write = device.write;
        let pass_thru_filter = device.filter;
        let pass_thru_ioctl = device.ioctl;

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
            return Err((format!(
                "PassThruConnect (ISO15765, {bitrate} bps) failed: 0x{ret:02X} ({})",
                j2534_common::status_str(ret)
            ), device));
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
            return Err((format!(
                "PassThruStartMsgFilter failed: 0x{ret:02X} ({})",
                j2534_common::status_str(ret)
            ), device));
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

        // ── STMIN_TX ioctl ─────────────────────────────────────────────────
        // Default to 300 µs if no override is provided.  This gives the
        // receiving ECU (and the software ISO-TP pipeline on the raw-CAN
        // path) enough breathing room without significantly slowing down
        // large transfers.
        let stmin_us = stmin_tx_us.unwrap_or(500);
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
                .map_err(|e| format!("Failed to spawn J2534 ISO-TP TX thread: {e}"))
        };
        let tx_thread = match tx_thread {
            Ok(h) => h,
            Err(e) => return Err((e, device)),
        };

        let rx_thread = {
            let bcast = bcast_tx.clone();
            let stop = stop_rx.clone();
            thread::Builder::new()
                .name("j2534-isotp-rx".to_owned())
                .spawn(move || isotp_rx_thread(channel_id, pass_thru_read, bcast, stop))
                .map_err(|e| format!("Failed to spawn J2534 ISO-TP RX thread: {e}"))
        };
        let rx_thread = match rx_thread {
            Ok(h) => h,
            Err(e) => return Err((e, device)),
        };

        Ok(Self {
            tx_cmd: Some(tx_cmd),
            rx_bcast: bcast_tx,
            stop_rx,
            tx_thread: Some(tx_thread),
            rx_thread: Some(rx_thread),
            channel_id,
            pass_thru_disconnect,
            device: Some(device),
        })
    }

    /// Disconnect the ISO 15765 channel and return the underlying
    /// [`J2534Device`] so it can be reused for another channel.
    ///
    /// The device remains open — only the channel is torn down.
    pub(crate) fn into_device(mut self) -> J2534Device {
        self.shutdown_channel();
        // Take the device so Drop doesn't close it.
        self.device.take().expect("device already taken")
    }

    /// Stop threads and disconnect the channel (shared by Drop and into_device).
    fn shutdown_channel(&mut self) {
        // Signal TX thread to stop.
        drop(self.tx_cmd.take());
        // Signal RX thread to stop.
        self.stop_rx.store(true, Ordering::Release);
        // Disconnect invalidates the channel, causing in-flight
        // PassThruWriteMsgs / PassThruReadMsgs to return an error.
        let ret = unsafe { (self.pass_thru_disconnect)(self.channel_id) };
        tracing::trace!(ret = j2534_common::status_str(ret), "PassThruDisconnect");
        // Join threads BEFORE PassThruClose — the threads may still be inside
        // a DLL call that references device-level structures.
        if let Some(h) = self.tx_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.rx_thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for J2534NativeIsoTpTransport {
    fn drop(&mut self) {
        self.shutdown_channel();
        // If the device is still owned (i.e. `into_device` was not called),
        // dropping it here calls PassThruClose.
        drop(self.device.take());
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
                    let src_id = mqb_bytes::read_u32_be(&msg.data, 0);
                    let payload = &msg.data[4..len];
                    tracing::debug!(
                        rx_status = format_args!("0x{:04X}", msg.rx_status),
                        src_id = format_args!("{src_id:08X}"),
                        data_size = len - 4,
                        payload = %hex::encode(&payload[..payload.len().min(16)]),
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
