//! SAE J2534 PassThru CAN adapter for the `automotive` crate.
//!
//! Two dedicated background threads — one for transmit, one for receive —
//! call `PassThruWriteMsgs` and `PassThruReadMsgs` concurrently on the same
//! channel.  Modern J2534 DLLs support concurrent read/write on the same
//! channel; this is documented as a precondition for using this adapter.
//!
//! Both threads are interrupted promptly on [`Drop`] via `PassThruDisconnect`,
//! so the adapter tears down in at most one TX-write timeout (100 ms).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::Arc;
use std::thread;

use tokio::sync::broadcast;

use automotive::can::{CanAdapter, Frame, Identifier};

use crate::j2534_common::{
    self, FnPassThruConnect, FnPassThruDisconnect, FnPassThruClose,
    FnPassThruOpen, FnPassThruReadMsgs, FnPassThruStartMsgFilter, FnPassThruWriteMsgs,
    PassThruMsg, STATUS_NOERROR, ERR_BUFFER_EMPTY, ERR_TIMEOUT,
};

// ── Protocol / filter constants ────────────────────────────────────────────

const PROTOCOL_CAN: u32 = 5;
const FILTER_PASS: u32 = 1;

// ── Internal channel types ─────────────────────────────────────────────────

enum J2534Cmd {
    Send { arb_id: u32, data: Vec<u8> },
}

#[derive(Clone)]
enum J2534CanEvt {
    Frame { arb_id: u32, data: Vec<u8>, loopback: bool },
    Disconnected,
}

// ── Public adapter struct ──────────────────────────────────────────────────

/// CAN adapter backed by a SAE J2534 PassThru device.
///
/// Two dedicated background threads handle transmit and receive concurrently.
/// The struct is [`Send`] (not [`Sync`]) so it can be moved into the
/// [`automotive::can::AsyncCanAdapter`] processing thread.
///
/// Loopback frames are synthesised in software after each successful
/// `PassThruWriteMsgs` call.  Hardware loopback (`SET_CONFIG(LOOPBACK=1)`)
/// is intentionally avoided because many target devices do not support it.
pub struct J2534CanAdapter {
    /// Commands to the TX thread.
    tx_cmd: Option<SyncSender<J2534Cmd>>,
    /// Subscription to the RX broadcast channel.  Stored directly (not in a
    /// `Mutex`) because `CanAdapter::recv` takes `&mut self`.
    rx_sub: broadcast::Receiver<J2534CanEvt>,
    /// Signals the RX thread to exit.
    stop_rx: Arc<AtomicBool>,
    tx_thread: Option<thread::JoinHandle<()>>,
    rx_thread: Option<thread::JoinHandle<()>>,
    // ── Cleanup state (used in Drop after threads are joined) ──────────────
    channel_id: u32,
    device_id: u32,
    pass_thru_disconnect: FnPassThruDisconnect,
    pass_thru_close: FnPassThruClose,
    /// Keeps the PassThru DLL loaded for the lifetime of this adapter.
    _lib: libloading::Library,
}

impl J2534CanAdapter {
    /// Open a J2534 CAN channel and start the TX/RX background threads.
    ///
    /// * `dll_path` — path to the PassThru DLL, or `None` to auto-discover
    ///   the first 64-bit driver from the Windows registry.
    /// * `bitrate` — CAN bitrate in bits/sec (e.g. `500_000`).
    pub fn open(dll_path: Option<&str>, bitrate: u32) -> Result<Self, String> {
        let path = resolve_dll_path(dll_path)?;

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

        let pass_thru_open       = sym!(b"PassThruOpen\0",           FnPassThruOpen);
        let pass_thru_close      = sym!(b"PassThruClose\0",          FnPassThruClose);
        let pass_thru_connect    = sym!(b"PassThruConnect\0",        FnPassThruConnect);
        let pass_thru_disconnect = sym!(b"PassThruDisconnect\0",     FnPassThruDisconnect);
        let pass_thru_read       = sym!(b"PassThruReadMsgs\0",       FnPassThruReadMsgs);
        let pass_thru_write      = sym!(b"PassThruWriteMsgs\0",      FnPassThruWriteMsgs);
        let pass_thru_filter     = sym!(b"PassThruStartMsgFilter\0", FnPassThruStartMsgFilter);

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

        // ── Open CAN channel ───────────────────────────────────────────────
        let mut channel_id: u32 = 0;
        let ret = unsafe {
            pass_thru_connect(device_id, PROTOCOL_CAN, 0, bitrate, &mut channel_id)
        };
        tracing::debug!(ret = j2534_common::status_str(ret), channel_id, bitrate, "PassThruConnect");
        if ret != STATUS_NOERROR {
            unsafe { pass_thru_close(device_id) };
            return Err(format!(
                "PassThruConnect (CAN, {bitrate} bps) failed: 0x{ret:02X} ({})",
                j2534_common::status_str(ret)
            ));
        }

        // ── Install pass-all receive filter ───────────────────────────────
        // Mask and pattern both all-zero: every frame passes regardless of ID.
        let zero_msg = PassThruMsg::new(PROTOCOL_CAN, 0, &[]);
        let mut filter_id: u32 = 0;
        let ret = unsafe {
            pass_thru_filter(
                channel_id,
                FILTER_PASS,
                &zero_msg,
                &zero_msg,
                std::ptr::null(),
                &mut filter_id,
            )
        };
        tracing::debug!(ret = j2534_common::status_str(ret), filter_id, "PassThruStartMsgFilter");
        if ret != STATUS_NOERROR {
            unsafe { pass_thru_disconnect(channel_id) };
            unsafe { pass_thru_close(device_id) };
            return Err(format!(
                "PassThruStartMsgFilter (PASS, pass-all) failed: 0x{ret:02X} ({})",
                j2534_common::status_str(ret)
            ));
        }

        // ── Create channels and spawn threads ─────────────────────────────
        let (tx_cmd, rx_cmd) = mpsc::sync_channel::<J2534Cmd>(64);
        let (bcast_tx, bcast_rx) = broadcast::channel::<J2534CanEvt>(1024);
        let stop_rx = Arc::new(AtomicBool::new(false));

        let tx_thread = {
            let bcast = bcast_tx.clone();
            let stop = stop_rx.clone();
            thread::Builder::new()
                .name("j2534-can-tx".to_owned())
                .spawn(move || can_tx_thread(channel_id, pass_thru_write, rx_cmd, bcast, stop))
                .map_err(|e| format!("Failed to spawn J2534 CAN TX thread: {e}"))?
        };

        let rx_thread = {
            let stop = stop_rx.clone();
            thread::Builder::new()
                .name("j2534-can-rx".to_owned())
                .spawn(move || can_rx_thread(channel_id, pass_thru_read, bcast_tx, stop))
                .map_err(|e| format!("Failed to spawn J2534 CAN RX thread: {e}"))?
        };

        Ok(Self {
            tx_cmd: Some(tx_cmd),
            rx_sub: bcast_rx,
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

impl Drop for J2534CanAdapter {
    fn drop(&mut self) {
        // Signal TX thread to stop (its recv() will return Err).
        drop(self.tx_cmd.take());
        // Signal RX thread to stop.
        self.stop_rx.store(true, Ordering::Release);
        // Disconnect interrupts any in-flight PassThruReadMsgs / PassThruWriteMsgs,
        // so both threads exit promptly instead of waiting for their next timeout.
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

impl CanAdapter for J2534CanAdapter {
    fn send(&mut self, frames: &mut VecDeque<Frame>) -> automotive::Result<()> {
        let Some(tx) = &self.tx_cmd else {
            return Ok(());
        };
        while let Some(frame) = frames.pop_front() {
            let arb_id: u32 = frame.id.into();
            match tx.try_send(J2534Cmd::Send { arb_id, data: frame.data.clone() }) {
                Ok(()) => {}
                Err(_) => {
                    // TX queue full — restore frame and retry next cycle.
                    frames.push_front(frame);
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn recv(&mut self) -> automotive::Result<Vec<Frame>> {
        let mut frames = Vec::new();
        loop {
            match self.rx_sub.try_recv() {
                Ok(J2534CanEvt::Frame { arb_id, data, loopback }) => {
                    if let Ok(mut frame) = Frame::new(0, Identifier::from(arb_id), &data) {
                        frame.loopback = loopback;
                        frames.push(frame);
                    }
                }
                Ok(J2534CanEvt::Disconnected) => return Err(automotive::Error::Disconnected),
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Closed) => {
                    return Err(automotive::Error::Disconnected)
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "J2534 CAN RX broadcast lagged — frames dropped");
                    // Continue; the next try_recv() picks up current frames.
                }
            }
        }
        Ok(frames)
    }
}

// ── DLL path resolution ────────────────────────────────────────────────────

/// Resolve the PassThru DLL path.  Shared with `j2534_isotp_adapter`.
pub(crate) fn resolve_dll_path(dll_path: Option<&str>) -> Result<String, String> {
    let path = if let Some(p) = dll_path {
        p.to_owned()
    } else {
        let (native, wow32) = enumerate_passthru_drivers()
            .map_err(|e| format!("Cannot enumerate J2534 drivers: {e}"))?;

        if let Some(p) = native.into_iter().next() {
            p
        } else if wow32.is_empty() {
            return Err(
                "No J2534 PassThru drivers found in \
                 HKLM\\SOFTWARE\\PassThruSupport.04.04"
                    .to_owned(),
            );
        } else {
            return Err(format!(
                "No 64-bit J2534 drivers found. \
                 The following device(s) have 32-bit-only drivers registered \
                 under HKLM\\SOFTWARE\\WOW6432Node\\PassThruSupport.04.04, \
                 which cannot be loaded by this 64-bit process:\n  {}\n\
                 Options:\n  \
                   1. Install 64-bit drivers for your device (check manufacturer's website).\n  \
                   2. Use `j2534:<path>` to specify a 64-bit DLL explicitly.\n  \
                   3. Use mqb-flash-x86.exe instead (32-bit build).",
                wow32.join("\n  ")
            ));
        }
    };

    check_dll_architecture(&path)?;
    Ok(path)
}

/// Returns `(native_64bit_paths, wow32_paths)`.
fn enumerate_passthru_drivers() -> Result<(Vec<String>, Vec<String>), String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    const PASSTHRU_KEY: &str = "SOFTWARE\\PassThruSupport.04.04";
    const PASSTHRU_KEY_WOW: &str = "SOFTWARE\\WOW6432Node\\PassThruSupport.04.04";

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let native = read_passthru_paths(&hklm, PASSTHRU_KEY).unwrap_or_default();
    let wow32 = read_passthru_paths(&hklm, PASSTHRU_KEY_WOW)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| !native.contains(p))
        .collect();

    Ok((native, wow32))
}

fn read_passthru_paths(hklm: &winreg::RegKey, key: &str) -> Result<Vec<String>, String> {
    use winreg::enums::KEY_READ;

    let root = hklm
        .open_subkey_with_flags(key, KEY_READ)
        .map_err(|e| e.to_string())?;

    let mut paths = Vec::new();
    for name in root.enum_keys().flatten() {
        if let Ok(sub) = root.open_subkey_with_flags(&name, KEY_READ) {
            if let Ok(path) = sub.get_value::<String, _>("FunctionLibrary") {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

// ── PE header architecture check ──────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum DllMachine {
    X86,
    X64,
    Arm64,
    Other(u16),
}

fn dll_machine(path: &str) -> std::io::Result<DllMachine> {
    use std::io::{Read, Seek, SeekFrom};

    let mut f = std::fs::File::open(path)?;

    let mut magic = [0u8; 2];
    f.read_exact(&mut magic)?;
    if magic != [b'M', b'Z'] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a PE file (no MZ header)",
        ));
    }

    f.seek(SeekFrom::Start(0x3C))?;
    let mut pe_offset_bytes = [0u8; 4];
    f.read_exact(&mut pe_offset_bytes)?;
    let pe_offset = u32::from_le_bytes(pe_offset_bytes) as u64;

    f.seek(SeekFrom::Start(pe_offset))?;
    let mut sig = [0u8; 4];
    f.read_exact(&mut sig)?;
    if sig != [b'P', b'E', 0, 0] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a valid PE file (bad PE signature)",
        ));
    }

    let mut machine_bytes = [0u8; 2];
    f.read_exact(&mut machine_bytes)?;
    let machine = u16::from_le_bytes(machine_bytes);

    Ok(match machine {
        0x014C => DllMachine::X86,
        0x8664 => DllMachine::X64,
        0xAA64 => DllMachine::Arm64,
        other => DllMachine::Other(other),
    })
}

fn check_dll_architecture(path: &str) -> Result<(), String> {
    let machine = match dll_machine(path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    #[cfg(target_arch = "x86_64")]
    if machine == DllMachine::X86 {
        return Err(format!(
            "J2534 DLL '{path}' is 32-bit (IMAGE_FILE_MACHINE_I386) and cannot \
             be loaded by this 64-bit process.\n\
             Options:\n  \
               1. Install 64-bit drivers for your device.\n  \
               2. Use mqb-flash-x86.exe instead (32-bit build)."
        ));
    }

    #[cfg(target_arch = "x86")]
    if machine == DllMachine::X64 {
        return Err(format!(
            "J2534 DLL '{path}' is 64-bit (IMAGE_FILE_MACHINE_AMD64) and cannot \
             be loaded by this 32-bit process.\n\
             Options:\n  \
               1. Install 32-bit drivers for your device.\n  \
               2. Use mqb-flash-x64.exe instead (64-bit build)."
        ));
    }

    Ok(())
}

// ── TX background thread ───────────────────────────────────────────────────

/// Transmit thread: dequeues [`J2534Cmd`] items and writes them to the CAN
/// channel.  Synthesises a software loopback frame after each successful send.
///
/// Exits when `rx_cmds` is disconnected (adapter dropped) or when the stop
/// flag is set (set by itself after `rx_cmds` disconnect, or by Drop via
/// `PassThruDisconnect` which causes the in-flight write to return an error).
fn can_tx_thread(
    channel_id: u32,
    write: FnPassThruWriteMsgs,
    rx_cmds: std::sync::mpsc::Receiver<J2534Cmd>,
    bcast: broadcast::Sender<J2534CanEvt>,
    stop_rx: Arc<AtomicBool>,
) {
    loop {
        match rx_cmds.recv() {
            Ok(J2534Cmd::Send { arb_id, data }) => {
                tracing::debug!(
                    id = format_args!("{arb_id:08X}"),
                    payload = %hex::encode(&data),
                    "J2534 TX"
                );
                let mut msg = PassThruMsg::new(PROTOCOL_CAN, arb_id, &data);
                let mut count: u32 = 1;
                // 100 ms timeout: short enough that Drop's PassThruDisconnect
                // will interrupt us promptly.
                let ret = unsafe { write(channel_id, &mut msg, &mut count, 100) };
                tracing::trace!(ret = j2534_common::status_str(ret), count, "PassThruWriteMsgs");
                if ret == STATUS_NOERROR {
                    // Software loopback: hardware loopback is unreliable on many adapters.
                    bcast.send(J2534CanEvt::Frame { arb_id, data, loopback: true }).ok();
                } else {
                    tracing::debug!(
                        ret = j2534_common::status_str(ret),
                        "J2534 TX error (channel may be disconnected)"
                    );
                }
            }
            Err(_) => break, // tx_cmd dropped
        }
    }
    // Tell the RX thread to stop.
    stop_rx.store(true, Ordering::Release);
}

// ── RX background thread ───────────────────────────────────────────────────

/// Receive thread: blocks on `PassThruReadMsgs` waiting for one CAN frame at
/// a time and broadcasts each frame.
///
/// Using count=1 with a long blocking timeout means the thread sleeps
/// efficiently in the DLL when the bus is quiet, rather than spinning with a
/// 1 ms poll.  `Drop` calls `PassThruDisconnect` which interrupts any blocked
/// read immediately.  The 10-second fallback timeout handles DLLs that do not
/// properly interrupt on disconnect: the thread wakes up, sees `stop=true`,
/// and exits within 10 s at most.
///
/// Note: requesting count=N > 1 with a long timeout would make the call wait
/// for N frames before returning, introducing up to `timeout` ms of latency
/// for bursts smaller than N.  count=1 avoids this by returning as soon as
/// any frame is available.
fn can_rx_thread(
    channel_id: u32,
    read: FnPassThruReadMsgs,
    bcast: broadcast::Sender<J2534CanEvt>,
    stop: Arc<AtomicBool>,
) {
    let mut msg = PassThruMsg::default();

    loop {
        let mut count: u32 = 1;
        // Block until one frame arrives or 500 ms elapse (fallback).
        // A shorter timeout means the thread checks the stop flag more frequently,
        // so Drop completes in at most ~500 ms even when PassThruDisconnect does
        // not interrupt the blocked read.
        let ret = unsafe { read(channel_id, &mut msg, &mut count, 500) };

        match ret {
            STATUS_NOERROR if count > 0 => {
                // One frame received — process it.
                let len = msg.data_size as usize;
                if len < 4 {
                    tracing::trace!(
                        rx_status = format_args!("0x{:04X}", msg.rx_status),
                        data_size = msg.data_size,
                        "J2534 RX skipped (frame too short)"
                    );
                } else {
                    let arb_id = u32::from_be_bytes([
                        msg.data[0], msg.data[1], msg.data[2], msg.data[3],
                    ]);
                    let data = msg.data[4..len].to_vec();
                    tracing::debug!(
                        id = format_args!("{arb_id:08X}"),
                        payload = %hex::encode(&data),
                        "J2534 RX"
                    );
                    bcast.send(J2534CanEvt::Frame { arb_id, data, loopback: false }).ok();
                }
            }
            ERR_TIMEOUT | ERR_BUFFER_EMPTY | STATUS_NOERROR => {
                // Timeout (no frame) or buffer empty — check stop flag.
                if stop.load(Ordering::Acquire) {
                    return;
                }
            }
            _ => {
                // Fatal error — usually ERR_INVALID_CHANNEL_ID after PassThruDisconnect.
                tracing::debug!(
                    ret = j2534_common::status_str(ret),
                    "J2534 RX error — channel disconnected, exiting"
                );
                bcast.send(J2534CanEvt::Disconnected).ok();
                return;
            }
        }
    }
}
