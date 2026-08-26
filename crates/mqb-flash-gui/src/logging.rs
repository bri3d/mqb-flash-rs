//! Optional protocol logging to a file.
//!
//! The release GUI is built with `windows_subsystem = "windows"`, so it has no
//! console and `tracing`'s terminal output goes nowhere: without a file there
//! is no record of a failed flash.
//!
//! Opt-in, because it needs `debug`, where `automotive` logs every ISO-TP
//! frame — tens of thousands of lines per flash. The checkbox on the interface
//! screen is the switch.
//!
//! Two layers are installed at startup and never replaced: the console layer,
//! unchanged; and the file layer, whose filter reads [`ENABLED`] per event, so
//! toggling is one atomic store rather than a subscriber rebuild.
//!
//! The file is unbuffered, so a flash that dies mid-transfer still leaves a
//! complete log.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tracing::{Level, Metadata};
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;

/// Log file name, alongside the executable. Fixed rather than timestamped so
/// the path can be stated once.
const LOG_FILE_NAME: &str = "mqb-flash.log";

/// Whether the file layer currently accepts events.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// The open log file, shared between the GUI and the `tracing` writer.
static FILE: OnceLock<Arc<Mutex<Option<File>>>> = OnceLock::new();

/// Remembered separately so the path can be read without the file lock.
static PATH: OnceLock<PathBuf> = OnceLock::new();

fn file_slot() -> &'static Arc<Mutex<Option<File>>> {
    FILE.get_or_init(|| Arc::new(Mutex::new(None)))
}

/// Which events reach the log file when it is on.
///
/// `debug` on our own crates and on `automotive` is what puts the PDU bytes in
/// the file: `automotive::isotp` and `automotive::j2534` log every TX and RX
/// payload as hex at that level. Anything noisier (`trace`, and the whole of
/// `wgpu`/`iced`) is not protocol and stays out.
fn wanted(target: &str, level: Level) -> bool {
    level <= Level::DEBUG && (target.starts_with("mqb_") || target.starts_with("automotive"))
}

/// Install the console and file layers. Call once, before the UI starts.
pub fn init() {
    let console = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive("mqb_flash=info".parse().unwrap())
            .from_env_lossy()
            .add_directive("wgpu_core=warn".parse().unwrap())
            .add_directive("wgpu_hal=warn".parse().unwrap())
            .add_directive("naga=warn".parse().unwrap()),
    );

    let to_file = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(LogFile(file_slot().clone()))
        .with_filter(FilterFn::new(|meta: &Metadata<'_>| {
            ENABLED.load(Ordering::Relaxed) && wanted(meta.target(), *meta.level())
        }));

    tracing_subscriber::registry()
        .with(console)
        .with(to_file)
        .init();
}

/// Turn file logging on or off.
///
/// Returns the path being written to when enabling. Enabling twice reuses the
/// already-open file, so toggling the checkbox does not restart the log.
pub fn set_enabled(on: bool) -> Result<Option<PathBuf>, String> {
    let slot = file_slot();
    let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());

    if !on {
        ENABLED.store(false, Ordering::Relaxed);
        if let Some(mut file) = guard.take() {
            let _ = file.flush();
        }
        return Ok(None);
    }

    if guard.is_none() {
        let (mut file, path) = open_log()?;
        // The file is appended to, so mark where each run starts.
        let _ = writeln!(
            file,
            "==== mqb-flash-gui {} — protocol logging enabled ====",
            env!("CARGO_PKG_VERSION")
        );
        *guard = Some(file);
        ENABLED.store(true, Ordering::Relaxed);
        return Ok(Some(path));
    }

    ENABLED.store(true, Ordering::Relaxed);
    Ok(PATH.get().cloned())
}

/// Open the log next to the executable, falling back to the temp directory.
///
/// The executable's directory is the first place a user looks, but it is not
/// always writable — Program Files, a read-only share, a mounted image.
fn open_log() -> Result<(File, PathBuf), String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.to_path_buf());
        }
    }
    dirs.push(std::env::temp_dir());

    let mut last_err = None;
    for dir in dirs {
        let path = dir.join(LOG_FILE_NAME);
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                let _ = PATH.set(path.clone());
                return Ok((file, path));
            }
            Err(e) => last_err = Some((path, e)),
        }
    }

    Err(match last_err {
        Some((path, e)) => format!("could not open {}: {e}", path.display()),
        None => "no directory to write a log to".to_owned(),
    })
}

/// A `MakeWriter` over an optionally-open file.
///
/// When the file is closed, writes are discarded rather than failing: the
/// filter should have kept them out, and a logging error must never surface as
/// a flashing error.
#[derive(Clone)]
struct LogFile(Arc<Mutex<Option<File>>>);

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = LogFileGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogFileGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

struct LogFileGuard<'a>(MutexGuard<'a, Option<File>>);

impl Write for LogFileGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.as_mut() {
            Some(file) => file.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `wanted` is the whole filter: `wgpu` at debug would make the log
    /// unreadable, and excluding `automotive` would drop the PDU bytes.
    #[test]
    fn only_protocol_targets_at_debug_reach_the_file() {
        assert!(wanted("mqb_flash_uds::flash", Level::DEBUG));
        assert!(wanted("mqb_flash_uds::flash", Level::INFO));
        assert!(wanted("automotive::isotp", Level::DEBUG));
        assert!(wanted("automotive::j2534::isotp_adapter", Level::DEBUG));

        assert!(!wanted("automotive::isotp", Level::TRACE));
        assert!(!wanted("wgpu_core::device", Level::DEBUG));
        assert!(!wanted("iced_wgpu::window", Level::INFO));
    }

    /// End to end: nothing is written until the checkbox is on, PDU-level
    /// events land in the file while it is, and turning it off stops them.
    ///
    /// This installs the process-wide subscriber, so it must be the only test
    /// in this binary that calls [`init`].
    #[test]
    fn the_switch_actually_starts_and_stops_the_file() {
        init();

        // Off: the event is dropped, and no file has even been opened.
        tracing::debug!(target: "automotive::isotp", "TX before");
        assert!(PATH.get().is_none(), "logging off must not open a file");

        let path = set_enabled(true).expect("enable").expect("a path");
        tracing::debug!(target: "automotive::isotp", "TX {}", "1003");
        tracing::debug!(target: "wgpu_core::device", "noise");

        set_enabled(false).expect("disable");
        tracing::debug!(target: "automotive::isotp", "TX after");

        let body = std::fs::read_to_string(&path).expect("read log");
        assert!(body.contains("TX 1003"), "PDU bytes missing from {body}");
        assert!(!body.contains("TX before"), "logged while disabled");
        assert!(!body.contains("TX after"), "kept logging after disable");
        assert!(
            !body.contains("noise"),
            "non-protocol target reached the log"
        );

        let _ = std::fs::remove_file(&path);
    }
}
