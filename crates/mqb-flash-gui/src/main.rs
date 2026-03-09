//! mqb-flash-gui — iced 0.13 GUI for VW ECU flashing.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use iced::widget::{
    button, column, container, horizontal_rule, pick_list, progress_bar, radio, row,
    scrollable, text, text_input,
};
use iced::{Alignment, Element, Length, Subscription, Task};

use mqb_checksum::{validate_dq381, validate_dsg, validate_haldex, validate_simos};
use mqb_flash_uds::{
    flash_blocks, prepare_block_for_flash, prepare_patch_for_flash, read_ecu_data, FlashOptions,
    Interface, ProgressUpdate,
};
use mqb_modules::{ChecksumKind, ChecksumState, FlashInfo, PreparedBlockData};

// ─── Application entry point ─────────────────────────────────────────────────

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive("mqb_flash=info".parse().unwrap())
                .from_env_lossy()
                // Always suppress wgpu noise regardless of RUST_LOG.
                .add_directive("wgpu_core=warn".parse().unwrap())
                .add_directive("wgpu_hal=warn".parse().unwrap())
                .add_directive("naga=warn".parse().unwrap()),
        )
        .init();
    iced::application("MQB Flash", update, view)
        .subscription(subscription)
        .window_size((820.0_f32, 720.0_f32))
        .run()
}

// ─── State ───────────────────────────────────────────────────────────────────

struct State {
    /// Which ECU module is selected.
    selected_module: Option<&'static str>,
    /// Which physical interface to use.
    interface_kind: InterfaceKind,
    /// SocketCAN interface name (only used when interface_kind == SocketCan).
    socketcan_name: String,
    /// J2534 PassThru DLL path (empty = auto-discover from registry).
    j2534_dll_path: String,
    /// Path to the selected firmware file (.frf, .odx, or .bin).
    firmware_path: Option<PathBuf>,
    /// ECU data records populated by Connect.
    ecu_info: BTreeMap<String, String>,
    /// Active flash operation (drives the subscription).
    flash_op: Option<FlashOp>,
    /// Overall UI status.
    status: AppStatus,
    /// Scrollable log lines.
    log_lines: Vec<String>,
    /// Flash progress 0.0–1.0.
    progress: f32,
    /// Human-readable description of the current step.
    progress_step: String,
    /// Total block count for the current flash (used by BlockComplete).
    total_blocks: usize,
    /// Monotonically increasing counter, used as subscription id.
    op_id: u64,
}

impl Default for State {
    fn default() -> Self {
        State {
            selected_module: None,
            interface_kind: InterfaceKind::Panda,
            socketcan_name: String::new(),
            j2534_dll_path: String::new(),
            firmware_path: None,
            ecu_info: BTreeMap::new(),
            flash_op: None,
            status: AppStatus::Idle,
            log_lines: Vec::new(),
            progress: 0.0,
            progress_step: String::new(),
            total_blocks: 1,
            op_id: 0,
        }
    }
}

impl State {
    fn log(&mut self, msg: impl Into<String>) {
        let line = msg.into();
        tracing::info!("{}", line);
        self.log_lines.push(line);
    }

    fn build_interface(&self) -> Option<Interface> {
        match self.interface_kind {
            InterfaceKind::Panda => Some(Interface::Panda),
            InterfaceKind::SocketCan => {
                if self.socketcan_name.is_empty() {
                    None
                } else {
                    Some(Interface::SocketCan(self.socketcan_name.clone()))
                }
            }
            InterfaceKind::J2534 => {
                let dll = if self.j2534_dll_path.is_empty() {
                    None
                } else {
                    Some(self.j2534_dll_path.clone())
                };
                Some(Interface::J2534 { dll, bitrate: 500_000, native_isotp: false })
            }
            InterfaceKind::J2534IsoTp => {
                let dll = if self.j2534_dll_path.is_empty() {
                    None
                } else {
                    Some(self.j2534_dll_path.clone())
                };
                Some(Interface::J2534 { dll, bitrate: 500_000, native_isotp: true })
            }
        }
    }

    /// Whether the Connect button should be enabled.
    fn can_connect(&self) -> bool {
        self.selected_module.is_some() && self.build_interface().is_some()
            && !matches!(self.status, AppStatus::Connecting | AppStatus::Flashing)
    }

    /// Whether flash operation buttons should be enabled.
    fn can_flash(&self) -> bool {
        self.selected_module.is_some()
            && self.firmware_path.is_some()
            && self.build_interface().is_some()
            && !matches!(self.status, AppStatus::Connecting | AppStatus::Flashing)
    }

    /// Whether Unlock is enabled (needs patch_info on the module).
    fn can_unlock(&self) -> bool {
        self.can_flash()
            && self
                .selected_module
                .and_then(mqb_modules::get_flash_info)
                .map(|fi| fi.patch_info.is_some())
                .unwrap_or(false)
    }
}

// ─── Supporting types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceKind {
    Panda,
    SocketCan,
    J2534,
    J2534IsoTp,
}

#[derive(Default)]
enum AppStatus {
    #[default]
    Idle,
    Connecting,
    Connected,
    Flashing,
    Done,
    Error(String),
}

impl AppStatus {
    fn label(&self) -> String {
        match self {
            AppStatus::Idle => "Idle".into(),
            AppStatus::Connecting => "Connecting...".into(),
            AppStatus::Connected => "Connected".into(),
            AppStatus::Flashing => "Flashing...".into(),
            AppStatus::Done => "Done".into(),
            AppStatus::Error(e) => format!("Error: {e}"),
        }
    }
}

/// Everything needed to run a flash operation from the subscription.
#[derive(Clone)]
struct FlashOp {
    /// Unique id — used as iced subscription identity so each op gets a fresh subscription.
    id: u64,
    flash_info: &'static FlashInfo,
    blocks: Arc<Vec<PreparedBlockData>>,
    opts: FlashOptions,
}

// ─── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Message {
    ModuleSelected(&'static str),
    InterfaceKindChanged(InterfaceKind),
    SocketCanNameChanged(String),
    J2534DllPathChanged(String),
    BrowseFirmwarePressed,
    FirmwareSelected(Option<PathBuf>),
    ConnectPressed,
    ConnectResult(Result<BTreeMap<String, String>, String>),
    UnlockPressed,
    FullFlashPressed,
    CalFlashPressed,
    StockFlashPressed,
    FlashProgress(ProgressUpdate),
    ClearLog,
}

// ─── Update ──────────────────────────────────────────────────────────────────

fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::ModuleSelected(name) => {
            state.selected_module = Some(name);
            Task::none()
        }

        Message::InterfaceKindChanged(kind) => {
            state.interface_kind = kind;
            Task::none()
        }

        Message::SocketCanNameChanged(s) => {
            state.socketcan_name = s;
            Task::none()
        }

        Message::J2534DllPathChanged(s) => {
            state.j2534_dll_path = s;
            Task::none()
        }

        Message::BrowseFirmwarePressed => Task::future(async {
            let handle = rfd::AsyncFileDialog::new()
                .set_title("Select firmware file")
                .add_filter("Firmware files", &["frf", "odx", "bin"])
                .add_filter("FRF files", &["frf"])
                .add_filter("ODX files", &["odx"])
                .add_filter("BIN files", &["bin"])
                .add_filter("All files", &["*"])
                .pick_file()
                .await;
            Message::FirmwareSelected(handle.map(|h| h.path().to_path_buf()))
        }),

        Message::FirmwareSelected(path) => {
            state.firmware_path = path;
            Task::none()
        }

        Message::ConnectPressed => {
            let Some(module_name) = state.selected_module else {
                return Task::none();
            };
            let Some(flash_info) = mqb_modules::get_flash_info(module_name) else {
                return Task::none();
            };
            let Some(interface) = state.build_interface() else {
                return Task::none();
            };
            state.status = AppStatus::Connecting;
            state.log(format!("Connecting via {:?}...", interface));
            Task::future(async move {
                match read_ecu_data(flash_info, interface).await {
                    Ok(map) => {
                        let sorted: BTreeMap<String, String> = map.into_iter().collect();
                        Message::ConnectResult(Ok(sorted))
                    }
                    Err(e) => Message::ConnectResult(Err(e.to_string())),
                }
            })
        }

        Message::ConnectResult(Ok(info)) => {
            state.status = AppStatus::Connected;
            state.log(format!("Connected — {} data records read", info.len()));
            state.ecu_info = info;
            Task::none()
        }

        Message::ConnectResult(Err(e)) => {
            state.status = AppStatus::Error(e.clone());
            state.log(format!("Connect failed: {e}"));
            Task::none()
        }

        Message::FullFlashPressed => {
            start_flash_op(state, FlashKind::Full);
            Task::none()
        }

        Message::StockFlashPressed => {
            start_flash_op(state, FlashKind::Stock);
            Task::none()
        }

        Message::CalFlashPressed => {
            start_flash_op(state, FlashKind::Cal);
            Task::none()
        }

        Message::UnlockPressed => {
            start_flash_op(state, FlashKind::Unlock);
            Task::none()
        }

        Message::FlashProgress(update) => {
            handle_progress(state, update);
            Task::none()
        }

        Message::ClearLog => {
            state.log_lines.clear();
            Task::none()
        }
    }
}

// ─── Flash operation kinds ────────────────────────────────────────────────────

enum FlashKind {
    Full,
    Stock,
    Cal,
    Unlock,
}

/// Prepare blocks and set `state.flash_op` for the subscription to pick up.
fn start_flash_op(state: &mut State, kind: FlashKind) {
    let (Some(module_name), Some(firmware_path)) =
        (state.selected_module, state.firmware_path.clone())
    else {
        return;
    };
    let Some(flash_info) = mqb_modules::get_flash_info(module_name) else {
        state.status = AppStatus::Error(format!("Unknown module: {module_name}"));
        return;
    };
    let Some(interface) = state.build_interface() else {
        state.status = AppStatus::Error("No interface configured".into());
        return;
    };

    let prepared_blocks = match kind {
        FlashKind::Full => prepare_full_flash(&firmware_path, flash_info, state),
        FlashKind::Stock => prepare_stock_flash(&firmware_path, flash_info, state),
        FlashKind::Cal => prepare_cal_flash(&firmware_path, flash_info, state),
        FlashKind::Unlock => prepare_unlock(&firmware_path, flash_info, module_name, state),
    };

    let prepared_blocks = match prepared_blocks {
        Some(blocks) => blocks,
        None => return, // error already recorded in state
    };

    state.total_blocks = prepared_blocks.len();
    state.op_id += 1;
    state.flash_op = Some(FlashOp {
        id: state.op_id,
        flash_info,
        blocks: Arc::new(prepared_blocks),
        opts: FlashOptions {
            interface,
            patch_cboot: false, // handled by us before flash
            stmin_override: None,
            workshop_code: [0x20, 0x04, 0x20, 0x42, 0x04, 0x20, 0x42, 0xB1, 0x3D],
            progress_tx: None, // subscription fills this in
        },
    });
    state.status = AppStatus::Flashing;
    state.progress = 0.0;
    state.progress_step = "Starting...".into();
}

// ─── Block preparation helpers ───────────────────────────────────────────────

fn extract_raw_blocks(
    firmware_path: &Path,
    flash_info: &FlashInfo,
) -> Result<HashMap<u8, Vec<u8>>, String> {
    mqb_binfile::load_raw_blocks(firmware_path, flash_info)
        .map_err(|e| e.to_string())
}

/// Build a `PreparedBlockData` for a normal block (≤5): LZSS + AES encrypt.
fn make_prepared(
    block_num: u8,
    raw: &[u8],
    flash_info: &FlashInfo,
) -> PreparedBlockData {
    let encrypted = prepare_block_for_flash(raw, flash_info.crypto);
    let block_name = flash_info
        .block_number_to_name(block_num)
        .unwrap_or("UNKNOWN")
        .to_owned();
    PreparedBlockData {
        block_number: block_num,
        block_encrypted_bytes: encrypted,
        boxcode: String::new(),
        encryption_type: 0x0A,
        compression_type: 0x0A,
        should_erase: true,
        uds_checksum: flash_info.block_checksum(block_num).unwrap_or([0; 4]),
        block_name,
    }
}

/// Build a `PreparedBlockData` for a patch block (>5): AES encrypt only.
fn make_patch_prepared(block_num: u8, raw: &[u8], flash_info: &FlashInfo) -> PreparedBlockData {
    let encrypted = prepare_patch_for_flash(raw, flash_info.crypto);
    PreparedBlockData {
        block_number: block_num,
        block_encrypted_bytes: encrypted,
        boxcode: String::new(),
        encryption_type: 0x0A,
        compression_type: 0x0A,
        should_erase: false,
        uds_checksum: [0; 4],
        block_name: "UNLOCK_PATCH".to_owned(),
    }
}

/// Fix the checksum for a single raw block using the appropriate algorithm.
/// Returns the (possibly patched) bytes.
fn fix_block_checksum(
    flash_info: &FlashInfo,
    raw: Vec<u8>,
    block_num: u8,
) -> Result<Vec<u8>, String> {
    let (state, fixed) = match flash_info.checksum_kind {
        ChecksumKind::Simos => validate_simos(flash_info, &raw, block_num, true),
        ChecksumKind::Dq381 => {
            let base = mqb_modules::modules::dq381::BLOCK_BASE_ADDRESSES
                .iter()
                .find(|(n, _)| *n == block_num)
                .map(|(_, a)| *a)
                .unwrap_or(0);
            validate_dq381(&raw, base, true)
        }
        ChecksumKind::Dsg => validate_dsg(&raw, true),
        ChecksumKind::Haldex => validate_haldex(&raw, block_num, flash_info, true),
    };
    match state {
        ChecksumState::Valid | ChecksumState::Fixed => Ok(fixed.into_owned()),
        ChecksumState::Invalid => Err(format!("Block {block_num}: checksum invalid, could not fix")),
        ChecksumState::Failed => Err(format!("Block {block_num}: checksum algorithm failed")),
    }
}

fn prepare_full_flash(
    firmware_path: &Path,
    flash_info: &FlashInfo,
    state: &mut State,
) -> Option<Vec<PreparedBlockData>> {
    state.log("Extracting blocks from firmware file...");
    let mut raw_blocks = match extract_raw_blocks(firmware_path, flash_info) {
        Ok(b) => b,
        Err(e) => {
            state.status = AppStatus::Error(e.clone());
            state.log(format!("Firmware extraction failed: {e}"));
            return None;
        }
    };

    // For Simos ECUs: patch CBOOT and fix its checksum.
    if matches!(flash_info.checksum_kind, ChecksumKind::Simos) {
        if let Some(cboot_num) = flash_info.block_to_number("CBOOT") {
            if let Some(cboot_raw) = raw_blocks.remove(&cboot_num) {
                match mqb_cboot::patch_cboot(&cboot_raw) {
                    Ok(patched) => {
                        match fix_block_checksum(flash_info, patched, cboot_num) {
                            Ok(fixed) => {
                                raw_blocks.insert(cboot_num, fixed);
                                state.log("CBOOT: sample-mode patch applied and checksum fixed");
                            }
                            Err(e) => {
                                state.status = AppStatus::Error(e.clone());
                                state.log(format!("CBOOT checksum fix failed: {e}"));
                                return None;
                            }
                        }
                    }
                    Err(e) => {
                        state.status = AppStatus::Error(e.to_string());
                        state.log(format!("CBOOT patch failed: {e}"));
                        return None;
                    }
                }
            }
        }
    }

    let mut prepared: Vec<PreparedBlockData> = raw_blocks
        .iter()
        .map(|(&num, raw)| make_prepared(num, raw, flash_info))
        .collect();
    prepared.sort_by_key(|b| b.block_number);
    state.log(format!("Prepared {} blocks for Full Flash", prepared.len()));
    Some(prepared)
}

fn prepare_stock_flash(
    firmware_path: &Path,
    flash_info: &FlashInfo,
    state: &mut State,
) -> Option<Vec<PreparedBlockData>> {
    state.log("Extracting blocks from firmware file (Stock Flash)...");
    let raw_blocks = match extract_raw_blocks(firmware_path, flash_info) {
        Ok(b) => b,
        Err(e) => {
            state.status = AppStatus::Error(e.clone());
            state.log(format!("Firmware extraction failed: {e}"));
            return None;
        }
    };
    let mut prepared: Vec<PreparedBlockData> = raw_blocks
        .iter()
        .map(|(&num, raw)| make_prepared(num, raw, flash_info))
        .collect();
    prepared.sort_by_key(|b| b.block_number);
    state.log(format!("Prepared {} blocks for Stock Flash", prepared.len()));
    Some(prepared)
}

fn prepare_cal_flash(
    firmware_path: &Path,
    flash_info: &FlashInfo,
    state: &mut State,
) -> Option<Vec<PreparedBlockData>> {
    state.log("Extracting CAL block from firmware file...");
    let raw_blocks = match extract_raw_blocks(firmware_path, flash_info) {
        Ok(b) => b,
        Err(e) => {
            state.status = AppStatus::Error(e.clone());
            state.log(format!("Firmware extraction failed: {e}"));
            return None;
        }
    };
    // CAL is block 5
    let cal_raw = match raw_blocks.get(&5) {
        Some(b) => b,
        None => {
            state.status = AppStatus::Error("FRF does not contain CAL (block 5)".into());
            state.log("No CAL block in FRF");
            return None;
        }
    };
    let prepared = vec![make_prepared(5, cal_raw, flash_info)];
    state.log("Prepared CAL block for CAL Flash");
    Some(prepared)
}

fn prepare_unlock(
    firmware_path: &Path,
    flash_info: &FlashInfo,
    module_name: &str,
    state: &mut State,
) -> Option<Vec<PreparedBlockData>> {
    let patch_info = match flash_info.patch_info.as_ref() {
        Some(pi) => pi,
        None => {
            state.status =
                AppStatus::Error(format!("Module '{module_name}' does not support unlock"));
            state.log("No patch_info for unlock");
            return None;
        }
    };

    state.log("Extracting blocks from firmware file (Unlock)...");
    let raw_blocks = match extract_raw_blocks(firmware_path, flash_info) {
        Ok(b) => b,
        Err(e) => {
            state.status = AppStatus::Error(e.clone());
            state.log(format!("Firmware extraction failed: {e}"));
            return None;
        }
    };

    // Validate box code from CAL (block 5)
    if let Some(cal_bytes) = raw_blocks.get(&5) {
        if let Some((box_start, box_end)) = flash_info.box_code_location(5) {
            if box_end <= cal_bytes.len() {
                let file_box_code =
                    std::str::from_utf8(&cal_bytes[box_start..box_end])
                        .unwrap_or("")
                        .trim();
                let expected_prefix = patch_info.patch_box_code.split('_').next().unwrap_or("");
                if file_box_code != expected_prefix {
                    let msg = format!(
                        "Box code mismatch: file='{file_box_code}', required='{expected_prefix}'"
                    );
                    state.status = AppStatus::Error(msg.clone());
                    state.log(msg);
                    return None;
                }
                state.log(format!("Box code validated: {file_box_code}"));
            }
        }
    }

    // Build unlock order: [1, 2, 3, 4, pbi+5, 5]
    let patch_block_num = patch_info.patch_block_index + 5;
    let mut prepared = Vec::new();

    for &block_num in &[1u8, 2, 3, 4] {
        let raw = match raw_blocks.get(&block_num) {
            Some(b) => b,
            None => {
                state.status =
                    AppStatus::Error(format!("FRF is missing block {block_num}"));
                state.log(format!("Missing block {block_num} in FRF"));
                return None;
            }
        };
        prepared.push(make_prepared(block_num, raw, flash_info));
    }

    // Patch block
    prepared.push(make_patch_prepared(patch_block_num, patch_info.patch_bytes, flash_info));

    // CAL (block 5)
    if let Some(cal_raw) = raw_blocks.get(&5) {
        prepared.push(make_prepared(5, cal_raw, flash_info));
    } else {
        state.status = AppStatus::Error("FRF is missing CAL (block 5)".into());
        return None;
    }

    state.log(format!("Prepared {} blocks for Unlock", prepared.len()));
    Some(prepared)
}

// ─── Progress handling ────────────────────────────────────────────────────────

fn handle_progress(state: &mut State, update: ProgressUpdate) {
    match &update {
        ProgressUpdate::Connecting => {
            state.progress_step = "Connecting...".into();
            state.log("Connecting to ECU...");
        }
        ProgressUpdate::Authenticating => {
            state.progress_step = "Authenticating (SA2)...".into();
            state.log("Performing SA2 seed-key authentication...");
        }
        ProgressUpdate::FlashingBlock { name, index, total } => {
            state.total_blocks = *total;
            state.progress = *index as f32 / (*total).max(1) as f32;
            state.progress_step =
                format!("Flashing block {} ({}/{})", name, index + 1, total);
            state.log(format!("Flashing {} ({}/{})", name, index + 1, total));
        }
        ProgressUpdate::BlockComplete { index } => {
            state.progress = (*index + 1) as f32 / state.total_blocks.max(1) as f32;
        }
        ProgressUpdate::Verifying => {
            state.progress_step = "Verifying programming dependencies...".into();
            state.log("Verifying programming dependencies...");
        }
        ProgressUpdate::Complete => {
            state.progress = 1.0;
            state.progress_step = "Complete!".into();
            state.status = AppStatus::Done;
            state.flash_op = None;
            state.log("Flash sequence complete!");
        }
        ProgressUpdate::Error(e) => {
            state.progress_step = format!("Error: {e}");
            state.status = AppStatus::Error(e.clone());
            state.flash_op = None;
            state.log(format!("Flash failed: {e}"));
        }
    }
}

// ─── Subscription ─────────────────────────────────────────────────────────────

fn subscription(state: &State) -> Subscription<Message> {
    let Some(op) = &state.flash_op else {
        return Subscription::none();
    };

    let flash_info = op.flash_info;
    let blocks_arc = Arc::clone(&op.blocks);
    let mut opts = op.opts.clone();
    let id = op.id;

    Subscription::run_with_id(
        id,
        iced::stream::channel(64, move |mut output| async move {
            use iced::futures::SinkExt;

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ProgressUpdate>();
            opts.progress_tx = Some(tx.clone());

            let blocks_vec: Vec<PreparedBlockData> = (*blocks_arc).clone();

            tokio::spawn(async move {
                let result = flash_blocks(flash_info, blocks_vec, opts).await;
                match result {
                    Ok(()) => {
                        let _ = tx.send(ProgressUpdate::Complete);
                    }
                    Err(e) => {
                        let _ = tx.send(ProgressUpdate::Error(e.to_string()));
                    }
                }
            });

            while let Some(update) = rx.recv().await {
                let is_done = matches!(
                    update,
                    ProgressUpdate::Complete | ProgressUpdate::Error(_)
                );
                let _ = output.send(Message::FlashProgress(update)).await;
                if is_done {
                    break;
                }
            }

            // Keep the future alive until iced drops this subscription.
            std::future::pending::<()>().await
        }),
    )
}

// ─── View ─────────────────────────────────────────────────────────────────────

fn view(state: &State) -> Element<'_, Message> {
    let module_names: Vec<&'static str> = mqb_modules::module_names();

    // ── Configuration panel ────────────────────────────────────────────────
    let module_picker = row![
        text("Module:").width(80),
        pick_list(module_names, state.selected_module, Message::ModuleSelected)
            .width(160)
            .placeholder("Select module…"),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    let iface_row = row![
        radio("Panda", InterfaceKind::Panda, Some(state.interface_kind), Message::InterfaceKindChanged),
        radio(
            "J2534",
            InterfaceKind::J2534,
            Some(state.interface_kind),
            Message::InterfaceKindChanged,
        ),
        radio(
            "J2534 ISO-TP",
            InterfaceKind::J2534IsoTp,
            Some(state.interface_kind),
            Message::InterfaceKindChanged,
        ),
        text_input("DLL path (blank = auto)", &state.j2534_dll_path)
            .on_input(Message::J2534DllPathChanged)
            .width(200),
        radio(
            "SocketCAN",
            InterfaceKind::SocketCan,
            Some(state.interface_kind),
            Message::InterfaceKindChanged,
        ),
        text_input("can0", &state.socketcan_name)
            .on_input(Message::SocketCanNameChanged)
            .width(100),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    let connect_btn = button(text("Connect & Identify ECU").size(14))
        .on_press_maybe(state.can_connect().then_some(Message::ConnectPressed))
        .padding([8, 16]);

    let config_section = section(
        "Configuration",
        column![module_picker, iface_row, connect_btn].spacing(10),
    );

    // ── ECU Info ───────────────────────────────────────────────────────────
    let ecu_rows: Vec<Element<'_, Message>> = state
        .ecu_info
        .iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, v)| {
            row![
                text(k).width(280),
                text(v),
            ]
            .spacing(8)
            .into()
        })
        .collect();

    let ecu_content: Element<'_, Message> = if ecu_rows.is_empty() {
        text("(not connected)").into()
    } else {
        scrollable(
            column(ecu_rows).spacing(4),
        )
        .height(120)
        .into()
    };
    let ecu_section = section("ECU Info", ecu_content);

    // ── Firmware file ──────────────────────────────────────────────────────
    let firmware_label = state
        .firmware_path
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "(none selected)".into());

    let firmware_section = section(
        "Firmware File (.frf / .odx / .bin)",
        row![
            button("Browse…").on_press(Message::BrowseFirmwarePressed).padding([6, 14]),
            text(firmware_label),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    );

    // ── Flash operations ───────────────────────────────────────────────────
    let flash_enabled = state.can_flash();
    let unlock_enabled = state.can_unlock();

    let ops_section = section(
        "Flash Operations",
        row![
            button(text("Unlock").size(14))
                .on_press_maybe(unlock_enabled.then_some(Message::UnlockPressed))
                .padding([8, 16]),
            button(text("Full Flash").size(14))
                .on_press_maybe(flash_enabled.then_some(Message::FullFlashPressed))
                .padding([8, 16]),
            button(text("CAL Flash").size(14))
                .on_press_maybe(flash_enabled.then_some(Message::CalFlashPressed))
                .padding([8, 16]),
            button(text("Stock Flash").size(14))
                .on_press_maybe(flash_enabled.then_some(Message::StockFlashPressed))
                .padding([8, 16]),
        ]
        .spacing(10),
    );

    // ── Progress ───────────────────────────────────────────────────────────
    let status_line = row![
        text("Status:").width(60),
        text(state.status.label()),
    ]
    .spacing(8);

    let progress_label = if state.progress_step.is_empty() {
        text("Idle")
    } else {
        text(&state.progress_step)
    };

    let log_entries: Vec<Element<'_, Message>> = state
        .log_lines
        .iter()
        .rev()
        .take(200)
        .rev()
        .map(|line| text(line).size(12).into())
        .collect();

    let log_view: Element<'_, Message> = if log_entries.is_empty() {
        text("(no log entries)").size(12).into()
    } else {
        scrollable(column(log_entries).spacing(2))
            .height(150)
            .into()
    };

    let progress_section = section(
        "Progress",
        column![
            status_line,
            progress_label,
            progress_bar(0.0..=1.0, state.progress).width(Length::Fill),
            log_view,
            button("Clear Log")
                .on_press(Message::ClearLog)
                .padding([4, 12]),
        ]
        .spacing(8),
    );

    // ── Root layout ────────────────────────────────────────────────────────
    scrollable(
        container(
            column![
                config_section,
                ecu_section,
                firmware_section,
                ops_section,
                progress_section,
            ]
            .spacing(16)
            .padding(20)
            .width(Length::Fill),
        )
        .width(Length::Fill),
    )
    .into()
}

/// Helper: wrap content in a titled section box.
fn section<'a>(
    title: &'a str,
    content: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    column![
        text(title).size(17),
        horizontal_rule(1),
        content.into(),
    ]
    .spacing(6)
    .into()
}
