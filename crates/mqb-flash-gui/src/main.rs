//! mqb-flash-gui — a wizard-style flashing tool for VW control modules.
//!
//! The wizard walks one path, one decision per screen:
//!
//! ```text
//! Interface -> Identify -> Unlock -> Operation -> Firmware -> Preflight -> Confirm -> Flashing -> Done
//! ```
//!
//! Design rules, in priority order:
//!
//! * **Nothing is flashed that the user did not see described first.** The
//!   Confirm screen lists the module, the file, every block that will be
//!   written, and the outcome of every safety check.
//! * **The ECU is identified, not chosen.** The wizard scans the bus. The user
//!   only picks when two modules are genuinely indistinguishable (DQ250 vs
//!   DQ381 share CAN addresses and nothing in the response tells them apart).
//! * **Warnings never silently become blocks.** A risky immobilizer verdict
//!   requires an explicit confirmation; it does not disable the button. A check
//!   that could not run reports that it could not run, and is not treated as a
//!   failure.
//! * **Work happens off the UI thread.** Preparing a Simos18 full flash means
//!   LZSS-compressing ~4 MB; doing that inside `update` freezes the window.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use iced::widget::rule::horizontal as horizontal_rule;
use iced::widget::{
    button, column, container, progress_bar, radio, row, scrollable, text, text_input, Space,
};
use iced::{Alignment, Element, Length, Subscription, Task};

use mqb_flash_uds::identify::{Candidate, ChannelIdentification};
use mqb_flash_uds::immo::{ImmoReport, ImmoSnapshot, ImmoSupport, Severity};
use mqb_flash_uds::unlock::{UnlockProbe, UnlockState};
use mqb_flash_uds::{
    flash_blocks, prepare_block, prepare_patch_block, FlashOptions, Interface, ProbeKind,
    ProbeOutcome, ProgressUpdate, ScanProgress,
};
use mqb_modules::{FlashInfo, PreparedBlockData};

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive("mqb_flash=info".parse().unwrap())
                .from_env_lossy()
                .add_directive("wgpu_core=warn".parse().unwrap())
                .add_directive("wgpu_hal=warn".parse().unwrap())
                .add_directive("naga=warn".parse().unwrap()),
        )
        .init();
    iced::application(State::default, update, view)
        .title("MQB Flash")
        .subscription(subscription)
        .window_size((900.0_f32, 780.0_f32))
        .run()
}

// ─── Steps ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Interface,
    Identify,
    Unlock,
    Operation,
    Firmware,
    Preflight,
    Confirm,
    Flashing,
    Done,
}

impl Step {
    fn title(self) -> &'static str {
        match self {
            Step::Interface => "Connect an adapter",
            Step::Identify => "Identify the control module",
            Step::Unlock => "Unlock status",
            Step::Operation => "What do you want to flash?",
            Step::Firmware => "Choose the firmware file",
            Step::Preflight => "Safety checks",
            Step::Confirm => "Confirm",
            Step::Flashing => "Flashing",
            Step::Done => "Finished",
        }
    }

    /// One sentence telling the user what this screen is for.
    fn blurb(self) -> &'static str {
        match self {
            Step::Interface => {
                "Pick the interface you are using to reach the car. Nothing is sent to the \
                 vehicle on this screen."
            }
            Step::Identify => {
                "The wizard reads identification records from each control module address \
                 and works out what is connected."
            }
            Step::Unlock => {
                "A Simos ECU only accepts modified software once its bootloader has been \
                 unlocked. This checks whether that has already been done."
            }
            Step::Operation => {
                "A calibration flash writes only the tune. A full flash rewrites the \
                 application software as well, and a relock does the same without patching \
                 the bootloader. All of them rewrite the calibration area, so all are \
                 checked against the immobilizer."
            }
            Step::Firmware => "Choose the file to write. It is inspected before anything is sent.",
            Step::Preflight => {
                "Checksums are corrected and the ECU is checked for conditions that would \
                 leave it unable to start."
            }
            Step::Confirm => "This is exactly what will be written. Nothing has been sent yet.",
            Step::Flashing => {
                "Do not disconnect the adapter, switch off the ignition, or close this window."
            }
            Step::Done => "",
        }
    }
}

/// Which flash the user asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    /// Every block in the file, with the CBOOT sample-mode patch applied.
    FullFlash,
    /// Every block in the file, with CBOOT written exactly as the file has it
    /// — which puts the ECU back to validating signatures.
    Relock,
    /// The calibration block only.
    CalibrationFlash,
    /// Write the unlock patch.
    Unlock,
}

impl Operation {
    fn label(self) -> &'static str {
        match self {
            Operation::FullFlash => "Full flash",
            Operation::Relock => "Relock",
            Operation::CalibrationFlash => "Calibration flash",
            Operation::Unlock => "Unlock",
        }
    }
}

// ─── Interface selection ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceKind {
    Panda,
    J2534,
    J2534IsoTp,
    SocketCan,
}

// ─── State ───────────────────────────────────────────────────────────────────

struct State {
    step: Step,
    /// Set when a step is waiting on the bus; disables navigation.
    busy: Option<String>,
    error: Option<String>,

    // Interface
    interface_kind: InterfaceKind,
    socketcan_name: String,
    j2534_dll_path: String,
    stmin_input: String,

    // Identification
    scan_results: Vec<ChannelIdentification>,
    /// Index into the chosen channel's candidate list.
    chosen_candidate: Option<usize>,
    chosen_channel: Option<usize>,

    // Unlock
    unlock: Option<UnlockProbe>,
    unlock_file: Option<PathBuf>,
    unlock_file_error: Option<String>,

    // Operation + firmware
    operation: Option<Operation>,
    firmware_path: Option<PathBuf>,
    firmware: Option<FirmwareInfo>,

    // Preflight
    prepared: Option<Arc<Vec<PreparedBlockData>>>,
    prep_notes: Vec<String>,
    immo_before: Option<ImmoSnapshot>,
    immo_report: Option<ImmoReport>,
    risk_acknowledged: bool,

    // Flashing
    flash_op: Option<FlashOp>,
    progress: f32,
    progress_step: String,
    log_lines: Vec<String>,
    total_blocks: usize,
    block_progress_base: f32,
    op_id: u64,
    finished_ok: bool,
    post_flash_findings: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        State {
            step: Step::Interface,
            busy: None,
            error: None,
            interface_kind: InterfaceKind::J2534IsoTp,
            socketcan_name: String::new(),
            j2534_dll_path: String::new(),
            stmin_input: String::new(),
            scan_results: Vec::new(),
            chosen_candidate: None,
            chosen_channel: None,
            unlock: None,
            unlock_file: None,
            unlock_file_error: None,
            operation: None,
            firmware_path: None,
            firmware: None,
            prepared: None,
            prep_notes: Vec::new(),
            immo_before: None,
            immo_report: None,
            risk_acknowledged: false,
            flash_op: None,
            progress: 0.0,
            progress_step: String::new(),
            log_lines: Vec::new(),
            total_blocks: 1,
            block_progress_base: 0.0,
            op_id: 0,
            finished_ok: false,
            post_flash_findings: Vec::new(),
        }
    }
}

impl State {
    fn log(&mut self, msg: impl Into<String>) {
        let line = msg.into();
        tracing::info!("{}", line);
        self.log_lines.push(line);
    }

    fn stmin_override(&self) -> Option<u32> {
        let t = self.stmin_input.trim();
        if t.is_empty() {
            None // fall back to the module's own default
        } else {
            t.parse::<u32>().ok()
        }
    }

    fn interface(&self) -> Option<Interface> {
        match self.interface_kind {
            InterfaceKind::Panda => Some(Interface::Panda),
            InterfaceKind::SocketCan => (!self.socketcan_name.trim().is_empty())
                .then(|| Interface::SocketCan(self.socketcan_name.trim().to_owned())),
            InterfaceKind::J2534 | InterfaceKind::J2534IsoTp => {
                let dll = (!self.j2534_dll_path.trim().is_empty())
                    .then(|| self.j2534_dll_path.trim().to_owned());
                Some(Interface::J2534 {
                    dll,
                    bitrate: 500_000,
                    native_isotp: matches!(self.interface_kind, InterfaceKind::J2534IsoTp),
                })
            }
        }
    }

    /// The candidate the user is proceeding with, if one is settled.
    fn selected(&self) -> Option<&Candidate> {
        let ch = self.scan_results.get(self.chosen_channel?)?;
        ch.candidates.get(self.chosen_candidate?)
    }

    fn flash_info(&self) -> Option<&'static FlashInfo> {
        self.selected().map(|c| c.flash_info)
    }

    /// Whether the current step's Next button should be enabled.
    fn can_advance(&self) -> bool {
        if self.busy.is_some() {
            return false;
        }
        match self.step {
            Step::Interface => self.interface().is_some(),
            Step::Identify => self.selected().is_some(),
            // A locked ECU may still proceed — the user may want to unlock, and
            // the operation screen offers that. An Unknown result may proceed
            // too: the check is advisory and fails open.
            Step::Unlock => self.unlock.is_some(),
            Step::Operation => self.operation.is_some(),
            Step::Firmware => self.firmware.is_some(),
            Step::Preflight => {
                self.prepared.is_some() && (!self.preflight_has_risk() || self.risk_acknowledged)
            }
            Step::Confirm => self.prepared.is_some(),
            Step::Flashing => false,
            Step::Done => false,
        }
    }

    fn preflight_has_risk(&self) -> bool {
        self.immo_report
            .as_ref()
            .is_some_and(|r| r.findings.iter().any(|f| f.severity == Severity::Warn))
    }

    /// Whether the immobilizer pre-flight applies to the pending operation.
    fn immo_check_applies_now(&self) -> bool {
        match (self.flash_info(), &self.firmware, self.operation) {
            (Some(fi), Some(fw), Some(op)) => immo_check_applies(fi, fw, op),
            _ => false,
        }
    }

    /// Whether an unlock step applies to the identified module at all.
    fn unlock_applies(&self) -> bool {
        self.flash_info()
            .is_some_and(mqb_flash_uds::unlock::supports_unlock)
    }
}

// ─── Firmware inspection ─────────────────────────────────────────────────────

/// What could be learned about a user-supplied file without flashing it.
#[derive(Debug, Clone)]
struct FirmwareInfo {
    path: PathBuf,
    /// Raw block bytes by block number.
    blocks: HashMap<u8, Vec<u8>>,
    /// Box code read out of the calibration block, when the module has one.
    box_code: Option<String>,
    /// `(block name, software version)` for every block that carries one.
    versions: Vec<(String, String)>,
}

impl FirmwareInfo {
    fn block_names(&self, flash_info: &FlashInfo) -> Vec<String> {
        let mut nums: Vec<u8> = self.blocks.keys().copied().collect();
        nums.sort_unstable();
        nums.iter()
            .map(|n| {
                flash_info
                    .block_number_to_name(*n)
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|| format!("block {n}"))
            })
            .collect()
    }
}

fn inspect_firmware(path: &Path, flash_info: &'static FlashInfo) -> Result<FirmwareInfo, String> {
    let blocks = mqb_binfile::load_raw_blocks(path, flash_info).map_err(|e| e.to_string())?;
    if blocks.is_empty() {
        return Err("No flashable blocks were found in this file.".into());
    }

    let box_code = flash_info
        .block_to_number("CAL")
        .and_then(|cal| Some((cal, blocks.get(&cal)?)))
        .and_then(|(cal, bytes)| {
            let (s, e) = flash_info.box_code_location(cal)?;
            // Several modules have no box code field at all; it reads as (0, 0).
            if e <= s || e > bytes.len() {
                return None;
            }
            Some(String::from_utf8_lossy(&bytes[s..e]).trim().to_owned())
        })
        .filter(|s| !s.is_empty());

    let mut versions = Vec::new();
    let mut nums: Vec<u8> = blocks.keys().copied().collect();
    nums.sort_unstable();
    for n in nums {
        let Some((s, e)) = flash_info.software_version_location(n) else {
            continue;
        };
        if e <= s {
            continue;
        }
        let Some(bytes) = blocks.get(&n) else {
            continue;
        };
        if e > bytes.len() {
            continue;
        }
        let v = String::from_utf8_lossy(&bytes[s..e]).trim().to_owned();
        if !v.is_empty() {
            let name = flash_info
                .block_number_to_name(n)
                .map(|s| s.to_owned())
                .unwrap_or_else(|| format!("block {n}"));
            versions.push((name, v));
        }
    }

    Ok(FirmwareInfo {
        path: path.to_path_buf(),
        blocks,
        box_code,
        versions,
    })
}

/// The box code an unlock file must carry, for the identified module.
fn required_unlock_box_code(flash_info: &FlashInfo) -> Option<&'static str> {
    flash_info.patch_info.as_ref().map(|p| p.patch_box_code)
}

// ─── Flash operation plumbing ────────────────────────────────────────────────

#[derive(Clone)]
struct FlashOp {
    id: u64,
    flash_info: &'static FlashInfo,
    blocks: Arc<Vec<PreparedBlockData>>,
    opts: FlashOptions,
}

impl std::hash::Hash for FlashOp {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// ─── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Message {
    // Navigation
    Next,
    Back,
    StartOver,

    // Interface
    InterfaceKindChanged(InterfaceKind),
    SocketCanNameChanged(String),
    J2534DllPathChanged(String),
    StminChanged(String),

    // Identify
    ScanProgress(ScanProgress),
    ScanFinished(Vec<ChannelIdentification>),
    CandidateChosen(usize, usize),

    // Unlock
    UnlockProbeFinished(Result<UnlockProbe, String>),
    BrowseUnlockFile,
    UnlockFileSelected(Option<PathBuf>),

    // Operation / firmware
    OperationChosen(Operation),
    BrowseFirmware,
    FirmwareSelected(Option<PathBuf>),

    // Preflight
    PreflightFinished(Box<PreflightOutcome>),
    AcknowledgeRisk(bool),

    // Flashing
    FlashProgress(ProgressUpdate),
    PostFlashChecked(Vec<String>),
}

/// Everything the (off-thread) preflight produced.
#[derive(Debug)]
struct PreflightOutcome {
    prepared: Result<Vec<PreparedBlockData>, String>,
    notes: Vec<String>,
    immo_before: Option<ImmoSnapshot>,
    immo_report: Option<ImmoReport>,
}

impl Clone for PreflightOutcome {
    fn clone(&self) -> Self {
        PreflightOutcome {
            prepared: self.prepared.clone(),
            notes: self.notes.clone(),
            immo_before: self.immo_before.clone(),
            immo_report: self.immo_report.clone(),
        }
    }
}

// ─── Update ──────────────────────────────────────────────────────────────────

fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::InterfaceKindChanged(k) => {
            state.interface_kind = k;
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
        Message::StminChanged(s) => {
            state.stmin_input = s;
            Task::none()
        }

        Message::Next => advance(state),
        Message::Back => {
            state.error = None;
            state.step = previous_step(state);
            Task::none()
        }
        Message::StartOver => {
            let keep_iface = (
                state.interface_kind,
                state.socketcan_name.clone(),
                state.j2534_dll_path.clone(),
                state.stmin_input.clone(),
            );
            *state = State::default();
            state.interface_kind = keep_iface.0;
            state.socketcan_name = keep_iface.1;
            state.j2534_dll_path = keep_iface.2;
            state.stmin_input = keep_iface.3;
            Task::none()
        }

        Message::ScanProgress(p) => {
            match p {
                ScanProgress::ChannelStarted {
                    channel,
                    index,
                    total,
                } => {
                    state.busy = Some(format!(
                        "Probing {} — address {} of {}…",
                        channel.label,
                        index + 1,
                        total
                    ));
                }
                ScanProgress::ChannelAnswered { channel } => {
                    state.log(format!("{} answered", channel.label));
                }
                ScanProgress::ChannelSilent { channel } => {
                    state.log(format!("{} did not answer", channel.label));
                }
            }
            Task::none()
        }

        Message::ScanFinished(results) => {
            state.busy = None;
            if results.is_empty() {
                state.error = Some(
                    "No supported control module answered. Check the adapter, the ignition, \
                     and that the vehicle is awake."
                        .into(),
                );
            } else {
                // Pre-select when there is nothing to decide.
                if results.len() == 1 && results[0].candidates.len() == 1 {
                    state.chosen_channel = Some(0);
                    state.chosen_candidate = Some(0);
                }
                state.error = None;
            }
            state.scan_results = results;
            Task::none()
        }
        Message::CandidateChosen(ch, idx) => {
            state.chosen_channel = Some(ch);
            state.chosen_candidate = Some(idx);
            // Choosing a different module invalidates everything downstream.
            state.unlock = None;
            state.operation = None;
            state.firmware = None;
            state.prepared = None;
            Task::none()
        }

        Message::UnlockProbeFinished(result) => {
            state.busy = None;
            match result {
                Ok(p) => {
                    state.log(format!(
                        "Unlock check: {} ({})",
                        p.state.label(),
                        p.hardware_version.clone().unwrap_or_else(|| "—".into())
                    ));
                    state.unlock = Some(p);
                }
                Err(e) => state.error = Some(e),
            }
            Task::none()
        }

        Message::BrowseUnlockFile => Task::future(async {
            let handle = rfd::AsyncFileDialog::new()
                .set_title("Select the stock firmware file for the unlock")
                .add_filter("Firmware files", &["frf", "odx", "bin"])
                .pick_file()
                .await;
            Message::UnlockFileSelected(handle.map(|h| h.path().to_path_buf()))
        }),
        Message::UnlockFileSelected(path) => {
            state.unlock_file_error = None;
            let Some(path) = path else {
                return Task::none();
            };
            let Some(flash_info) = state.flash_info() else {
                return Task::none();
            };
            match inspect_firmware(&path, flash_info) {
                Ok(info) => match validate_unlock_file(flash_info, &info) {
                    Ok(()) => {
                        // Deliberately not `firmware_path`: that field tracks
                        // the file chosen on the Firmware step, and keeping
                        // them apart is what distinguishes an unlock file.
                        state.unlock_file = Some(path);
                        state.firmware = Some(info);
                    }
                    Err(e) => {
                        state.unlock_file = None;
                        state.unlock_file_error = Some(e);
                    }
                },
                Err(e) => {
                    state.unlock_file = None;
                    state.unlock_file_error = Some(e);
                }
            }
            Task::none()
        }

        Message::OperationChosen(op) => {
            state.operation = Some(op);
            state.prepared = None;
            // The unlock screen puts the unlock file into `firmware`. Switching
            // to a flash operation must not silently reuse it as the file to
            // write — that would flash stock software the user never chose.
            if op != Operation::Unlock && state.firmware_path.is_none() {
                state.firmware = None;
            }
            Task::none()
        }

        Message::BrowseFirmware => Task::future(async {
            let handle = rfd::AsyncFileDialog::new()
                .set_title("Select firmware file")
                .add_filter("Firmware files", &["frf", "odx", "bin"])
                .add_filter("All files", &["*"])
                .pick_file()
                .await;
            Message::FirmwareSelected(handle.map(|h| h.path().to_path_buf()))
        }),
        Message::FirmwareSelected(path) => {
            let Some(path) = path else {
                return Task::none();
            };
            let Some(flash_info) = state.flash_info() else {
                return Task::none();
            };
            state.firmware_path = Some(path.clone());
            match inspect_firmware(&path, flash_info) {
                Ok(info) => {
                    state.error = None;
                    state.firmware = Some(info);
                }
                Err(e) => {
                    state.firmware = None;
                    state.error = Some(format!("Could not read this file: {e}"));
                }
            }
            state.prepared = None;
            Task::none()
        }

        Message::PreflightFinished(outcome) => {
            state.busy = None;
            let outcome = *outcome;
            state.prep_notes = outcome.notes;
            state.immo_before = outcome.immo_before;
            state.immo_report = outcome.immo_report;
            match outcome.prepared {
                Ok(blocks) => {
                    state.total_blocks = blocks.len();
                    state.prepared = Some(Arc::new(blocks));
                    state.error = None;
                }
                Err(e) => {
                    state.prepared = None;
                    state.error = Some(e);
                }
            }
            Task::none()
        }
        Message::AcknowledgeRisk(v) => {
            state.risk_acknowledged = v;
            Task::none()
        }

        Message::FlashProgress(update) => handle_progress(state, update),

        Message::PostFlashChecked(findings) => {
            state.post_flash_findings = findings;
            Task::none()
        }
    }
}

/// Move to the next step, kicking off whatever work that step needs.
fn advance(state: &mut State) -> Task<Message> {
    state.error = None;
    match state.step {
        Step::Interface => {
            state.step = Step::Identify;
            start_scan(state)
        }
        Step::Identify => {
            if state.unlock_applies() {
                state.step = Step::Unlock;
                start_unlock_probe(state)
            } else {
                state.step = Step::Operation;
                Task::none()
            }
        }
        Step::Unlock => {
            state.step = Step::Operation;
            Task::none()
        }
        Step::Operation => {
            // The unlock file was already chosen and validated on the unlock
            // screen, so an unlock skips straight to the preflight.
            if state.operation == Some(Operation::Unlock) && state.firmware.is_some() {
                state.step = Step::Preflight;
                start_preflight(state)
            } else {
                state.step = Step::Firmware;
                Task::none()
            }
        }
        Step::Firmware => {
            state.step = Step::Preflight;
            start_preflight(state)
        }
        Step::Preflight => {
            state.step = Step::Confirm;
            Task::none()
        }
        Step::Confirm => start_flash(state),
        Step::Flashing | Step::Done => Task::none(),
    }
}

fn previous_step(state: &State) -> Step {
    match state.step {
        Step::Interface => Step::Interface,
        Step::Identify => Step::Interface,
        Step::Unlock => Step::Identify,
        Step::Operation => {
            if state.unlock_applies() {
                Step::Unlock
            } else {
                Step::Identify
            }
        }
        Step::Firmware => Step::Operation,
        Step::Preflight => {
            if state.operation == Some(Operation::Unlock) {
                Step::Operation
            } else {
                Step::Firmware
            }
        }
        Step::Confirm => Step::Preflight,
        // No going back once bytes are on the wire.
        Step::Flashing => Step::Flashing,
        Step::Done => Step::Done,
    }
}

// ─── Step actions ────────────────────────────────────────────────────────────

fn start_scan(state: &mut State) -> Task<Message> {
    let Some(interface) = state.interface() else {
        return Task::none();
    };
    state.busy = Some("Scanning the bus…".into());
    state.scan_results.clear();
    state.chosen_candidate = None;
    state.chosen_channel = None;

    // A stream rather than a future: the sweep spends up to `IDENT_TIMEOUT` on
    // every silent channel, which on a bench is two of the three, so reporting
    // each channel as it is tried keeps that visible. One connection for the
    // whole sweep where the interface allows it — opening a J2534 device per
    // channel is seconds of dead time each.
    Task::stream(iced::stream::channel(
        16,
        move |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
            use iced::futures::SinkExt;

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
            let scan_tx = tx.clone();
            tokio::spawn(async move {
                let results = mqb_flash_uds::identify_all_channels_with_progress(&interface, |p| {
                    let _ = scan_tx.send(Message::ScanProgress(p));
                })
                .await;
                let _ = tx.send(Message::ScanFinished(results));
            });

            while let Some(msg) = rx.recv().await {
                let _ = output.send(msg).await;
            }
        },
    ))
}

fn start_unlock_probe(state: &mut State) -> Task<Message> {
    let (Some(interface), Some(flash_info)) = (state.interface(), state.flash_info()) else {
        return Task::none();
    };
    state.busy = Some("Entering the bootloader…".into());
    Task::future(async move {
        let r = mqb_flash_uds::probe(&interface, flash_info, ProbeKind::UnlockState).await;
        Message::UnlockProbeFinished(match r {
            Ok(ProbeOutcome::UnlockState(p)) => Ok(p),
            Ok(_) => Err("unexpected probe result".into()),
            Err(e) => Err(e.to_string()),
        })
    })
}

/// Correct checksums, compress and encrypt every block, and take the
/// immobilizer snapshot. All of it off the UI thread.
fn start_preflight(state: &mut State) -> Task<Message> {
    let (Some(interface), Some(flash_info), Some(firmware), Some(operation)) = (
        state.interface(),
        state.flash_info(),
        state.firmware.clone(),
        state.operation,
    ) else {
        return Task::none();
    };
    state.busy = Some("Preparing…".into());
    state.risk_acknowledged = false;

    // The immobilizer check applies to any operation that rewrites CALIBRATION,
    // not just a full flash — see `immo_check_applies`. The research covers
    // Simos only, hence the `ImmoSupport` token.
    let writes_cal = immo_check_applies(flash_info, &firmware, operation);
    let want_immo = writes_cal && ImmoSupport::for_module(flash_info).is_some();

    Task::future(async move {
        // Compression is CPU-bound and multi-megabyte: keep it off the runtime.
        let prep =
            tokio::task::spawn_blocking(move || prepare_blocks(flash_info, &firmware, operation))
                .await
                .unwrap_or_else(|e| (Err(format!("preparation panicked: {e}")), Vec::new()));

        let (immo_before, immo_report) = if want_immo {
            match ImmoSupport::for_module(flash_info) {
                Some(support) => {
                    match mqb_flash_uds::probe(
                        &interface,
                        flash_info,
                        ProbeKind::Immobilizer(support),
                    )
                    .await
                    {
                        Ok(ProbeOutcome::Immobilizer(snap)) => {
                            let report = mqb_flash_uds::assess_immo(&snap);
                            (Some(snap), Some(report))
                        }
                        // Fail open: an unreachable check is reported as
                        // unverifiable, never as a reason to stop.
                        _ => (None, None),
                    }
                }
                None => (None, None),
            }
        } else {
            (None, None)
        };

        Message::PreflightFinished(Box::new(PreflightOutcome {
            prepared: prep.0,
            notes: prep.1,
            immo_before,
            immo_report,
        }))
    })
}

/// Whether the immobilizer pre-flight is relevant to this operation.
///
/// Two things have to be true. **The calibration block is written**: the
/// power-class allow-list (`strVarTun`) that the anti-tuning interlock tests
/// `idxTun` against lives in the calibration area, so a calibration-only flash
/// can trip the interlock just as a full flash can. **The ECU will then run the
/// application software**: `CheckTuning` lives in ImoDat's periodic ASW task, so
/// an unlock — which writes CAL but leaves the ECU in the bootloader — never
/// runs the interlock and has nothing to predict.
fn immo_check_applies(
    flash_info: &FlashInfo,
    firmware: &FirmwareInfo,
    operation: Operation,
) -> bool {
    if operation == Operation::Unlock {
        return false;
    }
    flash_info
        .block_to_number("CAL")
        .is_some_and(|cal| firmware.blocks.contains_key(&cal))
}

/// Fix checksums then compress+encrypt, in that order.
///
/// The order is load-bearing: for DQ381 and Haldex the UDS block checksum is a
/// CRC-32 of the plain block, so it has to be taken after the internal
/// checksums are corrected and before compression.
fn prepare_blocks(
    flash_info: &'static FlashInfo,
    firmware: &FirmwareInfo,
    operation: Operation,
) -> (Result<Vec<PreparedBlockData>, String>, Vec<String>) {
    let mut raw = firmware.blocks.clone();

    // A full flash of a Simos ECU applies the CBOOT sample-mode patch, which is
    // what makes the ECU accept modified software. A relock is the same flash
    // with that patch left off, putting the signature-checking bootloader back.
    let cboot = flash_info
        .block_to_number("CBOOT")
        .filter(|n| raw.contains_key(n));
    if operation == Operation::Relock && cboot.is_none() {
        return (
            Err(
                "This file does not contain a bootloader block, so it cannot relock the ECU."
                    .into(),
            ),
            Vec::new(),
        );
    }
    let patch_cboot = operation == Operation::FullFlash && cboot.is_some();

    let report = match mqb_flash_uds::checksum_and_patch_blocks(flash_info, &mut raw, patch_cboot) {
        Ok(r) => r,
        Err(e) => return (Err(e.to_string()), Vec::new()),
    };
    let mut notes = report.notes;

    let mut blocks = Vec::new();
    match operation {
        Operation::CalibrationFlash => {
            let Some(cal) = flash_info.block_to_number("CAL") else {
                return (Err("This module has no calibration block.".into()), notes);
            };
            let Some(bytes) = raw.get(&cal) else {
                return (
                    Err("The file does not contain a calibration block.".into()),
                    notes,
                );
            };
            blocks.push(prepare_block(flash_info, cal, bytes));
        }
        Operation::FullFlash | Operation::Relock => {
            let mut nums: Vec<u8> = raw.keys().copied().filter(|n| *n <= 5).collect();
            nums.sort_unstable();
            for n in nums {
                blocks.push(prepare_block(flash_info, n, &raw[&n]));
            }
        }
        Operation::Unlock => {
            let Some(patch_info) = flash_info.patch_info.as_ref() else {
                return (Err("This module has no unlock patch.".into()), notes);
            };
            // Order matters: 1..4, then the patch, then CAL last.
            for n in [1u8, 2, 3, 4] {
                let Some(bytes) = raw.get(&n) else {
                    return (Err(format!("The file is missing block {n}.")), notes);
                };
                blocks.push(prepare_block(flash_info, n, bytes));
            }
            let patch_num = patch_info.patch_block_index + 5;
            blocks.push(prepare_patch_block(
                flash_info,
                patch_num,
                patch_info.patch_bytes,
            ));
            let Some(cal) = raw.get(&5) else {
                return (
                    Err("The file is missing the calibration block.".into()),
                    notes,
                );
            };
            blocks.push(prepare_block(flash_info, 5, cal));
        }
    }

    notes.push(format!("{} block(s) prepared", blocks.len()));
    (Ok(blocks), notes)
}

fn validate_unlock_file(flash_info: &FlashInfo, info: &FirmwareInfo) -> Result<(), String> {
    let Some(required) = required_unlock_box_code(flash_info) else {
        return Err("This module does not support unlocking.".into());
    };
    // The stored value carries a `__NNNN` version suffix; only the part number
    // is compared, exactly as the reference tool does.
    let required_part = required.split('_').next().unwrap_or(required);

    match info.box_code.as_deref() {
        Some(found) if found == required_part => Ok(()),
        Some(found) => Err(format!(
            "This file is for box code {found}, but the unlock for this ECU is built \
             against {required_part} (file {required}). Only that exact file will work — \
             the patch is compiled for those precise software addresses, and flashing it \
             against any other version will not produce a working ECU."
        )),
        None => Err(
            "No box code could be read from this file's calibration block, so it cannot be \
             verified as the correct unlock file."
                .into(),
        ),
    }
}

fn start_flash(state: &mut State) -> Task<Message> {
    let (Some(interface), Some(flash_info), Some(blocks)) = (
        state.interface(),
        state.flash_info(),
        state.prepared.clone(),
    ) else {
        return Task::none();
    };

    state.op_id += 1;
    state.total_blocks = blocks.len();
    state.flash_op = Some(FlashOp {
        id: state.op_id,
        flash_info,
        blocks,
        opts: FlashOptions {
            interface,
            patch_cboot: false, // already applied during preparation
            stmin_override: state.stmin_override(),
            workshop_code: mqb_flash_uds::workshop::FALLBACK_WORKSHOP_CODE,
            progress_tx: None, // the subscription fills this in
        },
    });
    state.step = Step::Flashing;
    state.progress = 0.0;
    state.progress_step = "Starting…".into();
    Task::none()
}

// ─── Progress ────────────────────────────────────────────────────────────────

const PROGRESS_SETUP_END: f32 = 0.10;
const PROGRESS_BLOCKS_START: f32 = 0.10;
const PROGRESS_BLOCKS_END: f32 = 0.90;
const PROGRESS_VERIFY: f32 = 0.92;
const PROGRESS_RESET: f32 = 0.96;

fn block_progress(frac: f32) -> f32 {
    PROGRESS_BLOCKS_START + frac * (PROGRESS_BLOCKS_END - PROGRESS_BLOCKS_START)
}

fn handle_progress(state: &mut State, update: ProgressUpdate) -> Task<Message> {
    match &update {
        ProgressUpdate::ClearingDtcs => {
            state.progress = 0.01;
            state.progress_step = "Clearing fault codes…".into();
        }
        ProgressUpdate::Connecting => {
            state.progress = 0.02;
            state.progress_step = "Opening a diagnostic session…".into();
        }
        ProgressUpdate::ReadVin { vin } => {
            state.progress = 0.03;
            state.progress_step = format!("Connected — VIN {vin}");
            state.log(format!("VIN: {vin}"));
        }
        ProgressUpdate::CheckingPreconditions => {
            state.progress = 0.04;
            state.progress_step = "Checking programming preconditions…".into();
        }
        ProgressUpdate::ProgrammingSession => {
            state.progress = 0.05;
            state.progress_step = "Entering the bootloader…".into();
        }
        ProgressUpdate::SwitchPatchUsed => {
            state.log("Programming session refused; SwitchPatch fallback accepted");
        }
        ProgressUpdate::Authenticating => {
            state.progress = 0.07;
            state.progress_step = "Authenticating…".into();
        }
        ProgressUpdate::WritingWorkshopCode => {
            state.progress = PROGRESS_SETUP_END;
            state.progress_step = "Writing the workshop code…".into();
        }
        ProgressUpdate::FlashingBlock { name, index, total } => {
            state.total_blocks = *total;
            let base = block_progress(*index as f32 / (*total).max(1) as f32);
            state.progress = base;
            state.block_progress_base = base;
            state.progress_step = format!("Writing {name} ({}/{})", index + 1, total);
            state.log(format!("Writing {name} ({}/{})", index + 1, total));
        }
        ProgressUpdate::BlockErasing { name } => {
            state.progress_step = format!("Erasing {name}…");
        }
        ProgressUpdate::BlockDownloading { name } => {
            state.progress_step = format!("Starting transfer: {name}…");
        }
        ProgressUpdate::BlockTransferProgress {
            name,
            bytes_sent,
            bytes_total,
        } => {
            let pct = if *bytes_total > 0 {
                *bytes_sent as f32 / *bytes_total as f32
            } else {
                0.0
            };
            let slice =
                (PROGRESS_BLOCKS_END - PROGRESS_BLOCKS_START) / state.total_blocks.max(1) as f32;
            state.progress = state.block_progress_base + pct * slice;
            state.progress_step = format!(
                "Transferring {name}: {}/{} KB ({:.0}%)",
                bytes_sent / 1024,
                bytes_total / 1024,
                pct * 100.0
            );
        }
        ProgressUpdate::BlockChecksum { name } => {
            state.progress_step = format!("Verifying {name}…");
        }
        ProgressUpdate::BlockComplete { index } => {
            state.progress = block_progress((*index + 1) as f32 / state.total_blocks.max(1) as f32);
        }
        ProgressUpdate::Verifying => {
            state.progress = PROGRESS_VERIFY;
            state.progress_step = "Verifying programming dependencies…".into();
        }
        ProgressUpdate::EcuReset => {
            state.progress = PROGRESS_RESET;
            state.progress_step = "Restarting the control module…".into();
        }
        ProgressUpdate::Complete => {
            state.progress = 1.0;
            state.progress_step = "Complete".into();
            state.finished_ok = true;
            state.flash_op = None;
            state.step = Step::Done;
            state.log("Flash complete");
            return start_post_flash_check(state);
        }
        ProgressUpdate::Error(e) => {
            state.progress_step = format!("Failed: {e}");
            state.error = Some(e.clone());
            state.finished_ok = false;
            state.flash_op = None;
            state.step = Step::Done;
            state.log(format!("Flash failed: {e}"));
        }
    }
    Task::none()
}

/// Re-read the immobilizer state and diff it against the pre-flash snapshot.
fn start_post_flash_check(state: &mut State) -> Task<Message> {
    let (Some(interface), Some(flash_info), Some(before)) = (
        state.interface(),
        state.flash_info(),
        state.immo_before.clone(),
    ) else {
        return Task::none();
    };
    let Some(support) = ImmoSupport::for_module(flash_info) else {
        return Task::none();
    };

    Task::future(async move {
        // The ECU has just hard-reset; give it a moment to come back up.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let findings =
            match mqb_flash_uds::probe(&interface, flash_info, ProbeKind::Immobilizer(support))
                .await
            {
                Ok(ProbeOutcome::Immobilizer(after)) => {
                    mqb_flash_uds::diff_after_flash(&before, &after)
                        .into_iter()
                        .map(|f| format!("{} — {}", f.message, f.detail))
                        .collect()
                }
                _ => vec![
                    "The immobilizer state could not be re-read after the flash. \
                 This is not itself a fault; try reading it again with the ignition on."
                        .to_owned(),
                ],
            };
        Message::PostFlashChecked(findings)
    })
}

// ─── Subscription ────────────────────────────────────────────────────────────

fn subscription(state: &State) -> Subscription<Message> {
    let Some(op) = &state.flash_op else {
        return Subscription::none();
    };
    Subscription::run_with(op.clone(), flash_stream)
}

fn flash_stream(op: &FlashOp) -> impl iced::futures::Stream<Item = Message> {
    let flash_info = op.flash_info;
    let blocks_arc = Arc::clone(&op.blocks);
    let mut opts = op.opts.clone();

    iced::stream::channel::<Message>(
        64,
        move |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
            use iced::futures::SinkExt;

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ProgressUpdate>();
            opts.progress_tx = Some(tx.clone());
            let blocks_vec: Vec<PreparedBlockData> = (*blocks_arc).clone();

            tokio::spawn(async move {
                match flash_blocks(flash_info, blocks_vec, opts).await {
                    Ok(()) => {
                        let _ = tx.send(ProgressUpdate::Complete);
                    }
                    Err(e) => {
                        let _ = tx.send(ProgressUpdate::Error(e.to_string()));
                    }
                }
            });

            while let Some(update) = rx.recv().await {
                let done = matches!(update, ProgressUpdate::Complete | ProgressUpdate::Error(_));
                let _ = output.send(Message::FlashProgress(update)).await;
                if done {
                    break;
                }
            }

            std::future::pending::<()>().await
        },
    )
}

// ─── View ────────────────────────────────────────────────────────────────────

fn view(state: &State) -> Element<'_, Message> {
    let body: Element<'_, Message> = match state.step {
        Step::Interface => view_interface(state),
        Step::Identify => view_identify(state),
        Step::Unlock => view_unlock(state),
        Step::Operation => view_operation(state),
        Step::Firmware => view_firmware(state),
        Step::Preflight => view_preflight(state),
        Step::Confirm => view_confirm(state),
        Step::Flashing => view_flashing(state),
        Step::Done => view_done(state),
    };

    let mut page = column![
        text(state.step.title()).size(24),
        text(state.step.blurb()).size(13),
        horizontal_rule(1),
    ]
    .spacing(8);

    if let Some(busy) = &state.busy {
        page = page.push(text(busy.as_str()).size(14));
    }
    if let Some(err) = &state.error {
        page = page.push(callout("Problem", err));
    }

    page = page.push(body);
    page = page.push(iced::widget::space::vertical());
    page = page.push(horizontal_rule(1));
    page = page.push(nav_row(state));

    scrollable(container(page.padding(24).width(Length::Fill)).width(Length::Fill)).into()
}

fn nav_row(state: &State) -> Element<'_, Message> {
    let back_allowed = state.busy.is_none()
        && !matches!(state.step, Step::Interface | Step::Flashing | Step::Done);

    let next_label = match state.step {
        Step::Confirm => "Write to the ECU",
        Step::Preflight => "Continue",
        _ => "Next",
    };

    let mut r = row![].spacing(10).align_y(Alignment::Center);
    r = r.push(
        button(text("Back").size(14))
            .on_press_maybe(back_allowed.then_some(Message::Back))
            .padding([8, 18]),
    );
    r = r.push(iced::widget::space::horizontal());

    if matches!(state.step, Step::Done) {
        r = r.push(
            button(text("Start over").size(14))
                .on_press(Message::StartOver)
                .padding([8, 18]),
        );
    } else {
        r = r.push(
            button(text(next_label).size(14))
                .on_press_maybe(state.can_advance().then_some(Message::Next))
                .padding([8, 18]),
        );
    }
    r.into()
}

fn view_interface(state: &State) -> Element<'_, Message> {
    let kinds = row![
        radio(
            "J2534 (hardware ISO-TP)",
            InterfaceKind::J2534IsoTp,
            Some(state.interface_kind),
            Message::InterfaceKindChanged
        ),
        radio(
            "J2534 (raw CAN)",
            InterfaceKind::J2534,
            Some(state.interface_kind),
            Message::InterfaceKindChanged
        ),
        radio(
            "Panda",
            InterfaceKind::Panda,
            Some(state.interface_kind),
            Message::InterfaceKindChanged
        ),
        radio(
            "SocketCAN",
            InterfaceKind::SocketCan,
            Some(state.interface_kind),
            Message::InterfaceKindChanged
        ),
    ]
    .spacing(14)
    .align_y(Alignment::Center);

    let mut col = column![kinds].spacing(12);

    match state.interface_kind {
        InterfaceKind::J2534 | InterfaceKind::J2534IsoTp => {
            col = col.push(
                row![
                    text("Driver DLL:").width(120),
                    text_input("(detect automatically)", &state.j2534_dll_path)
                        .on_input(Message::J2534DllPathChanged)
                        .width(320),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
        }
        InterfaceKind::SocketCan => {
            col = col.push(
                row![
                    text("Interface:").width(120),
                    text_input("can0", &state.socketcan_name)
                        .on_input(Message::SocketCanNameChanged)
                        .width(160),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );
        }
        InterfaceKind::Panda => {}
    }

    col = col.push(
        row![
            text("STmin (µs):").width(120),
            text_input("module default", &state.stmin_input)
                .on_input(Message::StminChanged)
                .width(160),
            text("Leave blank unless transfers are unreliable.").size(12),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    );

    col.into()
}

fn view_identify(state: &State) -> Element<'_, Message> {
    // The live per-channel status is already rendered above the body from
    // `state.busy`; repeating a static line here would only contradict it.
    if state.busy.is_some() {
        return text(
            "Each address gets a moment to answer, so this takes a few seconds. \
             Addresses with no module fitted stay silent — that is expected.",
        )
        .size(13)
        .into();
    }
    if state.scan_results.is_empty() {
        return text("Nothing answered. Go back and check the adapter.").into();
    }

    let mut col = column![].spacing(14);

    for (ci, ident) in state.scan_results.iter().enumerate() {
        let mut group = column![text(ident.channel.label).size(16)].spacing(6);

        if ident.is_ambiguous() {
            group = group.push(callout(
                "Two modules are possible",
                "These control modules share the same CAN addresses and report the same \
                 records, so the wizard cannot tell them apart. Choose the one fitted to \
                 this car — flashing the wrong one will not work.",
            ));
        }

        for (idx, cand) in ident.candidates.iter().enumerate() {
            let chosen = state.chosen_channel == Some(ci) && state.chosen_candidate == Some(idx);
            group = group.push(
                radio(
                    format!("{} — {:?}", cand.module_name, cand.confidence),
                    (ci, idx),
                    chosen.then_some((ci, idx)),
                    move |(c, i)| Message::CandidateChosen(c, i),
                )
                .size(15),
            );
            group = group.push(
                container(text(cand.reason.as_str()).size(12))
                    .padding(iced::Padding::new(0.0).bottom(6).left(26)),
            );
        }

        col = col.push(group);
    }

    col.into()
}

fn view_unlock(state: &State) -> Element<'_, Message> {
    if state.busy.is_some() {
        return text("Reading the bootloader…").into();
    }
    let Some(probe) = &state.unlock else {
        return text("The unlock state has not been read.").into();
    };

    let mut col = column![].spacing(12);

    let hw = probe.hardware_version.clone().unwrap_or_else(|| "—".into());
    col = col.push(text(format!("Bootloader hardware version: {hw}")).size(15));

    match &probe.state {
        UnlockState::Unlocked => {
            col = col.push(callout(
                "This ECU is unlocked",
                "The bootloader reports an X-prefixed hardware version, which means the \
                 sample-mode patch is present. It will accept modified software.",
            ));
        }
        UnlockState::Locked => {
            col = col.push(callout(
                "This ECU is locked",
                "The bootloader reports a stock hardware version, so the ECU still checks \
                 signatures and will reject modified software. Unlock it first.",
            ));
            col = col.push(unlock_file_picker(state));
        }
        UnlockState::Unknown(reason) => {
            col = col.push(callout(
                "The unlock state could not be read",
                reason.clone(),
            ));
            col = col.push(
                text(
                    "You can continue, but modified software will be rejected if the ECU \
                     turns out to be locked. If you are not sure, unlocking an ECU that is \
                     already unlocked is harmless.",
                )
                .size(13),
            );
            // Fail open: not being able to read the state must not take the
            // unlock option away.
            col = col.push(unlock_file_picker(state));
        }
    }

    col.into()
}

fn unlock_file_picker(state: &State) -> Element<'_, Message> {
    let Some(flash_info) = state.flash_info() else {
        return text("").into();
    };
    let Some(required) = required_unlock_box_code(flash_info) else {
        return text("").into();
    };
    let required_part = required.split('_').next().unwrap_or(required);

    let mut col = column![
        text("To unlock, supply the stock firmware file").size(16),
        text(format!(
            "Only one file works for this ECU: the stock firmware for box code {required_part} \
             (typically named FL_{required}.frf). The unlock patch is compiled against those \
             exact software addresses — any other version, even a newer one for the same car, \
             will not produce a working ECU."
        ))
        .size(13),
    ]
    .spacing(8);

    let chosen = state
        .unlock_file
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "(none chosen)".into());

    col = col.push(
        row![
            button("Choose file…")
                .on_press(Message::BrowseUnlockFile)
                .padding([6, 14]),
            text(chosen),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    );

    if let Some(err) = &state.unlock_file_error {
        col = col.push(callout("This file cannot be used", err));
    } else if state.unlock_file.is_some() {
        col = col.push(text("File accepted — choose Unlock on the next screen.").size(13));
    }

    col.into()
}

fn view_operation(state: &State) -> Element<'_, Message> {
    let mut col = column![].spacing(10);

    // Offer the unlock whenever the ECU is not known to be unlocked — an
    // unreadable state must not remove the option.
    let locked = matches!(
        state.unlock.as_ref().map(|u| &u.state),
        Some(UnlockState::Locked) | Some(UnlockState::Unknown(_))
    );
    let definitely_locked = matches!(
        state.unlock.as_ref().map(|u| &u.state),
        Some(UnlockState::Locked)
    );
    let has_cboot = state
        .flash_info()
        .is_some_and(|fi| fi.block_to_number("CBOOT").is_some());

    if locked && state.unlock_file.is_some() {
        col = col.push(
            radio(
                "Unlock this ECU",
                Operation::Unlock,
                state.operation,
                Message::OperationChosen,
            )
            .size(15),
        );
        col = col.push(
            container(
                text("Writes the unlock patch. Do this before flashing modified software.")
                    .size(12),
            )
            .padding(iced::Padding::new(0.0).bottom(6).left(26)),
        );
    }

    col = col.push(
        radio(
            "Calibration flash",
            Operation::CalibrationFlash,
            state.operation,
            Message::OperationChosen,
        )
        .size(15),
    );
    col = col.push(
        container(
            text(
                "Writes only the tune; the application software is untouched. Note this is \
                 not immobilizer-safe: the allowed power classes live in the calibration \
                 area, so a calibration flash can trip the anti-tuning interlock too.",
            )
            .size(12),
        )
        .padding(iced::Padding::new(0.0).bottom(6).left(26)),
    );

    col = col.push(
        radio(
            "Full flash",
            Operation::FullFlash,
            state.operation,
            Message::OperationChosen,
        )
        .size(15),
    );
    col = col.push(
        container(
            text(
                "Rewrites the bootloader, application software and tune, and patches the \
                 bootloader into sample mode so the ECU keeps accepting modified software. \
                 Use this to change software version or recover an ECU.",
            )
            .size(12),
        )
        .padding(iced::Padding::new(0.0).bottom(6).left(26)),
    );

    // Relocking only means anything on a module whose bootloader we would
    // otherwise patch.
    if has_cboot {
        col = col.push(
            radio(
                "Relock",
                Operation::Relock,
                state.operation,
                Message::OperationChosen,
            )
            .size(15),
        );
        col = col.push(
            container(
                text(
                    "The same full flash, but the bootloader is written exactly as the file \
                     has it — no sample-mode patch. The ECU goes back to rejecting modified \
                     software, so use a complete, unmodified factory file.",
                )
                .size(12),
            )
            .padding(iced::Padding::new(0.0).bottom(6).left(26)),
        );
    }

    if definitely_locked {
        col = col.push(callout(
            "This ECU is locked",
            "Modified software will be rejected until the ECU is unlocked. Stock files will \
             still flash normally.",
        ));
    }

    col.into()
}

fn view_firmware(state: &State) -> Element<'_, Message> {
    let name = state
        .firmware_path
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "(none chosen)".into());

    let mut col = column![row![
        button("Choose file…")
            .on_press(Message::BrowseFirmware)
            .padding([6, 14]),
        text(name),
    ]
    .spacing(10)
    .align_y(Alignment::Center)]
    .spacing(12);

    if let (Some(info), Some(flash_info)) = (&state.firmware, state.flash_info()) {
        let mut details = column![text("What this file contains").size(16)].spacing(4);
        if let Some(bc) = &info.box_code {
            details = details.push(text(format!("Box code: {bc}")).size(13));
        }
        details = details.push(
            text(format!(
                "Blocks: {}",
                info.block_names(flash_info).join(", ")
            ))
            .size(13),
        );
        for (name, version) in &info.versions {
            details = details.push(text(format!("{name} version: {version}")).size(13));
        }
        col = col.push(details);

        // The ECU's own part number, when we read one, should match the file.
        if let (Some(bc), Some(cand)) = (&info.box_code, state.selected()) {
            if let Some(ecu_part) = cand.strings.spare_part_number.as_deref() {
                if !ecu_part.trim().is_empty() && !ecu_part.trim().starts_with(bc) {
                    col = col.push(callout(
                        "This file may be for a different ECU",
                        format!(
                            "The control module reports part number {}, but this file is for \
                             box code {bc}. Check you have the right file before continuing.",
                            ecu_part.trim()
                        ),
                    ));
                }
            }
        }
    }

    col.into()
}

fn view_preflight(state: &State) -> Element<'_, Message> {
    if state.busy.is_some() {
        return text("Correcting checksums and preparing blocks — this can take a moment…").into();
    }

    let mut col = column![].spacing(12);

    if !state.prep_notes.is_empty() {
        let mut notes = column![text("Preparation").size(16)].spacing(3);
        for n in &state.prep_notes {
            notes = notes.push(text(n.as_str()).size(12));
        }
        col = col.push(notes);
    }

    match &state.immo_report {
        Some(report) => {
            let mut sec = column![text("Immobilizer").size(16)].spacing(4);
            if report.findings.is_empty() {
                sec = sec.push(text("No immobilizer problems found.").size(13));
            }
            for f in &report.findings {
                let tag = match f.severity {
                    Severity::Ok => "OK",
                    Severity::Warn => "WARNING",
                    Severity::Unknown => "UNVERIFIED",
                };
                sec = sec.push(text(format!("[{tag}] {}", f.message)).size(13));
                sec = sec.push(
                    container(text(f.detail.as_str()).size(12))
                        .padding(iced::Padding::new(0.0).bottom(4).left(16)),
                );
            }
            col = col.push(sec);
        }
        // Any operation that writes CAL should have been checked, because the
        // power-class allow-list lives there.
        None if state.immo_check_applies_now() => {
            col = col.push(callout(
                "The immobilizer check did not run",
                "Either this module is not covered by the check, or the ECU did not answer. \
                 You can continue — this is not itself a fault.",
            ));
        }
        None => {}
    }

    if state.preflight_has_risk() {
        col = col.push(callout(
            "Read this before continuing",
            "At least one check above is a warning. A full flash can leave an ECU that will \
             not start, and some of those states can only be recovered with data that is not \
             available over the diagnostic port.",
        ));
        col = col.push(
            iced::widget::checkbox(state.risk_acknowledged)
                .label("I have read the warnings above and want to continue")
                .on_toggle(Message::AcknowledgeRisk),
        );
    }

    col.into()
}

fn view_confirm(state: &State) -> Element<'_, Message> {
    let mut col = column![].spacing(8);

    let module = state
        .selected()
        .map(|c| c.module_name)
        .unwrap_or("(unknown)");
    let op = state.operation.map(|o| o.label()).unwrap_or("(none)");
    let file = state
        .firmware
        .as_ref()
        .and_then(|f| f.path.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "(none)".into());

    col = col.push(text(format!("Control module:  {module}")).size(15));
    col = col.push(text(format!("Operation:       {op}")).size(15));
    col = col.push(text(format!("File:            {file}")).size(15));

    if let Some(blocks) = &state.prepared {
        let names: Vec<&str> = blocks.iter().map(|b| b.block_name.as_str()).collect();
        col = col.push(text(format!("Blocks written:  {}", names.join(", "))).size(15));
        let total: usize = blocks.iter().map(|b| b.block_encrypted_bytes.len()).sum();
        col = col.push(text(format!("Total payload:   {} KB", total / 1024)).size(15));
    }

    if state.operation == Some(Operation::Relock) {
        col = col.push(Space::new().height(10));
        col = col.push(callout(
            "This will relock the ECU",
            "The bootloader is written unpatched, so after this flash the ECU validates \
             signatures again and will refuse modified software. If the application software \
             or tune in this file is not the original signed factory content, the ECU will \
             not run until a stock file is flashed back.",
        ));
    }

    col = col.push(Space::new().height(10));
    col = col.push(callout(
        "Before you continue",
        "Keep the ignition on and the battery supported. Do not unplug the adapter or close \
         this window until the flash finishes. An interrupted flash usually leaves the ECU in \
         the bootloader, where it can be re-flashed, but it will not run the engine until it is.",
    ));

    col.into()
}

fn view_flashing(state: &State) -> Element<'_, Message> {
    let log: Vec<Element<'_, Message>> = state
        .log_lines
        .iter()
        .rev()
        .take(200)
        .map(|l| text(l.as_str()).size(12).into())
        .collect();

    column![
        text(state.progress_step.as_str()).size(15),
        progress_bar(0.0..=1.0, state.progress).length(Length::Fill),
        scrollable(column(log).spacing(2)).height(240),
    ]
    .spacing(12)
    .into()
}

fn view_done(state: &State) -> Element<'_, Message> {
    let mut col = column![].spacing(12);

    if state.finished_ok {
        col = col.push(text("The flash completed successfully.").size(16));
    } else {
        col = col.push(text("The flash did not complete.").size(16));
        col = col.push(callout(
            "What to do next",
            "The ECU is most likely still in the bootloader, which means it can be flashed \
             again. Fix the reported problem and retry the same operation before switching \
             the ignition off.",
        ));
    }

    if !state.post_flash_findings.is_empty() {
        let mut sec = column![text("Immobilizer, after the flash").size(16)].spacing(4);
        for f in &state.post_flash_findings {
            sec = sec.push(text(f.as_str()).size(13));
        }
        col = col.push(sec);
    }

    let log: Vec<Element<'_, Message>> = state
        .log_lines
        .iter()
        .map(|l| text(l.as_str()).size(12).into())
        .collect();
    col = col.push(scrollable(column(log).spacing(2)).height(200));

    col.into()
}

/// A titled block of explanatory text.
///
/// Takes owned strings so callers can build a message with `format!` inline.
fn callout<'a>(title: impl Into<String>, body: impl Into<String>) -> Element<'a, Message> {
    container(column![text(title.into()).size(14), text(body.into()).size(12)].spacing(3))
        .padding(10)
        .width(Length::Fill)
        .into()
}
