//! Application state, messages, and the update loop.

use std::path::PathBuf;

use iced::Task;
use tokio::sync::mpsc::UnboundedSender;

use mqb_immo::adapt::{adapt_plan, pclass_plan, vin_plan};
use mqb_immo::state::{decode_2ed, decode_2ff};
use mqb_immo::{adapt_preflight, DownloadPlan, PreflightItem, MASTER_KEY_CANDIDATES};
use mqb_nvcrypt::{ImmoRecord, StStatFct};
use mqb_transport::{supports_raw_can, Interface};

use crate::connection::{Command, Event, LiveState, MasterKeySelection, MasterUpdate};
use crate::secrets::{hex, parse_hex, parse_u8, KeySource, SourceKind};

/// The four things this tool does, one per tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Read the immobilizer's live state. Needs no keys at all.
    Live,
    /// Play the instrument cluster so a bench ECU releases.
    Master,
    /// Write an identity: a transplant, a power class, or a VIN.
    Identity,
    /// Decrypt, inspect and edit a DFlash image.
    Dflash,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Live, Tab::Master, Tab::Identity, Tab::Dflash];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Live => "Live state",
            Tab::Master => "Master emulator",
            Tab::Identity => "Identity",
            Tab::Dflash => "DFlash",
        }
    }

    pub fn blurb(self) -> &'static str {
        match self {
            Tab::Live => {
                "Reads the immobilizer status DIDs. These are unauthenticated, so this works \
                 against any ECU on the bus without keys or a dump."
            }
            Tab::Master => {
                "Answers the ECU's authentication requests on CAN 0x010/0x011 the way the \
                 instrument cluster would, so a bench ECU releases without patching the \
                 immobilizer out."
            }
            Tab::Identity => {
                "Writes the immobilizer record over UDS. The download needs the key the ECU \
                 holds now; the PIN that follows it needs a master on the powertrain bus, or \
                 the car's own cluster."
            }
            Tab::Dflash => {
                "Decrypts an NVRAM image with its Device ID, shows what every channel holds, \
                 and can write an edited immobilizer record back."
            }
        }
    }
}

/// Which ECU a key source describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// The ECU on the bench — its current key encrypts the download.
    Target,
    /// The identity being moved onto it.
    Donor,
}

/// Which manual field changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualField {
    NoKeySecu,
    NoKeyMst,
    IdxTun,
    Vin,
    CtDatBasFazit,
}

/// The three ways to settle on a master key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKeyMode {
    /// Read `idxLab` from DID `0x2ED` and derive the key.
    FromEcu,
    /// Try all three and drop the ones the ECU rejects.
    Narrow,
    /// Use the key typed in.
    Manual,
}

/// What kind of identity write is being built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    /// Move a donor ECU's identity onto the ECU on the bus.
    Transplant,
    /// Change only `idxTun` / PClass.
    PowerClass,
    /// Change only the VIN.
    Vin,
}

impl IdentityMode {
    pub const ALL: [IdentityMode; 3] = [
        IdentityMode::Transplant,
        IdentityMode::PowerClass,
        IdentityMode::Vin,
    ];

    pub fn label(self) -> &'static str {
        match self {
            IdentityMode::Transplant => "Transplant an identity",
            IdentityMode::PowerClass => "Change the power class",
            IdentityMode::Vin => "Change the VIN",
        }
    }
}

/// The interfaces the tool can open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    J2534,
    J2534IsoTp,
    Panda,
    SocketCan,
}

/// Whether the bus is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    Disconnected,
    Connecting,
    Connected { interface: String, raw_can: bool },
}

impl Connection {
    pub fn is_connected(&self) -> bool {
        matches!(self, Connection::Connected { .. })
    }

    /// Whether raw CAN frames are visible, i.e. whether the master emulator can
    /// hear the ECU at all.
    pub fn has_raw_can(&self) -> bool {
        matches!(self, Connection::Connected { raw_can: true, .. })
    }
}

/// The master emulator's state, as the UI sees it.
#[derive(Debug, Default)]
pub struct MasterState {
    pub running: bool,
    pub key_mode_index: usize,
    pub key_hex: String,
    pub started_with: Option<[u8; 4]>,
    pub key_source: Option<String>,
    pub latest: Option<MasterUpdate>,
    pub frames: Vec<String>,
}

impl MasterState {
    pub fn key_mode(&self) -> MasterKeyMode {
        [
            MasterKeyMode::FromEcu,
            MasterKeyMode::Narrow,
            MasterKeyMode::Manual,
        ][self.key_mode_index.min(2)]
    }
}

/// The DFlash tab's state.
#[derive(Debug, Default)]
pub struct DflashState {
    pub selected_channel: Option<u8>,
    /// The immobilizer record as edited, before it is written back.
    pub edited: Option<ImmoRecord>,
    pub vin_input: String,
    pub idx_tun_input: String,
    pub no_key_mst_input: String,
    pub no_key_secu_input: String,
    pub ct_fazit_input: String,
    pub st_stat_index: usize,
    pub edit_error: Option<String>,
    pub confirm_write: bool,
    pub save_result: Option<Result<String, String>>,
}

pub struct State {
    pub tab: Tab,

    // Connection
    pub interface_kind: InterfaceKind,
    pub socketcan_name: String,
    pub j2534_dll: String,
    pub connection: Connection,
    pub commands: Option<UnboundedSender<Command>>,
    pub log: Vec<String>,

    // Live state
    pub live: Option<LiveState>,
    pub live_error: Option<String>,
    pub polling: bool,

    // Key sources
    pub target: KeySource,
    pub donor: KeySource,

    // Master emulator
    pub master: MasterState,

    // Identity
    pub identity_mode: IdentityMode,
    pub idx_tun_input: String,
    pub vin_input: String,
    pub donor_idx_lab_input: String,
    pub plan: Option<DownloadPlan>,
    pub plan_error: Option<String>,
    pub preflight: Vec<PreflightItem>,
    pub confirm_download: bool,
    pub download_result: Option<Result<String, String>>,
    pub sending: bool,

    // DFlash
    pub dflash: DflashState,
}

impl Default for State {
    fn default() -> Self {
        Self {
            tab: Tab::Live,
            interface_kind: InterfaceKind::J2534,
            socketcan_name: "can0".into(),
            j2534_dll: String::new(),
            connection: Connection::Disconnected,
            commands: None,
            log: Vec::new(),
            live: None,
            live_error: None,
            polling: false,
            target: KeySource::default(),
            donor: KeySource::default(),
            master: MasterState::default(),
            identity_mode: IdentityMode::Transplant,
            idx_tun_input: String::new(),
            vin_input: String::new(),
            donor_idx_lab_input: String::new(),
            plan: None,
            plan_error: None,
            preflight: Vec::new(),
            confirm_download: false,
            download_result: None,
            sending: false,
            dflash: DflashState::default(),
        }
    }
}

impl State {
    pub fn interface(&self) -> Interface {
        match self.interface_kind {
            InterfaceKind::Panda => Interface::Panda,
            InterfaceKind::SocketCan => Interface::SocketCan(self.socketcan_name.clone()),
            InterfaceKind::J2534 | InterfaceKind::J2534IsoTp => Interface::J2534 {
                dll: (!self.j2534_dll.trim().is_empty()).then(|| self.j2534_dll.trim().to_string()),
                bitrate: 500_000,
                native_isotp: self.interface_kind == InterfaceKind::J2534IsoTp,
            },
        }
    }

    /// Whether the interface *as configured* could carry master emulation.
    ///
    /// Checked before connecting so the reason is visible while the choice is
    /// still being made, rather than after the fact.
    pub fn interface_supports_master(&self) -> bool {
        supports_raw_can(&self.interface())
    }

    pub fn source(&self, which: Which) -> &KeySource {
        match which {
            Which::Target => &self.target,
            Which::Donor => &self.donor,
        }
    }

    pub fn source_mut(&mut self, which: Which) -> &mut KeySource {
        match which {
            Which::Target => &mut self.target,
            Which::Donor => &mut self.donor,
        }
    }

    fn send(&mut self, command: Command) {
        match &self.commands {
            Some(tx) => {
                if tx.send(command).is_err() {
                    self.note("The connection task has stopped; restart the application.");
                }
            }
            None => self.note("The connection is not ready yet."),
        }
    }

    pub fn note(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        // The log is a running commentary, not an archive.
        if self.log.len() > 400 {
            self.log.drain(..self.log.len() - 400);
        }
    }

    /// `idxLab` as the ECU last reported it.
    pub fn reported_idx_lab(&self) -> Option<u8> {
        let snapshot = &self.live.as_ref()?.snapshot;
        decode_2ed(snapshot.raw(mqb_immo::state::DID_STATE)?).map(|s| s.idx_lab)
    }

    /// `idxTun` as the ECU last reported it.
    pub fn reported_idx_tun(&self) -> Option<u8> {
        let snapshot = &self.live.as_ref()?.snapshot;
        decode_2ff(snapshot.raw(mqb_immo::state::DID_EXTENDED)?).map(|e| e.idx_tun)
    }

    /// The power-class allow-list the ECU last reported.
    pub fn reported_allow_list(&self) -> Option<[u8; 5]> {
        let snapshot = &self.live.as_ref()?.snapshot;
        decode_2ff(snapshot.raw(mqb_immo::state::DID_EXTENDED)?).map(|e| e.str_var_tun)
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),

    // Connection
    InterfaceKindChanged(InterfaceKind),
    SocketCanNameChanged(String),
    J2534DllChanged(String),
    ConnectPressed,
    DisconnectPressed,
    Connection(Event),

    // Live
    RefreshPressed,
    PollingToggled(bool),

    // Key sources
    SourceKindChanged(Which, SourceKind),
    BrowseDump(Which),
    BrowsePflash(Which),
    DumpChosen(Which, Option<PathBuf>),
    PflashChosen(Which, Option<PathBuf>),
    DeviceIdChanged(Which, String),
    RecordHexChanged(Which, String),
    ManualFieldChanged(Which, ManualField, String),

    // Master
    MasterKeyModeChanged(MasterKeyMode),
    MasterKeyHexChanged(String),
    StartMasterPressed,
    StopMasterPressed,
    ClearMasterLog,

    // Identity
    IdentityModeChanged(IdentityMode),
    IdxTunChanged(String),
    VinChanged(String),
    DonorIdxLabChanged(String),
    BuildPlanPressed,
    ConfirmDownloadToggled(bool),
    SendDownloadPressed,

    // DFlash
    DflashChannelSelected(u8),
    DflashVinChanged(String),
    DflashIdxTunChanged(String),
    DflashNoKeyMstChanged(String),
    DflashNoKeySecuChanged(String),
    DflashCtFazitChanged(String),
    DflashStStatChanged(StStatFct),
    DflashRevert,
    DflashConfirmWriteToggled(bool),
    DflashSavePressed,
    DflashSaveChosen(Option<PathBuf>),
}

pub fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::TabSelected(tab) => state.tab = tab,

        // ── Connection ────────────────────────────────────────────────────
        Message::InterfaceKindChanged(kind) => state.interface_kind = kind,
        Message::SocketCanNameChanged(name) => state.socketcan_name = name,
        Message::J2534DllChanged(path) => state.j2534_dll = path,

        Message::ConnectPressed => {
            let interface = state.interface();
            state.connection = Connection::Connecting;
            state.send(Command::Connect(interface));
        }

        Message::DisconnectPressed => {
            state.send(Command::Disconnect);
        }

        Message::Connection(event) => return handle_connection_event(state, event),

        // ── Live ──────────────────────────────────────────────────────────
        Message::RefreshPressed => state.send(Command::ReadState),

        Message::PollingToggled(on) => {
            state.polling = on;
            state.send(Command::SetPolling(on));
        }

        // ── Key sources ───────────────────────────────────────────────────
        Message::SourceKindChanged(which, kind) => {
            state.source_mut(which).set_kind(kind);
            state.invalidate_plan();
        }

        Message::BrowseDump(which) => {
            return Task::perform(
                pick_file("DFlash dump", &["bin", "dfl", "*"]),
                move |path| Message::DumpChosen(which, path),
            )
        }

        Message::BrowsePflash(which) => {
            return Task::perform(
                pick_file("Program flash dump", &["bin", "*"]),
                move |path| Message::PflashChosen(which, path),
            )
        }

        Message::DumpChosen(which, Some(path)) => {
            state.source_mut(which).load_dump(path);
            state.after_source_change(which);
        }
        Message::DumpChosen(_, None) => {}

        Message::PflashChosen(which, Some(path)) => {
            state.source_mut(which).load_device_id_from_pflash(path);
            state.after_source_change(which);
        }
        Message::PflashChosen(_, None) => {}

        Message::DeviceIdChanged(which, value) => {
            let source = state.source_mut(which);
            source.device_id_hex = value;
            source.resolve();
            state.after_source_change(which);
        }

        Message::RecordHexChanged(which, value) => {
            let source = state.source_mut(which);
            source.record_hex = value;
            source.resolve();
            state.after_source_change(which);
        }

        Message::ManualFieldChanged(which, field, value) => {
            let source = state.source_mut(which);
            match field {
                ManualField::NoKeySecu => source.manual.no_key_secu = value,
                ManualField::NoKeyMst => source.manual.no_key_mst = value,
                ManualField::IdxTun => source.manual.idx_tun = value,
                ManualField::Vin => source.manual.vin = value,
                ManualField::CtDatBasFazit => source.manual.ct_dat_bas_fazit = value,
            }
            source.resolve();
            state.after_source_change(which);
        }

        // ── Master ────────────────────────────────────────────────────────
        Message::MasterKeyModeChanged(mode) => {
            state.master.key_mode_index = [
                MasterKeyMode::FromEcu,
                MasterKeyMode::Narrow,
                MasterKeyMode::Manual,
            ]
            .iter()
            .position(|m| *m == mode)
            .unwrap_or(0);
        }

        Message::MasterKeyHexChanged(value) => state.master.key_hex = value,

        Message::StartMasterPressed => return start_master(state),

        Message::StopMasterPressed => state.send(Command::StopMaster),

        Message::ClearMasterLog => {
            state.master.frames.clear();
        }

        // ── Identity ──────────────────────────────────────────────────────
        Message::IdentityModeChanged(mode) => {
            state.identity_mode = mode;
            state.invalidate_plan();
        }
        Message::IdxTunChanged(value) => {
            state.idx_tun_input = value;
            state.invalidate_plan();
        }
        Message::VinChanged(value) => {
            state.vin_input = value;
            state.invalidate_plan();
        }
        Message::DonorIdxLabChanged(value) => {
            state.donor_idx_lab_input = value;
            state.invalidate_plan();
        }

        Message::BuildPlanPressed => build_plan(state),

        Message::ConfirmDownloadToggled(on) => state.confirm_download = on,

        Message::SendDownloadPressed => {
            if let Some(plan) = state.plan.clone() {
                state.sending = true;
                state.download_result = None;
                state.send(Command::SendDownload {
                    payload: plan.payload.to_vec(),
                });
            }
        }

        // ── DFlash ────────────────────────────────────────────────────────
        Message::DflashChannelSelected(channel) => {
            state.dflash.selected_channel = Some(channel);
            state.load_channel_for_edit(channel);
        }
        Message::DflashVinChanged(value) => {
            state.dflash.vin_input = value;
            state.apply_dflash_edits();
        }
        Message::DflashIdxTunChanged(value) => {
            state.dflash.idx_tun_input = value;
            state.apply_dflash_edits();
        }
        Message::DflashNoKeyMstChanged(value) => {
            state.dflash.no_key_mst_input = value;
            state.apply_dflash_edits();
        }
        Message::DflashNoKeySecuChanged(value) => {
            state.dflash.no_key_secu_input = value;
            state.apply_dflash_edits();
        }
        Message::DflashCtFazitChanged(value) => {
            state.dflash.ct_fazit_input = value;
            state.apply_dflash_edits();
        }
        Message::DflashStStatChanged(value) => {
            state.dflash.st_stat_index = StStatFct::all()
                .iter()
                .position(|s| *s == value)
                .unwrap_or(1);
            state.apply_dflash_edits();
        }
        Message::DflashRevert => {
            if let Some(channel) = state.dflash.selected_channel {
                state.load_channel_for_edit(channel);
            }
        }
        Message::DflashConfirmWriteToggled(on) => state.dflash.confirm_write = on,

        Message::DflashSavePressed => {
            return Task::perform(save_file("edited DFlash image", "bin"), |path| {
                Message::DflashSaveChosen(path)
            })
        }
        Message::DflashSaveChosen(Some(path)) => save_dflash(state, path),
        Message::DflashSaveChosen(None) => {}
    }

    Task::none()
}

fn handle_connection_event(state: &mut State, event: Event) -> Task<Message> {
    match event {
        Event::Ready(sender) => state.commands = Some(sender),

        Event::Connected { interface, raw_can } => {
            state.note(format!("Connected on {interface}."));
            state.connection = Connection::Connected { interface, raw_can };
            state.live_error = None;
            // One read straight away, so the screen is never blank after a
            // successful connect.
            state.send(Command::ReadState);
        }

        Event::ConnectFailed(error) => {
            state.note(format!("Could not connect: {error}"));
            state.connection = Connection::Disconnected;
        }

        Event::Disconnected => {
            state.note("Disconnected.");
            state.connection = Connection::Disconnected;
            state.polling = false;
            state.master.running = false;
            state.master.latest = None;
        }

        Event::State(live) => {
            state.live_error = None;
            state.live = Some(*live);
        }

        Event::StateFailed(error) => {
            state.live = None;
            state.live_error = Some(error);
        }

        Event::MasterStarted { master_key, source } => {
            state.master.running = true;
            state.master.started_with = Some(master_key);
            state.master.key_source = Some(source.clone());
            state.note(format!(
                "Master emulation started with key {} ({source}).",
                hex(&master_key)
            ));
        }

        Event::MasterUpdate(update) => {
            let line = format!(
                "< {}   {}",
                hex_frame(&update.request),
                match &update.reply {
                    Some(reply) => format!("> {}", hex_frame(reply)),
                    None => "(no reply due)".to_string(),
                }
            );
            state.master.frames.push(line);
            for event in &update.log {
                state.master.frames.push(format!("  # {}", event.message));
            }
            if state.master.frames.len() > 300 {
                let excess = state.master.frames.len() - 300;
                state.master.frames.drain(..excess);
            }
            state.master.latest = Some(*update);
        }

        Event::MasterStopped => {
            state.master.running = false;
            state.note("Master emulation stopped.");
        }

        Event::DownloadFinished(result) => {
            state.sending = false;
            state.confirm_download = false;
            state.download_result = Some(match result {
                Ok(()) => Ok(
                    "The ECU accepted the download. It is now in adaptation mode and will not \
                     start until a master supplies noKeyMst."
                        .to_string(),
                ),
                Err(e) => Err(e),
            });
        }

        Event::Log(line) => state.note(line),
    }

    Task::none()
}

impl State {
    /// A key source changed, so anything derived from it is stale.
    fn after_source_change(&mut self, which: Which) {
        self.invalidate_plan();
        if which == Which::Target {
            // The DFlash editor works on the target's dump.
            self.dflash = DflashState::default();
        }
    }

    fn invalidate_plan(&mut self) {
        self.plan = None;
        self.plan_error = None;
        self.preflight.clear();
        self.confirm_download = false;
        self.download_result = None;
    }

    /// Load one immobilizer channel into the editor fields.
    fn load_channel_for_edit(&mut self, channel: u8) {
        self.dflash.edit_error = None;
        self.dflash.save_result = None;
        self.dflash.confirm_write = false;

        let Some(survey) = self.target.survey.as_ref() else {
            self.dflash.edited = None;
            return;
        };
        let record = survey
            .records
            .iter()
            .find(|(c, _)| *c == channel)
            .and_then(|(_, r)| r.clone());

        match record {
            Some(record) => {
                self.dflash.vin_input = record.vin();
                self.dflash.idx_tun_input = format!("{:02X}", record.idx_tun());
                self.dflash.no_key_mst_input = format!("{:04X}", record.no_key_mst());
                self.dflash.no_key_secu_input = hex(&record.no_key_secu());
                self.dflash.ct_fazit_input = format!("{:02X}", record.ct_dat_bas_fazit());
                self.dflash.st_stat_index = StStatFct::all()
                    .iter()
                    .position(|s| *s == record.st_stat_fct())
                    .unwrap_or(1);
                self.dflash.edited = Some(record);
            }
            None => {
                self.dflash.edited = None;
                self.dflash.edit_error = Some(format!(
                    "channel {channel} did not decrypt to a valid record"
                ));
            }
        }
    }

    /// Fold the editor fields back into the record.
    ///
    /// The record keeps its raw bytes, so a field nobody touched cannot drift —
    /// only what is set here changes.
    fn apply_dflash_edits(&mut self) {
        let Some(channel) = self.dflash.selected_channel else {
            return;
        };
        // Always start from the record as it was read, so an edit that briefly
        // fails to parse cannot compound with the previous one.
        let Some(survey) = self.target.survey.as_ref() else {
            return;
        };
        let Some(mut record) = survey
            .records
            .iter()
            .find(|(c, _)| *c == channel)
            .and_then(|(_, r)| r.clone())
        else {
            return;
        };

        self.dflash.edit_error = None;
        self.dflash.save_result = None;

        if let Err(e) = record.set_vin(self.dflash.vin_input.trim()) {
            self.dflash.edit_error = Some(format!("VIN: {e}"));
            return;
        }
        match parse_u8(&self.dflash.idx_tun_input) {
            Ok(v) => record.set_idx_tun(v),
            Err(e) => {
                self.dflash.edit_error = Some(format!("idxTun: {e}"));
                return;
            }
        }
        match crate::secrets::parse_u16(&self.dflash.no_key_mst_input) {
            Ok(v) => record.set_no_key_mst(v),
            Err(e) => {
                self.dflash.edit_error = Some(format!("noKeyMst: {e}"));
                return;
            }
        }
        match parse_hex(&self.dflash.no_key_secu_input) {
            Ok(bytes) if bytes.len() == 16 => {
                let mut key = [0u8; 16];
                key.copy_from_slice(&bytes);
                record.set_no_key_secu(key);
            }
            Ok(bytes) => {
                self.dflash.edit_error =
                    Some(format!("noKeySecu is 16 bytes; {} given", bytes.len()));
                return;
            }
            Err(e) => {
                self.dflash.edit_error = Some(format!("noKeySecu: {e}"));
                return;
            }
        }
        match parse_u8(&self.dflash.ct_fazit_input) {
            Ok(v) => record.set_ct_dat_bas_fazit(v),
            Err(e) => {
                self.dflash.edit_error = Some(format!("ctDatBasFazit: {e}"));
                return;
            }
        }
        record.set_st_stat_fct(StStatFct::all()[self.dflash.st_stat_index.min(3)]);

        self.dflash.edited = Some(record);
        self.dflash.confirm_write = false;
    }
}

/// Build the download for whichever identity write is selected.
fn build_plan(state: &mut State) {
    state.invalidate_plan();

    let Some(target) = state.target.secrets.clone() else {
        state.plan_error = Some("the target ECU's secrets are not available yet".into());
        return;
    };

    let idx_tun_override = if state.idx_tun_input.trim().is_empty() {
        None
    } else {
        match parse_u8(&state.idx_tun_input) {
            Ok(v) => Some(v),
            Err(e) => {
                state.plan_error = Some(format!("idxTun: {e}"));
                return;
            }
        }
    };

    let vin_override = {
        let vin = state.vin_input.trim();
        (!vin.is_empty()).then(|| vin.to_string())
    };

    let built = match state.identity_mode {
        IdentityMode::Transplant => {
            let Some(donor) = state.donor.secrets.clone() else {
                state.plan_error = Some("the donor ECU's secrets are not available yet".into());
                return;
            };
            adapt_plan(&target, &donor, idx_tun_override, vin_override.as_deref())
        }
        IdentityMode::PowerClass => match idx_tun_override {
            Some(idx_tun) => pclass_plan(&target, idx_tun),
            None => {
                state.plan_error = Some("enter the new idxTun / PClass".into());
                return;
            }
        },
        IdentityMode::Vin => match vin_override.as_deref() {
            Some(vin) => vin_plan(&target, vin),
            None => {
                state.plan_error = Some("enter the new VIN".into());
                return;
            }
        },
    };

    let plan = match built {
        Ok(plan) => plan,
        Err(e) => {
            state.plan_error = Some(e.to_string());
            return;
        }
    };

    // The preflight needs a live reading. Without one the plan is still shown —
    // it is just a set of bytes — but nothing is checked, and that is said
    // plainly rather than left to look like a pass.
    match state.live.as_ref() {
        Some(live) => {
            let donor_idx_lab = if state.donor_idx_lab_input.trim().is_empty() {
                None
            } else {
                parse_u8(&state.donor_idx_lab_input).ok()
            };
            state.preflight =
                adapt_preflight(&plan, &live.snapshot, &target, donor_idx_lab, plan.same_ecu);
        }
        None => {
            state.preflight.clear();
            state.plan_error = Some(
                "no live reading, so nothing about this ECU has been checked. Connect and \
                 refresh before sending."
                    .into(),
            );
        }
    }

    state.plan = Some(plan);
}

fn start_master(state: &mut State) -> Task<Message> {
    let Some(secrets) = state.target.secrets.clone() else {
        state.note("Master emulation needs the ECU's secrets: load a dump, record or the fields.");
        return Task::none();
    };
    if !state.connection.has_raw_can() {
        state.note(
            "This connection has no raw CAN, so the ECU's authentication requests are not \
             visible. Use a raw-CAN interface on the powertrain bus.",
        );
        return Task::none();
    }

    let key = match state.master.key_mode() {
        MasterKeyMode::FromEcu => MasterKeySelection::FromEcu,
        MasterKeyMode::Narrow => MasterKeySelection::Narrow,
        MasterKeyMode::Manual => match parse_hex(&state.master.key_hex) {
            Ok(bytes) if bytes.len() == 4 => {
                let mut key = [0u8; 4];
                key.copy_from_slice(&bytes);
                MasterKeySelection::Fixed(key)
            }
            Ok(bytes) => {
                state.note(format!("A master key is 4 bytes; {} given.", bytes.len()));
                return Task::none();
            }
            Err(e) => {
                state.note(format!("Master key: {e}"));
                return Task::none();
            }
        },
    };

    state.master.frames.clear();
    state.master.latest = None;
    state.send(Command::StartMaster {
        secrets: Box::new(secrets),
        key,
    });
    Task::none()
}

fn save_dflash(state: &mut State, path: PathBuf) {
    let Some(record) = state.dflash.edited.clone() else {
        state.dflash.save_result = Some(Err("nothing to save".into()));
        return;
    };
    let Some(keys) = state.target.keys else {
        state.dflash.save_result = Some(Err("no Device ID, so nothing can be re-encrypted".into()));
        return;
    };
    let Some(dump) = state.target.dump.clone() else {
        state.dflash.save_result = Some(Err("no DFlash image is loaded".into()));
        return;
    };

    // All three copies hold the same identity and the firmware votes between
    // them, so writing one and leaving the others would produce a dump the ECU
    // itself would disagree with.
    let mut edited = dump;
    let mut written = Vec::new();
    for channel in mqb_nvcrypt::IMMO_CHANNELS {
        let Some(analysis) = edited.analyze_channel(channel, Some(&keys)) else {
            continue;
        };
        let Ok(existing) = ImmoRecord::decode(&analysis.content) else {
            continue;
        };
        if !existing.dat_dat_crc_ok() {
            continue;
        }
        // Keep each copy's own trailing FEE padding: the records are not all
        // the same length, and only the identity is shared.
        let mut copy = existing;
        copy.set_no_key_secu(record.no_key_secu());
        if let Err(e) = copy.set_vin(&record.vin()) {
            state.dflash.save_result = Some(Err(format!("channel {channel}: {e}")));
            return;
        }
        copy.set_idx_tun(record.idx_tun());
        copy.set_no_key_mst(record.no_key_mst());
        copy.set_ct_dat_bas_fazit(record.ct_dat_bas_fazit());
        copy.set_st_stat_fct(record.st_stat_fct());

        match edited.rewrite_channel(channel, &copy.encode(), Some(&keys)) {
            Ok(()) => written.push(channel),
            Err(e) => {
                state.dflash.save_result = Some(Err(format!("channel {channel}: {e}")));
                return;
            }
        }
    }

    if written.is_empty() {
        state.dflash.save_result = Some(Err(
            "no immobilizer channel could be rewritten in this image".into(),
        ));
        return;
    }

    match std::fs::write(&path, edited.bytes()) {
        Ok(()) => {
            let channels = written
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            state.dflash.save_result = Some(Ok(format!(
                "Wrote {} with channels {channels} updated.",
                path.display()
            )));
            state.dflash.confirm_write = false;
            // The saved image is now the one being edited.
            state.target.dump = Some(edited);
            if let Some(keys) = state.target.keys {
                state.target.survey = Some(mqb_nvcrypt::ImmoChannelSurvey::read(
                    state.target.dump.as_ref().unwrap(),
                    &keys,
                ));
            }
        }
        Err(e) => state.dflash.save_result = Some(Err(format!("could not write the file: {e}"))),
    }
}

// ── File dialogs ──────────────────────────────────────────────────────────────

async fn pick_file(title: &str, extensions: &[&str]) -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .set_title(title)
        .add_filter(title, extensions)
        .pick_file()
        .await
        .map(|handle| handle.path().to_path_buf())
}

async fn save_file(title: &str, extension: &str) -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .set_title(title)
        .add_filter(title, &[extension])
        .save_file()
        .await
        .map(|handle| handle.path().to_path_buf())
}

fn hex_frame(frame: &[u8; 8]) -> String {
    frame
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The three master keys, for the picker's help text.
pub fn master_key_candidates() -> Vec<String> {
    MASTER_KEY_CANDIDATES.iter().map(|k| hex(k)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mqb_immo::state::{ImmoSnapshot, ImmoSupport};
    use mqb_immo::{assess, PreflightLevel};
    use mqb_modules::modules::simos18::S18_FLASH_INFO;
    use std::collections::HashMap;

    /// The reference record from NVCRYPT.md: VIN 1VWAT7A31FC022915, idxTun 6A,
    /// noKeyMst 2735.
    const RECORD_HEX: &str = "AAC985528F0000D43A0000F88B005967F8FBF7AF634F17CF7865F18324C3\
                              3156574154374133314643303232393135016AAA2735000000\
                              00A505000003000000BF80";

    /// `update`, discarding the `Task` these tests never run.
    fn dispatch(state: &mut State, message: Message) {
        let _ = update(state, message);
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        crate::secrets::parse_hex(input).expect("valid hex")
    }

    /// A different ECU for a transplant to come from.
    ///
    /// Derived from the reference record rather than written out by hand, so
    /// its CRCs are real — `ImmoRecord::encode` recomputes them, which is
    /// exactly the property the dump editor depends on.
    fn donor_hex() -> String {
        let mut record = ImmoRecord::decode(&decode_hex(RECORD_HEX)).expect("reference decodes");
        record.set_no_key_secu([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        record.set_vin("WVWZZZ1KZAW000001").expect("valid VIN");
        record.set_no_key_mst(0x9E42);
        record.set_idx_tun(0x88);
        crate::secrets::hex(&record.encode())
    }

    fn state_with_target() -> State {
        let mut state = State::default();
        state.target.set_kind(SourceKind::Record);
        state.target.record_hex = RECORD_HEX.into();
        state.target.resolve();
        assert!(
            state.target.is_ready(),
            "the reference record must resolve: {:?}",
            state.target.error
        );
        state
    }

    /// A synthetic healthy ECU on the bus, holding the reference record's key.
    fn healthy_live(key: [u8; 16], idx_tun: u8, allow: [u8; 5]) -> LiveState {
        let support = ImmoSupport::for_module(&S18_FLASH_INFO).unwrap();
        let challenge = [0x11u8, 0x22, 0x33, 0x44];
        let fazit = [b'F'; 23];
        let vin = b"1VWAT7A31FC022915";
        let adapt = vec![0x02, 0x01, 0x0D, 0, 0, 0, 0, 0, 0, 0];
        let bits = vec![0x04, 0xFC, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut snap = vec![0u8; 19];
        snap[0] = 0x53;
        snap[9] = idx_tun;
        snap[10..15].copy_from_slice(&allow);
        snap[15..18].copy_from_slice(&[8, 2, 0]);

        let cks = mqb_immo::diag::identity_checksum(&key, &fazit, vin, &adapt, &bits, &challenge)
            .unwrap();

        let mut dids: HashMap<u16, Vec<u8>> = HashMap::new();
        dids.insert(mqb_immo::state::DID_CHALLENGE, challenge.to_vec());
        dids.insert(mqb_immo::state::DID_STATE, adapt);
        dids.insert(mqb_immo::state::DID_STATUS_BITS, bits);
        dids.insert(mqb_immo::state::DID_VIN, vin.to_vec());
        dids.insert(mqb_immo::state::DID_FAZIT, fazit.to_vec());
        dids.insert(mqb_immo::state::DID_LOCKOUT, vec![0u8; 6]);
        dids.insert(mqb_immo::state::DID_EXTENDED, snap);
        dids.insert(mqb_immo::state::DID_IDENTITY_CKS, cks.to_vec());

        let snapshot = ImmoSnapshot::from_dids(support, dids);
        let report = assess(&snapshot);
        LiveState { snapshot, report }
    }

    fn key_of(state: &State) -> [u8; 16] {
        state.target.secrets.as_ref().unwrap().no_key_secu
    }

    /// The whole point of the Identity tab: build a plan, check it, and have
    /// the plan encrypted under the key the ECU holds now.
    #[test]
    fn a_power_class_plan_builds_and_checks() {
        let mut state = state_with_target();
        state.live = Some(healthy_live(key_of(&state), 0x6A, [0x6A, 0, 0, 0, 0]));
        state.identity_mode = IdentityMode::PowerClass;
        state.idx_tun_input = "6a".into();

        dispatch(&mut state, Message::BuildPlanPressed);

        let plan = state.plan.as_ref().expect("a plan was built");
        assert_eq!(plan.idx_tun, 0x6A);
        assert_eq!(plan.encrypted_under, key_of(&state));
        assert!(plan.same_ecu);
        assert!(!state.preflight.is_empty(), "the preflight ran");
        assert!(
            !state
                .preflight
                .iter()
                .any(|i| i.level == PreflightLevel::Blocker),
            "unexpected blockers: {:#?}",
            state.preflight
        );
    }

    /// The interlock that bricks silently must block in the UI too.
    #[test]
    fn an_idx_tun_outside_the_allow_list_blocks() {
        let mut state = state_with_target();
        state.live = Some(healthy_live(key_of(&state), 0x6A, [0x6A, 0, 0, 0, 0]));
        state.identity_mode = IdentityMode::PowerClass;
        state.idx_tun_input = "88".into();

        dispatch(&mut state, Message::BuildPlanPressed);

        assert!(state.plan.is_some());
        assert!(state
            .preflight
            .iter()
            .any(|i| i.level == PreflightLevel::Blocker
                && i.message.contains("not in this ECU's allow-list")));
    }

    /// Without a live reading nothing has been checked, and the UI must not be
    /// left holding an empty preflight that reads like a pass.
    #[test]
    fn building_a_plan_without_a_live_reading_says_so() {
        let mut state = state_with_target();
        state.identity_mode = IdentityMode::PowerClass;
        state.idx_tun_input = "6a".into();

        dispatch(&mut state, Message::BuildPlanPressed);

        assert!(state.plan.is_some(), "the bytes are still shown");
        assert!(state.preflight.is_empty());
        assert!(
            state
                .plan_error
                .as_ref()
                .is_some_and(|e| e.contains("nothing about this ECU has been checked")),
            "the absence of checks has to be stated: {:?}",
            state.plan_error
        );
    }

    /// Changing the keys after building a plan must throw the plan away.
    /// Otherwise a download built for one ECU could be sent to another.
    #[test]
    fn changing_the_key_source_discards_the_plan() {
        let mut state = state_with_target();
        state.live = Some(healthy_live(key_of(&state), 0x6A, [0x6A, 0, 0, 0, 0]));
        state.identity_mode = IdentityMode::PowerClass;
        state.idx_tun_input = "6a".into();
        dispatch(&mut state, Message::BuildPlanPressed);
        dispatch(&mut state, Message::ConfirmDownloadToggled(true));
        assert!(state.plan.is_some());
        assert!(state.confirm_download);

        dispatch(
            &mut state,
            Message::RecordHexChanged(Which::Target, donor_hex()),
        );

        assert!(state.plan.is_none(), "a stale plan must not survive");
        assert!(state.preflight.is_empty());
        assert!(
            !state.confirm_download,
            "the confirmation must not carry over to a different plan"
        );
    }

    /// Likewise for the values: changing idxTun after confirming must re-arm
    /// the confirmation.
    #[test]
    fn changing_a_value_discards_the_confirmation() {
        let mut state = state_with_target();
        state.live = Some(healthy_live(key_of(&state), 0x6A, [0x6A, 0, 0, 0, 0]));
        state.identity_mode = IdentityMode::PowerClass;
        state.idx_tun_input = "6a".into();
        dispatch(&mut state, Message::BuildPlanPressed);
        dispatch(&mut state, Message::ConfirmDownloadToggled(true));

        dispatch(&mut state, Message::IdxTunChanged("88".into()));

        assert!(state.plan.is_none());
        assert!(!state.confirm_download);
    }

    /// A transplant carries the donor's identity but is keyed by the target.
    #[test]
    fn a_transplant_is_keyed_by_the_target() {
        let mut state = state_with_target();
        state.donor.set_kind(SourceKind::Record);
        state.donor.record_hex = donor_hex();
        state.donor.resolve();
        assert!(
            state.donor.is_ready(),
            "donor record: {:?}",
            state.donor.error
        );

        let target_key = key_of(&state);
        let donor_key = state.donor.secrets.as_ref().unwrap().no_key_secu;
        assert_ne!(target_key, donor_key);

        state.live = Some(healthy_live(target_key, 0x6A, [0x88, 0, 0, 0, 0]));
        state.identity_mode = IdentityMode::Transplant;
        dispatch(&mut state, Message::BuildPlanPressed);

        let plan = state.plan.as_ref().expect("a plan was built");
        assert_eq!(plan.no_key_secu, donor_key, "the donor's key is written");
        assert_eq!(
            plan.encrypted_under, target_key,
            "but the target's key encrypts it"
        );
        assert!(!plan.same_ecu);
    }

    /// A VIN change needs a VIN, and a malformed one is refused rather than
    /// producing a record with a truncated field.
    #[test]
    fn a_vin_change_validates_its_input() {
        let mut state = state_with_target();
        state.live = Some(healthy_live(key_of(&state), 0x6A, [0x6A, 0, 0, 0, 0]));
        state.identity_mode = IdentityMode::Vin;

        dispatch(&mut state, Message::BuildPlanPressed);
        assert!(state.plan.is_none());
        assert!(state.plan_error.as_ref().unwrap().contains("new VIN"));

        dispatch(&mut state, Message::VinChanged("TOO SHORT".into()));
        dispatch(&mut state, Message::BuildPlanPressed);
        assert!(state.plan.is_none());

        dispatch(&mut state, Message::VinChanged("WVWZZZ1KZAW000001".into()));
        dispatch(&mut state, Message::BuildPlanPressed);
        let plan = state.plan.as_ref().expect("a valid VIN builds a plan");
        assert_eq!(plan.vin, "WVWZZZ1KZAW000001");
        assert_eq!(plan.idx_tun, 0x6A, "only the VIN moves");
    }

    /// Master emulation must refuse to start without a connection that can
    /// carry it, rather than appearing to run and never hearing anything.
    #[test]
    fn master_emulation_needs_raw_can_and_secrets() {
        let mut state = State::default();
        dispatch(&mut state, Message::StartMasterPressed);
        assert!(
            state
                .log
                .iter()
                .any(|l| l.contains("needs the ECU's secrets")),
            "{:?}",
            state.log
        );

        let mut state = state_with_target();
        state.connection = Connection::Connected {
            interface: "j2534-isotp".into(),
            raw_can: false,
        };
        dispatch(&mut state, Message::StartMasterPressed);
        assert!(
            state.log.iter().any(|l| l.contains("no raw CAN")),
            "{:?}",
            state.log
        );
        assert!(!state.master.running);
    }

    /// The interface picker knows, before connecting, which choices can carry
    /// master emulation.
    #[test]
    fn hardware_isotp_is_known_not_to_support_the_master() {
        let mut state = State {
            interface_kind: InterfaceKind::J2534IsoTp,
            ..State::default()
        };
        assert!(!state.interface_supports_master());

        for kind in [
            InterfaceKind::J2534,
            InterfaceKind::Panda,
            InterfaceKind::SocketCan,
        ] {
            state.interface_kind = kind;
            assert!(state.interface_supports_master(), "{kind:?}");
        }
    }

    /// A download result must clear the confirmation, so a second click cannot
    /// resend without a fresh decision.
    #[test]
    fn a_finished_download_re_arms_the_confirmation() {
        let mut state = state_with_target();
        state.confirm_download = true;
        state.sending = true;

        dispatch(
            &mut state,
            Message::Connection(Event::DownloadFinished(Ok(()))),
        );

        assert!(!state.sending);
        assert!(!state.confirm_download);
        assert!(state.download_result.as_ref().unwrap().is_ok());
    }

    /// Disconnecting must not leave the UI claiming the master is still
    /// answering the ECU.
    #[test]
    fn disconnecting_clears_the_master() {
        let mut state = State {
            connection: Connection::Connected {
                interface: "panda".into(),
                raw_can: true,
            },
            polling: true,
            ..State::default()
        };
        state.master.running = true;

        dispatch(&mut state, Message::Connection(Event::Disconnected));

        assert!(!state.master.running);
        assert!(!state.polling);
        assert!(!state.connection.is_connected());
    }
}
