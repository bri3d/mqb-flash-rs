//! Simos18 immobilizer pre-flight check.
//!
//! If the ECU is already in — or is left in — a non-starting immobilizer state,
//! the car will crank but not run, and for several of those states there is no
//! diagnostic way back. This module reads the immobilizer status DIDs over
//! plain UDS and turns them into findings the flash wizard can show the user.
//!
//! **When it applies.** Not just a full flash. The power-class allow-list
//! `strVarTun` — the table `CheckTuning` tests `idxTun` against — lives in the
//! **calibration area**, so writing CAL alone is enough to trip the anti-tuning
//! interlock and leave the ECU unable to start. Any operation that writes CAL
//! and then lets the ECU boot the application software is in scope.
//!
//! The unlock operation is the exception: it writes CAL, but the ECU never
//! fully boots the application software afterwards, and `CheckTuning` runs from
//! ImoDat's periodic task in the ASW — so the interlock never evaluates and
//! there is nothing to predict.
//!
//! **Policy.** The wizard *warns* and asks for explicit confirmation; it never
//! hard-refuses. There is deliberately no `Severity::Block`. If the ECU will not
//! answer the status DIDs at all the check *fails open*: that is reported as
//! [`Severity::Unknown`] ("could not be verified"), never as a risk.
//!
//! **Scope.** Every rule here comes from reverse-engineering work done on
//! Simos18 and only Simos18. There is no equivalent research for DQ250, DQ381,
//! Haldex, or the other Simos variants, so an [`ImmoSnapshot`] can only be
//! constructed by first obtaining an [`ImmoSupport`] token, which
//! [`ImmoSupport::for_module`] hands out for Simos18 alone. Every other module
//! is structurally incapable of producing a report.
//!
//! All reads are `ReadDataByIdentifier` on the module's normal channel
//! (tester `0x7E0` / ECU `0x7E8`) in the *default* session, with no
//! SecurityAccess and no immobilizer login.

use std::collections::HashMap;

use automotive::TransportLayer;

use mqb_modules::FlashInfo;

use crate::flash::read_dids;

// ── DID list ──────────────────────────────────────────────────────────────────

/// The immobilizer status DIDs, in the order they must be requested.
///
/// The order matters: DID `0x2F9` is refused by the ECU unless immobilizer
/// services 1/3/4/9 have already run in the current session. We do not read
/// `0x2F9`, but the surrounding order is kept exactly as the research session
/// used it so that a future addition of `0x2F9` behaves the same way.
pub const IMMO_DIDS: [u16; 7] = [0x2E0, 0x2ED, 0x2EE, 0x2EF, 0x2FF, 0xF190, 0xF17C];

/// `stStatFct` — immobilizer function state (DID `0x2ED`, byte 0).
pub const DID_STATE: u16 = 0x2ED;
/// Immobilizer status bit field (DID `0x2EE`).
pub const DID_STATUS_BITS: u16 = 0x2EE;
/// Download / login lockout timers (DID `0x2EF`).
pub const DID_LOCKOUT: u16 = 0x2EF;
/// Extended immobilizer info: tuning index, allow-list, versions (DID `0x2FF`).
pub const DID_EXTENDED: u16 = 0x2FF;
/// VIN (DID `0xF190`).
pub const DID_VIN: u16 = 0xF190;
/// FAZIT identification string (DID `0xF17C`).
pub const DID_FAZIT: u16 = 0xF17C;

// ── Module gating ─────────────────────────────────────────────────────────────

/// Proof that the target module is one the immobilizer research covers.
///
/// This exists so that no caller can run the Simos18 rules against a DQ250,
/// DQ381 or Haldex and present the result as meaningful. It is required to
/// build an [`ImmoSnapshot`], which is in turn required by every rule function.
#[derive(Debug, Clone, Copy)]
pub struct ImmoSupport {
    // Private field: the only way to obtain one is `for_module`.
    _private: (),
}

impl ImmoSupport {
    /// Returns `Some` only for Simos18 (project prefix `SC8`).
    ///
    /// Simos 12.2 / 16 / 18.1 / 18.10 / 18.4 are *not* included: the DID layout
    /// and the tuning-interlock behaviour were only ever verified on Simos18,
    /// and a wrong decode here would produce a confident, wrong verdict about
    /// whether a car will start.
    pub fn for_module(flash_info: &FlashInfo) -> Option<Self> {
        if flash_info.project_name == "SC8" {
            Some(Self { _private: () })
        } else {
            None
        }
    }
}

// ── Severity / findings ───────────────────────────────────────────────────────

/// How serious a finding is. There is intentionally no `Block` variant — the
/// wizard warns and confirms, it never refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Informational: nothing about this finding should gate the flash.
    Ok,
    /// The user must be shown this and must explicitly confirm.
    Warn,
    /// The check could not be performed. Fail-open — shown as a caveat, not a risk.
    Unknown,
}

impl Severity {
    /// Rank used to pick a report-level severity. `Warn` outranks `Unknown`
    /// because a known risk is more actionable than an unverifiable one.
    fn rank(self) -> u8 {
        match self {
            Severity::Ok => 0,
            Severity::Unknown => 1,
            Severity::Warn => 2,
        }
    }

    /// The more severe of two severities.
    pub fn worst(self, other: Severity) -> Severity {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Which rule produced a finding. Lets the UI group or filter findings without
/// string-matching the message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmoRule {
    /// The check itself could not run (DIDs missing or malformed).
    Unavailable,
    /// R2 — tuning interlock (`idxTun` vs. `strVarTun`).
    TuningInterlock,
    /// R3 — dead state (`stStatFct` 10 / 0x58 / 0x63).
    DeadState,
    /// R4 — never adapted (`stStatFct` 1).
    NotAdapted,
    /// R5 — hidden state behind a reported `stStatFct` of 2.
    HiddenState,
    /// R6 — current lock / release status.
    LockState,
    /// R7 — download or login lockout counting down.
    Lockout,
    /// R8 — last recorded immobilizer error code.
    LastError,
    /// `bInhAcsMem` — tooling limitation, never an immobilizer risk.
    MemoryAccess,
    /// R12 — a before/after difference across a flash.
    PostFlashChange,
}

/// A single observation about the immobilizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmoFinding {
    /// Which rule produced this.
    pub rule: ImmoRule,
    /// How the wizard should treat it.
    pub severity: Severity,
    /// One-line, user-facing summary.
    pub message: String,
    /// Longer explanation and, where one exists, the recovery path.
    pub detail: String,
}

impl ImmoFinding {
    fn new(
        rule: ImmoRule,
        severity: Severity,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            rule,
            severity,
            message: message.into(),
            detail: detail.into(),
        }
    }
}

/// The result of applying every rule to a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmoReport {
    /// Worst severity across all findings.
    pub severity: Severity,
    /// Raw `stStatFct` as reported by the ECU, before R5 disambiguation.
    pub reported_state: Option<u8>,
    /// The state after R5 disambiguation, when it could be determined.
    pub state: Option<ImmoState>,
    /// Every finding, in rule order.
    pub findings: Vec<ImmoFinding>,
}

impl ImmoReport {
    /// True when at least one finding is a genuine risk the user must confirm.
    pub fn has_risk(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Warn)
    }

    /// Findings the user must explicitly confirm.
    pub fn risks(&self) -> impl Iterator<Item = &ImmoFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warn)
    }
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

/// The raw DID bytes read from one ECU at one point in time.
///
/// Raw bytes are stored rather than decoded values so that a before/after
/// comparison (R12) is exact, including fields no rule currently looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImmoSnapshot {
    dids: HashMap<u16, Vec<u8>>,
}

impl ImmoSnapshot {
    /// Build a snapshot from an already-collected DID map.
    ///
    /// Requires an [`ImmoSupport`] token so a snapshot cannot exist for a module
    /// the research does not cover.
    pub fn from_dids(_support: ImmoSupport, dids: HashMap<u16, Vec<u8>>) -> Self {
        Self { dids }
    }

    /// Raw bytes for one DID, if the ECU answered it.
    pub fn raw(&self, did: u16) -> Option<&[u8]> {
        self.dids.get(&did).map(|v| v.as_slice())
    }

    /// The DIDs every rule needs, that the ECU did not answer with usable data.
    pub fn missing_required(&self) -> Vec<u16> {
        [
            (DID_STATE, 10usize),
            (DID_STATUS_BITS, 10),
            (DID_EXTENDED, 19),
        ]
        .iter()
        .filter(|(did, len)| self.raw(*did).map(|b| b.len() < *len).unwrap_or(true))
        .map(|(did, _)| *did)
        .collect()
    }

    /// VIN from DID `0xF190`, if present.
    pub fn vin(&self) -> Option<String> {
        self.raw(DID_VIN).map(ascii_string)
    }

    /// FAZIT identification string from DID `0xF17C`, if present.
    pub fn fazit(&self) -> Option<String> {
        self.raw(DID_FAZIT).map(ascii_string)
    }
}

/// Render a DID payload as printable ASCII; non-printable bytes become `.`.
fn ascii_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Format a byte slice as space-separated uppercase hex, for finding details.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Reading ───────────────────────────────────────────────────────────────────

/// Read every immobilizer DID in the required order.
///
/// Never fails: DIDs the ECU refuses are simply absent from the snapshot, which
/// the rules treat as [`Severity::Unknown`] (fail-open). Response-pending
/// (NRC `0x78`) is handled inside `UDSClient`.
///
/// Takes an [`ImmoSupport`] token — the spec's signature is
/// `read_immo_snapshot(transport)`, but the token is threaded through here as
/// well so that the module gate cannot be bypassed by reading first and looking
/// for a way to build a snapshot afterwards.
pub async fn read_immo_snapshot<T: TransportLayer>(
    transport: &T,
    support: ImmoSupport,
) -> ImmoSnapshot {
    let dids = read_dids(transport, &IMMO_DIDS).await;
    ImmoSnapshot::from_dids(support, dids)
}

// ── DID decodes ───────────────────────────────────────────────────────────────

/// Immobilizer function state (`stStatFct`).
///
/// Values 3, `0x42` and 4 never appear on the wire — the ECU forces all three to
/// report as 2 — so they are only ever produced by the R5 disambiguation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmoState {
    /// 1 — neutral, no immobilizer identity has ever been adapted.
    NotAdapted,
    /// 2 — adapted.
    Adapted,
    /// 3 — hardware-sample adapted (reported as 2).
    HardwareSampleAdapted,
    /// 4 — adaptation mode (reported as 2).
    AdaptationMode,
    /// 10 — locked (`noConfMod` remap).
    NoConfMod,
    /// `0x42` `'B'` — tuning check failed (reported as 2).
    TuningCheckFailed,
    /// `0x58` `'X'` — hardware-sample lock.
    HardwareSampleLock,
    /// `0x63` `'c'` — locked.
    LockedC,
    /// Anything else the ECU reports.
    Other(u8),
}

impl ImmoState {
    /// The `stStatFct` byte this state corresponds to.
    pub fn raw(self) -> u8 {
        match self {
            ImmoState::NotAdapted => 1,
            ImmoState::Adapted => 2,
            ImmoState::HardwareSampleAdapted => 3,
            ImmoState::AdaptationMode => 4,
            ImmoState::NoConfMod => 10,
            ImmoState::TuningCheckFailed => 0x42,
            ImmoState::HardwareSampleLock => 0x58,
            ImmoState::LockedC => 0x63,
            ImmoState::Other(v) => v,
        }
    }

    /// Decode a wire value. Never yields 3, 4 or `0x42` — see R5.
    pub fn from_raw(v: u8) -> ImmoState {
        match v {
            1 => ImmoState::NotAdapted,
            2 => ImmoState::Adapted,
            10 => ImmoState::NoConfMod,
            0x58 => ImmoState::HardwareSampleLock,
            0x63 => ImmoState::LockedC,
            other => ImmoState::Other(other),
        }
    }

    /// Short human-readable label including the raw value.
    pub fn label(self) -> String {
        let text = match self {
            ImmoState::NotAdapted => "neutral / not adapted",
            ImmoState::Adapted => "adapted",
            ImmoState::HardwareSampleAdapted => "hardware-sample adapted",
            ImmoState::AdaptationMode => "adaptation mode",
            ImmoState::NoConfMod => "locked (noConfMod)",
            ImmoState::TuningCheckFailed => "'B' — tuning check failed",
            ImmoState::HardwareSampleLock => "'X' — hardware-sample lock",
            ImmoState::LockedC => "'c' — locked",
            ImmoState::Other(_) => "unrecognised state",
        };
        format!("{text} (stStatFct = 0x{:02X})", self.raw())
    }

    /// True for the three states in which neither login nor download is
    /// accepted, so there is no diagnostic recovery (R3).
    pub fn is_dead(self) -> bool {
        matches!(
            self,
            ImmoState::NoConfMod | ImmoState::HardwareSampleLock | ImmoState::LockedC
        )
    }
}

/// Decoded DID `0x2ED` (10 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDid {
    /// Byte 0 as reported. The ECU forces 3, `0x42` and 4 to report as 2, so a
    /// value of 2 is ambiguous — resolve it with R5 ([`resolve_state`]).
    pub st_stat_fct: u8,
    /// Byte 1 — `ctDatBasFazit`.
    pub ct_dat_bas_fazit: u8,
    /// Byte 2 — `idxLab`.
    pub idx_lab: u8,
    /// Byte 8 bit `0x08` — `bLimModEna`.
    pub b_lim_mod_ena: bool,
}

/// Decode DID `0x2ED`. Returns `None` if the payload is short.
pub fn decode_2ed(p: &[u8]) -> Option<StateDid> {
    if p.len() < 10 {
        return None;
    }
    Some(StateDid {
        st_stat_fct: p[0],
        ct_dat_bas_fazit: p[1],
        idx_lab: p[2],
        b_lim_mod_ena: p[8] & 0x08 != 0,
    })
}

/// Decoded DID `0x2EE` (10 bytes).
///
/// A fully healthy released ECU reads `p[0] = 0x04`, `p[1] = 0xFC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusBitsDid {
    /// Byte 0 bit `0x04` — ignition on.
    pub ignition_on: bool,
    /// Byte 1 bit `0x80` — `stStatFct != 3`.
    pub st_not_3: bool,
    /// Byte 1 bit `0x40` — `stStatFct == 2`.
    pub st_is_2: bool,
    /// Byte 1 bit `0x20` — `bMstRespRx`, the master (cluster) replied.
    pub b_mst_resp_rx: bool,
    /// Byte 1 bit `0x10` — `bMstCksVld`, `CrcMaster` accepted.
    pub b_mst_cks_vld: bool,
    /// Byte 1 bit `0x08` — `bMstKeyVld`, PIN accepted.
    pub b_mst_key_vld: bool,
    /// `bInhAcsMem` — memory access inhibited. The wire bit (byte 1, `0x04`) is
    /// **inverted**: set means *not* inhibited, so this field is the logical
    /// negation of that bit.
    pub b_inh_acs_mem: bool,
}

/// Decode DID `0x2EE`. Returns `None` if the payload is short.
pub fn decode_2ee(p: &[u8]) -> Option<StatusBitsDid> {
    if p.len() < 10 {
        return None;
    }
    Some(StatusBitsDid {
        ignition_on: p[0] & 0x04 != 0,
        st_not_3: p[1] & 0x80 != 0,
        st_is_2: p[1] & 0x40 != 0,
        b_mst_resp_rx: p[1] & 0x20 != 0,
        b_mst_cks_vld: p[1] & 0x10 != 0,
        b_mst_key_vld: p[1] & 0x08 != 0,
        b_inh_acs_mem: p[1] & 0x04 == 0,
    })
}

/// Decoded DID `0x2EF` (6 bytes) — lockout timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutDid {
    /// Byte 0 — minutes remaining before a download is accepted again.
    pub download_lockout_minutes: u8,
    /// Byte 1 — minutes remaining before a login is accepted again.
    pub login_lockout_minutes: u8,
}

/// Decode DID `0x2EF`. Returns `None` if the payload is short.
pub fn decode_2ef(p: &[u8]) -> Option<LockoutDid> {
    if p.len() < 6 {
        return None;
    }
    Some(LockoutDid {
        download_lockout_minutes: p[0],
        login_lockout_minutes: p[1],
    })
}

/// Decoded DID `0x2FF` (19 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedDid {
    /// Byte 0 — `0x53` `'S'` normally, `0x41` `'A'` on a hardware-sample ECU.
    pub marker: u8,
    /// Byte 7 — `ctAuthLos`, quantized (see [`unquantize`]).
    pub ct_auth_los: u8,
    /// Byte 8 — `ctWrAccNvm`, quantized (see [`unquantize`]).
    pub ct_wr_acc_nvm: u8,
    /// Byte 9 — `idxTun` / PClass.
    pub idx_tun: u8,
    /// Bytes 10..15 — `strVarTun`, the five-entry power-class allow-list.
    pub str_var_tun: [u8; 5],
    /// Bytes 15..18 — Imo component version, e.g. `08 02 00` = 8.2.0.
    pub imo_version: [u8; 3],
    /// Byte 18 — last error code. No decode table is available.
    pub last_error: u8,
}

impl ExtendedDid {
    /// True when byte 0 reads `0x41` `'A'` — a hardware-sample ECU.
    pub fn is_hardware_sample(self) -> bool {
        self.marker == 0x41
    }

    /// `ctAuthLos` with the quantization undone; `None` means saturated.
    pub fn auth_loss_count(self) -> Option<u32> {
        unquantize(self.ct_auth_los)
    }

    /// `ctWrAccNvm` with the quantization undone; `None` means saturated.
    pub fn nvm_write_count(self) -> Option<u32> {
        unquantize(self.ct_wr_acc_nvm)
    }

    /// Imo component version as `major.minor.patch`.
    pub fn version_string(self) -> String {
        format!(
            "{}.{}.{}",
            self.imo_version[0], self.imo_version[1], self.imo_version[2]
        )
    }
}

/// Decode DID `0x2FF`. Returns `None` if the payload is short.
pub fn decode_2ff(p: &[u8]) -> Option<ExtendedDid> {
    if p.len() < 19 {
        return None;
    }
    let mut str_var_tun = [0u8; 5];
    str_var_tun.copy_from_slice(&p[10..15]);
    let mut imo_version = [0u8; 3];
    imo_version.copy_from_slice(&p[15..18]);
    Some(ExtendedDid {
        marker: p[0],
        ct_auth_los: p[7],
        ct_wr_acc_nvm: p[8],
        idx_tun: p[9],
        str_var_tun,
        imo_version,
        last_error: p[18],
    })
}

/// Undo the counter quantization used by DID `0x2FF` bytes 7 and 8.
///
/// `None` means the counter is saturated (`255`) and the true value is unknown.
pub fn unquantize(v: u8) -> Option<u32> {
    match v {
        255 => None,
        200..=254 => Some((v as u32 - 200) * 1000),
        100..=199 => Some((v as u32 - 100) * 100),
        _ => Some(v as u32),
    }
}

// ── Rules ─────────────────────────────────────────────────────────────────────

/// Outcome of the R2 tuning-interlock test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuningStatus {
    /// `idxTun` is present in a non-zero allow-list.
    Ok,
    /// The allow-list `strVarTun` is entirely zero — nothing can ever match.
    AllowListEmpty,
    /// `idxTun` is not one of the five allow-list entries.
    NotAllowed,
}

/// R2 — the tuning interlock, the only proven silent immobilizer brick.
///
/// `idxTun` is byte 4 of every authentication plaintext block. Once the ECU
/// decides the tuning check failed it forces `stStatFct` to `0x42` `'B'`, and
/// from then on it can never produce a `CrcMaster`/`CrcSlave` the cluster will
/// accept. Recovery needs the `noKeySecu` key, which only exists in a DFlash dump.
pub fn tuning_status(ext: &ExtendedDid) -> TuningStatus {
    if ext.str_var_tun.iter().all(|&b| b == 0) {
        TuningStatus::AllowListEmpty
    } else if !ext.str_var_tun.contains(&ext.idx_tun) {
        TuningStatus::NotAllowed
    } else {
        TuningStatus::Ok
    }
}

/// True for the states in which the ECU has already zeroed `idxTun`, so an
/// `idxTun` of 0 there is expected and must not be reported as a tuning
/// violation (the R2 exception).
fn state_zeroes_idx_tun(st_stat_fct: u8) -> bool {
    matches!(st_stat_fct, 1 | 10 | 0x58 | 0x63)
}

/// R5 — disambiguate a reported `stStatFct` of 2.
///
/// `tuning` is R2's verdict; it is `None` when DID `0x2FF` is unavailable, in
/// which case the `'B'` / adaptation-mode branch cannot be decided and this
/// returns `None`.
pub fn resolve_state(
    state: &StateDid,
    bits: &StatusBitsDid,
    tuning: Option<TuningStatus>,
) -> Option<ImmoState> {
    if state.st_stat_fct != 2 {
        return Some(ImmoState::from_raw(state.st_stat_fct));
    }
    if bits.st_is_2 {
        return Some(ImmoState::Adapted);
    }
    if !bits.st_not_3 {
        return Some(ImmoState::HardwareSampleAdapted);
    }
    // 0x80 set, 0x40 clear: either the tuning lock or adaptation mode, told
    // apart by R2's membership test.
    match tuning? {
        TuningStatus::Ok => Some(ImmoState::AdaptationMode),
        _ => Some(ImmoState::TuningCheckFailed),
    }
}

/// Outcome of the R6 lock/release ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStatus {
    /// The ECU has verified the cluster's `CrcMaster` and PIN.
    ///
    /// This is *not* the same as "the immobilizer is released": those two bits
    /// mean full release only for authentication variant A. Variants B and C
    /// need a bit DID `0x2EE` does not publish.
    MasterVerified,
    /// Ignition is off; the ECU does not authenticate on bench power.
    IgnitionOff,
    /// No master reply — nothing is answering on CAN `0x011`.
    NoMasterReply,
    /// `CrcMaster` was rejected (wrong `noKeySecu`, `idxLab` or `idxTun`).
    CrcMasterRejected,
    /// `CrcMaster` was accepted but the PIN mask was rejected (wrong `noKeyMst`).
    PinRejected,
}

/// R6 — current lock / release status, evaluated in the documented order.
pub fn lock_status(bits: &StatusBitsDid) -> LockStatus {
    if bits.b_mst_cks_vld && bits.b_mst_key_vld {
        LockStatus::MasterVerified
    } else if !bits.ignition_on {
        LockStatus::IgnitionOff
    } else if !bits.b_mst_resp_rx {
        LockStatus::NoMasterReply
    } else if !bits.b_mst_cks_vld {
        LockStatus::CrcMasterRejected
    } else {
        LockStatus::PinRejected
    }
}

// ── Assessment ────────────────────────────────────────────────────────────────

/// Apply R2–R8 plus the `bInhAcsMem` tooling note to a snapshot.
///
/// Fail-open: anything that cannot be decoded yields [`Severity::Unknown`]
/// findings, never risks.
pub fn assess(snapshot: &ImmoSnapshot) -> ImmoReport {
    let mut findings = Vec::new();

    let state = snapshot.raw(DID_STATE).and_then(decode_2ed);
    let bits = snapshot.raw(DID_STATUS_BITS).and_then(decode_2ee);
    let lockout = snapshot.raw(DID_LOCKOUT).and_then(decode_2ef);
    let ext = snapshot.raw(DID_EXTENDED).and_then(decode_2ff);

    // Fail-open: say which of the required DIDs are missing, then evaluate
    // whatever did come back.
    let missing = snapshot.missing_required();
    if !missing.is_empty() {
        let list = missing
            .iter()
            .map(|d| format!("0x{d:04X}"))
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(ImmoFinding::new(
            ImmoRule::Unavailable,
            Severity::Unknown,
            format!("Immobilizer status could not be verified (no usable answer for DID {list})."),
            "The ECU did not answer, or answered with a short payload. This is not evidence of a \
             problem — the check simply could not run. Flashing is not known to be unsafe here, \
             but the immobilizer state is unverified.",
        ));
    }

    let tuning = ext.as_ref().map(tuning_status);

    // R2 — tuning interlock. Skipped in the states where the ECU has already
    // zeroed idxTun; those are reported by R3/R4 instead.
    if let (Some(ext), Some(tuning)) = (ext.as_ref(), tuning) {
        let already_zeroed = state
            .map(|s| state_zeroes_idx_tun(s.st_stat_fct))
            .unwrap_or(false);
        if !already_zeroed {
            match tuning {
                TuningStatus::Ok => {}
                TuningStatus::AllowListEmpty => findings.push(ImmoFinding::new(
                    ImmoRule::TuningInterlock,
                    Severity::Warn,
                    "Tuning interlock: the power-class allow-list (strVarTun) is all zeroes, so \
                     no tuning index can ever match.",
                    tuning_detail(ext),
                )),
                TuningStatus::NotAllowed => findings.push(ImmoFinding::new(
                    ImmoRule::TuningInterlock,
                    Severity::Warn,
                    format!(
                        "Tuning interlock: idxTun 0x{:02X} is not in the power-class allow-list \
                         [{}].",
                        ext.idx_tun,
                        hex(&ext.str_var_tun)
                    ),
                    tuning_detail(ext),
                )),
            }
        }
    }

    // R3 / R4 — the states that speak for themselves.
    if let Some(st) = state {
        let raw_state = ImmoState::from_raw(st.st_stat_fct);
        if raw_state.is_dead() {
            let mut detail = String::from(
                "In this state the ECU accepts neither a login nor a download, so there is no \
                 diagnostic recovery. Flashing ASW/CAL will not change it.",
            );
            if raw_state == ImmoState::HardwareSampleLock {
                detail.push_str(match ext.as_ref().map(|e| e.is_hardware_sample()) {
                    Some(true) => " Corroborated by DID 0x2FF byte 0 = 0x41 'A' (hardware sample).",
                    Some(false) => {
                        " Note: DID 0x2FF byte 0 reads 0x53 'S', which does not corroborate the \
                         hardware-sample lock."
                    }
                    None => {
                        " DID 0x2FF was not readable, so the hardware-sample marker could not \
                             be corroborated."
                    }
                });
            }
            findings.push(ImmoFinding::new(
                ImmoRule::DeadState,
                Severity::Warn,
                format!("The immobilizer is in a dead state: {}.", raw_state.label()),
                detail,
            ));
        }
        if st.st_stat_fct == 1 {
            findings.push(ImmoFinding::new(
                ImmoRule::NotAdapted,
                Severity::Warn,
                "The ECU has no immobilizer identity (stStatFct = 1, neutral / not adapted).",
                "Flashing ASW/CAL will not create an immobilizer identity. The ECU must be adapted \
                 to the vehicle before it will start.",
            ));
        }
    }

    // R5 — what a reported 2 really means.
    let resolved = match (state.as_ref(), bits.as_ref()) {
        (Some(st), Some(b)) => resolve_state(st, b, tuning),
        // Without 0x2EE a reported 2 is genuinely ambiguous — the ECU forces
        // 3, 4 and 'B' to report as 2, and only 0x2EE tells them apart. Do NOT
        // fall back to `from_raw`, which would resolve it to Adapted and make
        // the report claim "adapted and healthy" on the strength of a bit that
        // was never read. Other raw values are unambiguous and pass through.
        (Some(st), None) if st.st_stat_fct == 2 => None,
        (Some(st), None) => Some(ImmoState::from_raw(st.st_stat_fct)),
        _ => None,
    };
    if let Some(st) = state.as_ref() {
        if st.st_stat_fct == 2 {
            match resolved {
                Some(ImmoState::Adapted) => findings.push(ImmoFinding::new(
                    ImmoRule::HiddenState,
                    Severity::Ok,
                    "Immobilizer state 2 confirmed: adapted and healthy.",
                    "DID 0x2EE byte 1 bit 0x40 is set, so the reported state of 2 is the real one.",
                )),
                Some(ImmoState::HardwareSampleAdapted) => findings.push(ImmoFinding::new(
                    ImmoRule::HiddenState,
                    Severity::Warn,
                    "The reported state of 2 is really 3 — hardware-sample adapted.",
                    "DID 0x2EE byte 1 bit 0x80 is clear, which means stStatFct is actually 3. The \
                     ECU is a hardware sample; its immobilizer behaviour is not that of a \
                     production ECU.",
                )),
                Some(ImmoState::AdaptationMode) => findings.push(ImmoFinding::new(
                    ImmoRule::HiddenState,
                    Severity::Warn,
                    "The reported state of 2 is really 4 — adaptation mode.",
                    "The ECU is mid-adaptation rather than fully adapted. Complete the adaptation \
                     before relying on the immobilizer state.",
                )),
                Some(ImmoState::TuningCheckFailed) => findings.push(ImmoFinding::new(
                    ImmoRule::HiddenState,
                    Severity::Warn,
                    "The reported state of 2 is really 'B' (0x42) — the tuning check failed.",
                    "The ECU forces 'B' to report as 2. In 'B' the ECU can never produce a \
                     matching CrcMaster/CrcSlave, so it will not start. Recovery is the 0x04/0x80 \
                     login, which requires the noKeySecu key — that key only exists in a DFlash \
                     dump.",
                )),
                _ => findings.push(ImmoFinding::new(
                    ImmoRule::HiddenState,
                    Severity::Unknown,
                    "The reported immobilizer state of 2 could not be disambiguated.",
                    "The ECU forces states 3, 4 and 'B' (0x42) to report as 2. Telling them apart \
                     needs DID 0x2EE and DID 0x2FF, and at least one of them was unavailable.",
                )),
            }
        }
    }

    // R6 — current lock / release status. Ignition-off and no-master-reply are
    // Unknown rather than Warn: both are the normal reading on a bench harness
    // and say nothing about whether the ECU is bricked.
    if let Some(b) = bits.as_ref() {
        let (severity, message, detail) = match lock_status(b) {
            LockStatus::MasterVerified => (
                Severity::Ok,
                "The ECU has verified the cluster's CrcMaster and PIN.".to_string(),
                "Note this is not the same as 'the immobilizer is released': bMstCksVld plus \
                 bMstKeyVld equal full release only for authentication variant A. Variants B and C \
                 need a bit that DID 0x2EE does not publish."
                    .to_string(),
            ),
            LockStatus::IgnitionOff => (
                Severity::Unknown,
                "Ignition is off, so the immobilizer authentication state is unverified."
                    .to_string(),
                "The ECU does not authenticate on bench power. Turn the ignition on to read a \
                 meaningful lock state."
                    .to_string(),
            ),
            LockStatus::NoMasterReply => (
                Severity::Unknown,
                "No master reply — nothing is answering on CAN 0x011.".to_string(),
                "The cluster (immobilizer master) did not respond, so the ECU could not attempt \
                 authentication. This is expected on a bench harness with no cluster present."
                    .to_string(),
            ),
            LockStatus::CrcMasterRejected => (
                Severity::Warn,
                "The ECU rejected the cluster's CrcMaster.".to_string(),
                "CrcMaster is computed over noKeySecu, idxLab and idxTun; a rejection means one \
                 of those does not match the cluster. The ECU will not start in this state."
                    .to_string(),
            ),
            LockStatus::PinRejected => (
                Severity::Warn,
                "CrcMaster was accepted but the PIN mask was rejected (wrong noKeyMst)."
                    .to_string(),
                "The ECU and cluster agree on the security key but not on the PIN. The ECU will \
                 not start in this state."
                    .to_string(),
            ),
        };
        findings.push(ImmoFinding::new(
            ImmoRule::LockState,
            severity,
            message,
            detail,
        ));
    }

    // R7 — lockout timers.
    if let Some(lo) = lockout {
        if lo.download_lockout_minutes != 0 {
            findings.push(ImmoFinding::new(
                ImmoRule::Lockout,
                Severity::Warn,
                format!(
                    "A download lockout is counting down: {} minute(s) remaining.",
                    lo.download_lockout_minutes
                ),
                "The ECU will refuse an immobilizer download until the lockout expires, so the \
                 recovery path is unavailable for that long."
                    .to_string(),
            ));
        }
        if lo.login_lockout_minutes != 0 {
            findings.push(ImmoFinding::new(
                ImmoRule::Lockout,
                Severity::Warn,
                format!(
                    "A login lockout is counting down: {} minute(s) remaining.",
                    lo.login_lockout_minutes
                ),
                "The ECU will refuse an immobilizer login until the lockout expires, so the \
                 recovery path is unavailable for that long."
                    .to_string(),
            ));
        }
    }

    // R8 — last error code. Unknown, not Warn: there is no decode table, so we
    // can report the number but not what it means.
    if let Some(e) = ext.as_ref() {
        if e.last_error != 0 {
            findings.push(ImmoFinding::new(
                ImmoRule::LastError,
                Severity::Unknown,
                format!(
                    "The immobilizer recorded error code 0x{:02X} (DID 0x2FF byte 18).",
                    e.last_error
                ),
                "No decode table for these codes is available, so the raw value is all that can \
                 be reported."
                    .to_string(),
            ));
        }
    }

    // bInhAcsMem — a tooling limitation, deliberately never an immobilizer risk.
    if let Some(b) = bits.as_ref() {
        if b.b_inh_acs_mem {
            findings.push(ImmoFinding::new(
                ImmoRule::MemoryAccess,
                Severity::Ok,
                "Raw memory read (UDS 0x23) and CCP are disabled on this ECU.",
                "This is a tooling limitation, not an immobilizer risk. bInhAcsMem gates only UDS \
                 0x23 ReadMemoryByAddress and the CCP/ETK interface. It has no effect on engine \
                 start, on immobilizer authentication, or on the bootloader.",
            ));
        }
    }

    let severity = findings
        .iter()
        .fold(Severity::Ok, |acc, f| acc.worst(f.severity));

    ImmoReport {
        severity,
        reported_state: state.map(|s| s.st_stat_fct),
        state: resolved,
        findings,
    }
}

/// Shared explanation for both R2 failure modes.
fn tuning_detail(ext: &ExtendedDid) -> String {
    format!(
        "This is the only proven silent immobilizer lock. idxTun (0x{:02X}) is byte 4 of every \
         authentication plaintext block, so once the ECU forces stStatFct to 'B' (0x42) it can \
         never produce a matching CrcMaster/CrcSlave and the engine will not start. Allow-list \
         strVarTun = [{}]. Recovery requires the noKeySecu key, which only exists in a DFlash dump.",
        ext.idx_tun,
        hex(&ext.str_var_tun)
    )
}

// ── R12 — post-flash diff ─────────────────────────────────────────────────────

/// R12 — compare a snapshot taken before the flash with one taken after and
/// report anything that indicates the flash bricked the immobilizer.
///
/// Returns an empty vector when nothing changed. DIDs that are missing from
/// either side yield an [`Severity::Unknown`] finding rather than a risk.
pub fn diff_after_flash(before: &ImmoSnapshot, after: &ImmoSnapshot) -> Vec<ImmoFinding> {
    let mut findings = Vec::new();

    let ext_before = before.raw(DID_EXTENDED).and_then(decode_2ff);
    let ext_after = after.raw(DID_EXTENDED).and_then(decode_2ff);
    let state_before = before.raw(DID_STATE).and_then(decode_2ed);
    let state_after = after.raw(DID_STATE).and_then(decode_2ed);
    let bits_before = before.raw(DID_STATUS_BITS).and_then(decode_2ee);
    let bits_after = after.raw(DID_STATUS_BITS).and_then(decode_2ee);

    if ext_before.is_none()
        || ext_after.is_none()
        || state_before.is_none()
        || state_after.is_none()
    {
        findings.push(ImmoFinding::new(
            ImmoRule::Unavailable,
            Severity::Unknown,
            "The post-flash immobilizer comparison is incomplete — one or both snapshots are \
             missing DID 0x2ED or DID 0x2FF.",
            "Whatever could be compared is reported; the rest is unverified. This is not evidence \
             of a problem.",
        ));
    }

    if let (Some(b), Some(a)) = (ext_before, ext_after) {
        if b.str_var_tun != a.str_var_tun {
            findings.push(ImmoFinding::new(
                ImmoRule::PostFlashChange,
                Severity::Warn,
                format!(
                    "The power-class allow-list changed across the flash: [{}] -> [{}].",
                    hex(&b.str_var_tun),
                    hex(&a.str_var_tun)
                ),
                "strVarTun is the allow-list the tuning interlock tests idxTun against. It can \
                 only be rewritten through DID 0x2E2, which requires the noKeySecu key — and that \
                 key only exists in a DFlash dump."
                    .to_string(),
            ));
        }
        // Only report this as caused by the flash if the membership actually
        // held beforehand. An ECU that already failed the interlock before we
        // touched it must not have a pre-existing condition attributed to us —
        // `assess` reports that case as R2 on the "before" snapshot.
        if b.str_var_tun.contains(&b.idx_tun) && !a.str_var_tun.contains(&a.idx_tun) {
            findings.push(ImmoFinding::new(
                ImmoRule::PostFlashChange,
                Severity::Warn,
                format!(
                    "After the flash, idxTun 0x{:02X} is no longer in the allow-list [{}].",
                    a.idx_tun,
                    hex(&a.str_var_tun)
                ),
                "This is the tuning interlock tripping. The only recovery is rewriting idxTun via \
                 DID 0x2E2, which requires the noKeySecu key — and that key only exists in a \
                 DFlash dump."
                    .to_string(),
            ));
        }
        if b.marker == 0x53 && a.marker == 0x41 {
            findings.push(ImmoFinding::new(
                ImmoRule::PostFlashChange,
                Severity::Warn,
                "DID 0x2FF byte 0 flipped from 0x53 'S' to 0x41 'A' — the ECU now reports itself \
                 as a hardware sample.",
                "No diagnostic recovery for this transition is known.".to_string(),
            ));
        }
    }

    if let (Some(b), Some(a)) = (state_before, state_after) {
        let after_state = ImmoState::from_raw(a.st_stat_fct);
        if !ImmoState::from_raw(b.st_stat_fct).is_dead() && after_state.is_dead() {
            findings.push(ImmoFinding::new(
                ImmoRule::PostFlashChange,
                Severity::Warn,
                format!(
                    "The immobilizer state moved into a dead state across the flash: 0x{:02X} -> \
                     {}.",
                    b.st_stat_fct,
                    after_state.label()
                ),
                "There is no diagnostic recovery from stStatFct 10, 0x58 or 0x63 — the ECU \
                 accepts neither a login nor a download."
                    .to_string(),
            ));
        }

        // A reported 2 that has lost bit 0x40 means the ECU is really in 3, 4 or
        // 'B' now; 'B' is the outcome that matters.
        if let (Some(bb), Some(ba)) = (bits_before, bits_after) {
            if a.st_stat_fct == 2 && bb.st_is_2 && !ba.st_is_2 {
                findings.push(ImmoFinding::new(
                    ImmoRule::PostFlashChange,
                    Severity::Warn,
                    "The ECU still reports stStatFct 2 but has lost DID 0x2EE bit 0x40, so it is \
                     no longer really in state 2.",
                    "The ECU forces states 3, 4 and 'B' (0x42) to report as 2. If it has moved to \
                     'B', recovery is the 0x04/0x80 login, which requires the noKeySecu key — and \
                     that key only exists in a DFlash dump."
                        .to_string(),
                ));
            }
        }
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mqb_modules::modules::{dq250mqb::DQ250_FLASH_INFO, simos18::S18_FLASH_INFO};

    fn support() -> ImmoSupport {
        ImmoSupport::for_module(&S18_FLASH_INFO).expect("Simos18 is supported")
    }

    fn snapshot(entries: &[(u16, Vec<u8>)]) -> ImmoSnapshot {
        let map: HashMap<u16, Vec<u8>> = entries.iter().cloned().collect();
        ImmoSnapshot::from_dids(support(), map)
    }

    /// DID 0x2ED with the given stStatFct.
    fn p2ed(st: u8) -> Vec<u8> {
        let mut v = vec![0u8; 10];
        v[0] = st;
        v[1] = 0x11; // ctDatBasFazit
        v[2] = 0x22; // idxLab
        v
    }

    /// DID 0x2EE with the given bytes 0 and 1; the rest are padding.
    fn p2ee(b0: u8, b1: u8) -> Vec<u8> {
        let mut v = vec![0u8; 10];
        v[0] = b0;
        v[1] = b1;
        v
    }

    /// DID 0x2FF with the given idxTun and allow-list.
    fn p2ff(marker: u8, idx_tun: u8, allow: [u8; 5], last_error: u8) -> Vec<u8> {
        let mut v = vec![0u8; 19];
        v[0] = marker;
        v[7] = 0x05; // ctAuthLos
        v[8] = 0x05; // ctWrAccNvm
        v[9] = idx_tun;
        v[10..15].copy_from_slice(&allow);
        v[15..18].copy_from_slice(&[0x08, 0x02, 0x00]);
        v[18] = last_error;
        v
    }

    /// A reported state of 2 is ambiguous by design — the ECU forces 3, 4 and
    /// 'B' to report as 2, and only DID 0x2EE tells them apart. Without 0x2EE
    /// the report must not claim the ECU is adapted and healthy.
    #[test]
    fn state_2_without_0x2ee_is_not_reported_as_healthy() {
        let snap = snapshot(&[
            (0x2ED, p2ed(2)),
            // 0x2EE deliberately absent.
            (0x2FF, p2ff(0x53, 0x6A, [0x6A, 0, 0, 0, 0], 0)),
        ]);
        let report = assess(&snap);

        assert_ne!(
            report.state,
            Some(ImmoState::Adapted),
            "state must not resolve to Adapted without the DID that proves it"
        );

        let hidden: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule == ImmoRule::HiddenState)
            .collect();
        assert_eq!(hidden.len(), 1);
        assert_eq!(hidden[0].severity, Severity::Unknown);
        for f in &report.findings {
            assert!(
                !f.message.contains("adapted and healthy"),
                "must not claim health on the strength of an unread DID: {}",
                f.message
            );
        }
    }

    /// An ECU that already failed the tuning interlock before we touched it
    /// must not have that pre-existing condition attributed to the flash.
    #[test]
    fn pre_existing_tuning_violation_is_not_blamed_on_the_flash() {
        let bad = p2ff(0x53, 0x88, [0x42, 0x43, 0x00, 0x45, 0x44], 0);
        let before = snapshot(&[
            (0x2ED, p2ed(2)),
            (0x2EE, p2ee(0x04, 0xFC)),
            (0x2FF, bad.clone()),
        ]);
        let after = snapshot(&[(0x2ED, p2ed(2)), (0x2EE, p2ee(0x04, 0xFC)), (0x2FF, bad)]);

        let findings = diff_after_flash(&before, &after);
        assert!(
            findings
                .iter()
                .all(|f| !f.message.contains("no longer in the allow-list")),
            "unchanged snapshots must produce no post-flash membership finding: {findings:#?}"
        );

        // But a membership that really was lost across the flash still reports.
        let good = p2ff(0x53, 0x6A, [0x6A, 0, 0, 0, 0], 0);
        let lost = p2ff(0x53, 0x6A, [0x42, 0x43, 0x00, 0x45, 0x44], 0);
        let before_ok = snapshot(&[(0x2ED, p2ed(2)), (0x2EE, p2ee(0x04, 0xFC)), (0x2FF, good)]);
        let after_bad = snapshot(&[(0x2ED, p2ed(2)), (0x2EE, p2ee(0x04, 0xFC)), (0x2FF, lost)]);
        let findings = diff_after_flash(&before_ok, &after_bad);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("no longer in the allow-list")),
            "a genuinely lost membership must still be reported: {findings:#?}"
        );
    }

    /// The healthy reference ECU: adapted, released, idxTun 0x6A allowed.
    fn healthy() -> ImmoSnapshot {
        snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xFC)),
            (DID_LOCKOUT, vec![0u8; 6]),
            (
                DID_EXTENDED,
                p2ff(0x53, 0x6A, [0x6A, 0x00, 0x00, 0x00, 0x00], 0x00),
            ),
        ])
    }

    #[test]
    fn only_simos18_is_supported() {
        assert!(ImmoSupport::for_module(&S18_FLASH_INFO).is_some());
        assert!(ImmoSupport::for_module(&DQ250_FLASH_INFO).is_none());
    }

    #[test]
    fn healthy_reference_ecu_has_no_risk() {
        let report = assess(&healthy());
        assert_eq!(
            report.severity,
            Severity::Ok,
            "findings: {:?}",
            report.findings
        );
        assert!(!report.has_risk());
        assert_eq!(report.state, Some(ImmoState::Adapted));
        assert_eq!(report.reported_state, Some(2));
    }

    #[test]
    fn healthy_reference_bits_decode() {
        // 0x04 / 0xFC is the documented fully-healthy released reading.
        let bits = decode_2ee(&p2ee(0x04, 0xFC)).unwrap();
        assert!(bits.ignition_on);
        assert!(bits.st_not_3);
        assert!(bits.st_is_2);
        assert!(bits.b_mst_resp_rx);
        assert!(bits.b_mst_cks_vld);
        assert!(bits.b_mst_key_vld);
        // Bit 0x04 is set in 0xFC, and it is inverted: NOT inhibited.
        assert!(!bits.b_inh_acs_mem);
        assert_eq!(lock_status(&bits), LockStatus::MasterVerified);
    }

    #[test]
    fn idx_tun_outside_allow_list_is_a_tuning_risk() {
        let snap = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xFC)),
            (
                DID_EXTENDED,
                p2ff(0x53, 0x88, [0x42, 0x43, 0x00, 0x45, 0x44], 0x00),
            ),
        ]);
        let ext = decode_2ff(snap.raw(DID_EXTENDED).unwrap()).unwrap();
        assert_eq!(tuning_status(&ext), TuningStatus::NotAllowed);

        let report = assess(&snap);
        assert_eq!(report.severity, Severity::Warn);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == ImmoRule::TuningInterlock)
            .expect("R2 finding");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.message.contains("0x88"));
        assert!(f.detail.contains("noKeySecu"));
    }

    #[test]
    fn all_zero_allow_list_is_a_tuning_risk() {
        let snap = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xFC)),
            (DID_EXTENDED, p2ff(0x53, 0x00, [0; 5], 0x00)),
        ]);
        let ext = decode_2ff(snap.raw(DID_EXTENDED).unwrap()).unwrap();
        assert_eq!(tuning_status(&ext), TuningStatus::AllowListEmpty);

        let report = assess(&snap);
        assert!(report.has_risk());
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule == ImmoRule::TuningInterlock && f.severity == Severity::Warn));
    }

    #[test]
    fn dead_states_zeroing_idx_tun_do_not_report_a_tuning_violation() {
        // R2's exception: in state 0x58 the ECU has already zeroed idxTun, so
        // the all-zero reading is expected and R3 is the right finding.
        let snap = snapshot(&[
            (DID_STATE, p2ed(0x58)),
            (DID_STATUS_BITS, p2ee(0x04, 0x3C)),
            (DID_EXTENDED, p2ff(0x41, 0x00, [0; 5], 0x00)),
        ]);
        let report = assess(&snap);
        assert!(report.has_risk());
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == ImmoRule::TuningInterlock),
            "R2 must be suppressed in the idxTun-zeroing states"
        );
        let dead = report
            .findings
            .iter()
            .find(|f| f.rule == ImmoRule::DeadState)
            .expect("R3 finding");
        assert_eq!(dead.severity, Severity::Warn);
        assert!(dead.message.contains("0x58"));
        // 0x2FF byte 0 = 0x41 'A' corroborates the hardware-sample lock.
        assert!(dead.detail.contains("0x41"));
        assert_eq!(report.state, Some(ImmoState::HardwareSampleLock));
    }

    #[test]
    fn not_adapted_state_is_reported() {
        let snap = snapshot(&[
            (DID_STATE, p2ed(1)),
            (DID_STATUS_BITS, p2ee(0x04, 0xBC)),
            (DID_EXTENDED, p2ff(0x53, 0x00, [0; 5], 0x00)),
        ]);
        let report = assess(&snap);
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule == ImmoRule::NotAdapted && f.severity == Severity::Warn));
        assert!(!report
            .findings
            .iter()
            .any(|f| f.rule == ImmoRule::TuningInterlock));
    }

    #[test]
    fn missing_extended_did_is_unknown_not_risk() {
        let snap = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xFC)),
            (DID_LOCKOUT, vec![0u8; 6]),
        ]);
        let report = assess(&snap);
        assert_eq!(report.severity, Severity::Unknown);
        assert!(
            !report.has_risk(),
            "fail-open: missing DIDs are never a risk"
        );
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == ImmoRule::Unavailable)
            .expect("unavailable finding");
        assert_eq!(f.severity, Severity::Unknown);
        assert!(f.message.contains("0x02FF"));
    }

    #[test]
    fn no_dids_at_all_is_unknown_not_risk() {
        let report = assess(&snapshot(&[]));
        assert_eq!(report.severity, Severity::Unknown);
        assert!(!report.has_risk());
        assert_eq!(report.state, None);
    }

    #[test]
    fn hidden_state_resolution() {
        let st = decode_2ed(&p2ed(2)).unwrap();

        // 0x40 set -> really 2.
        let bits = decode_2ee(&p2ee(0x04, 0xFC)).unwrap();
        assert_eq!(
            resolve_state(&st, &bits, Some(TuningStatus::Ok)),
            Some(ImmoState::Adapted)
        );

        // 0x80 clear (and 0x40 clear, since the 0x40 test comes first) -> really 3.
        let bits = decode_2ee(&p2ee(0x04, 0x3C)).unwrap();
        assert_eq!(
            resolve_state(&st, &bits, Some(TuningStatus::Ok)),
            Some(ImmoState::HardwareSampleAdapted)
        );

        // 0x80 set, 0x40 clear, membership fails -> really 'B'.
        let bits = decode_2ee(&p2ee(0x04, 0xBC)).unwrap();
        assert_eq!(
            resolve_state(&st, &bits, Some(TuningStatus::NotAllowed)),
            Some(ImmoState::TuningCheckFailed)
        );

        // 0x80 set, 0x40 clear, membership OK -> really 4.
        assert_eq!(
            resolve_state(&st, &bits, Some(TuningStatus::Ok)),
            Some(ImmoState::AdaptationMode)
        );

        // Without DID 0x2FF the last two cases cannot be told apart.
        assert_eq!(resolve_state(&st, &bits, None), None);
    }

    #[test]
    fn hidden_tuning_lock_is_reported_as_b() {
        let snap = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xBC)),
            (
                DID_EXTENDED,
                p2ff(0x53, 0x88, [0x42, 0x43, 0x00, 0x45, 0x44], 0x00),
            ),
        ]);
        let report = assess(&snap);
        assert_eq!(report.state, Some(ImmoState::TuningCheckFailed));
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == ImmoRule::HiddenState)
            .expect("R5 finding");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.detail.contains("0x04/0x80"));
    }

    #[test]
    fn lock_ladder_order() {
        // Ignition off, but both validity bits set -> still "master verified":
        // the released test comes first.
        let bits = decode_2ee(&p2ee(0x00, 0x18)).unwrap();
        assert_eq!(lock_status(&bits), LockStatus::MasterVerified);
        // Ignition off with nothing else set.
        let bits = decode_2ee(&p2ee(0x00, 0xE0)).unwrap();
        assert_eq!(lock_status(&bits), LockStatus::IgnitionOff);
        // Ignition on, no master reply.
        let bits = decode_2ee(&p2ee(0x04, 0xC0)).unwrap();
        assert_eq!(lock_status(&bits), LockStatus::NoMasterReply);
        // Master replied, CrcMaster rejected.
        let bits = decode_2ee(&p2ee(0x04, 0xE0)).unwrap();
        assert_eq!(lock_status(&bits), LockStatus::CrcMasterRejected);
        // CrcMaster accepted, PIN rejected.
        let bits = decode_2ee(&p2ee(0x04, 0xF0)).unwrap();
        assert_eq!(lock_status(&bits), LockStatus::PinRejected);
    }

    #[test]
    fn released_wording_avoids_claiming_the_immobilizer_is_released() {
        let report = assess(&healthy());
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == ImmoRule::LockState)
            .expect("R6 finding");
        assert_eq!(f.severity, Severity::Ok);
        assert!(f
            .message
            .contains("verified the cluster's CrcMaster and PIN"));
        assert!(!f.message.to_lowercase().contains("immobilizer is released"));
    }

    #[test]
    fn inhibited_memory_access_is_informational_only() {
        // Byte 1 bit 0x04 clear -> bInhAcsMem true (inverted bit).
        let snap = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xF8)),
            (
                DID_EXTENDED,
                p2ff(0x53, 0x6A, [0x6A, 0x00, 0x00, 0x00, 0x00], 0x00),
            ),
        ]);
        let report = assess(&snap);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == ImmoRule::MemoryAccess)
            .expect("bInhAcsMem finding");
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.message.contains("UDS 0x23"));
        assert!(!report.has_risk());
    }

    #[test]
    fn lockout_timers_are_reported() {
        let mut lockout = vec![0u8; 6];
        lockout[0] = 12;
        lockout[1] = 3;
        let snap = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xFC)),
            (DID_LOCKOUT, lockout),
            (
                DID_EXTENDED,
                p2ff(0x53, 0x6A, [0x6A, 0x00, 0x00, 0x00, 0x00], 0x00),
            ),
        ]);
        let report = assess(&snap);
        let msgs: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule == ImmoRule::Lockout)
            .collect();
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0].message.contains("12 minute"));
        assert!(msgs[1].message.contains("3 minute"));
    }

    #[test]
    fn last_error_is_unknown_severity_with_the_raw_code() {
        let snap = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xFC)),
            (
                DID_EXTENDED,
                p2ff(0x53, 0x6A, [0x6A, 0x00, 0x00, 0x00, 0x00], 0x37),
            ),
        ]);
        let report = assess(&snap);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule == ImmoRule::LastError)
            .expect("R8 finding");
        assert_eq!(f.severity, Severity::Unknown);
        assert!(f.message.contains("0x37"));
    }

    #[test]
    fn extended_did_field_decode() {
        let ext = decode_2ff(&p2ff(0x53, 0x6A, [0x6A, 0, 0, 0, 0], 0)).unwrap();
        assert_eq!(ext.marker, 0x53);
        assert!(!ext.is_hardware_sample());
        assert_eq!(ext.idx_tun, 0x6A);
        assert_eq!(ext.str_var_tun, [0x6A, 0, 0, 0, 0]);
        assert_eq!(ext.version_string(), "8.2.0");
        assert_eq!(ext.last_error, 0);
        assert!(decode_2ff(&[0u8; 18]).is_none());
    }

    #[test]
    fn quantized_counters() {
        assert_eq!(unquantize(0), Some(0));
        assert_eq!(unquantize(99), Some(99));
        assert_eq!(unquantize(100), Some(0));
        assert_eq!(unquantize(101), Some(100));
        assert_eq!(unquantize(199), Some(9900));
        assert_eq!(unquantize(200), Some(0));
        assert_eq!(unquantize(201), Some(1000));
        assert_eq!(unquantize(254), Some(54000));
        assert_eq!(unquantize(255), None);
    }

    #[test]
    fn state_did_decode() {
        let mut p = p2ed(2);
        p[8] = 0x08;
        let st = decode_2ed(&p).unwrap();
        assert_eq!(st.st_stat_fct, 2);
        assert_eq!(st.ct_dat_bas_fazit, 0x11);
        assert_eq!(st.idx_lab, 0x22);
        assert!(st.b_lim_mod_ena);
        assert!(decode_2ed(&[0u8; 9]).is_none());
    }

    #[test]
    fn diff_flags_a_changed_allow_list() {
        let before = healthy();
        let after = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xFC)),
            (DID_LOCKOUT, vec![0u8; 6]),
            (
                DID_EXTENDED,
                p2ff(0x53, 0x6A, [0x42, 0x43, 0x00, 0x45, 0x44], 0x00),
            ),
        ]);
        let findings = diff_after_flash(&before, &after);
        assert!(findings.iter().any(|f| f.rule == ImmoRule::PostFlashChange
            && f.severity == Severity::Warn
            && f.message.contains("allow-list changed")));
        // idxTun 0x6A is no longer a member of the new list either.
        assert!(findings
            .iter()
            .any(|f| f.message.contains("no longer in the allow-list")));
        assert!(findings.iter().any(|f| f.detail.contains("0x2E2")));
    }

    #[test]
    fn diff_flags_a_move_into_a_dead_state() {
        let before = healthy();
        let after = snapshot(&[
            (DID_STATE, p2ed(0x63)),
            (DID_STATUS_BITS, p2ee(0x04, 0x3C)),
            (
                DID_EXTENDED,
                p2ff(0x53, 0x6A, [0x6A, 0x00, 0x00, 0x00, 0x00], 0x00),
            ),
        ]);
        let findings = diff_after_flash(&before, &after);
        let f = findings
            .iter()
            .find(|f| f.message.contains("dead state"))
            .expect("dead-state diff finding");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.detail.contains("no diagnostic recovery"));
    }

    #[test]
    fn diff_flags_a_sample_marker_flip_and_lost_state_bit() {
        let before = healthy();
        let after = snapshot(&[
            (DID_STATE, p2ed(2)),
            (DID_STATUS_BITS, p2ee(0x04, 0xBC)),
            (
                DID_EXTENDED,
                p2ff(0x41, 0x6A, [0x6A, 0x00, 0x00, 0x00, 0x00], 0x00),
            ),
        ]);
        let findings = diff_after_flash(&before, &after);
        assert!(findings
            .iter()
            .any(|f| f.message.contains("0x53 'S' to 0x41 'A'")));
        let lost = findings
            .iter()
            .find(|f| f.message.contains("lost DID 0x2EE bit 0x40"))
            .expect("lost-0x40 finding");
        assert!(lost.detail.contains("0x04/0x80"));
    }

    #[test]
    fn diff_of_identical_snapshots_is_clean() {
        assert!(diff_after_flash(&healthy(), &healthy()).is_empty());
    }

    #[test]
    fn diff_with_missing_dids_is_unknown_not_risk() {
        let findings = diff_after_flash(&healthy(), &snapshot(&[]));
        assert!(findings.iter().all(|f| f.severity == Severity::Unknown));
        assert!(findings.iter().any(|f| f.rule == ImmoRule::Unavailable));
    }
}
