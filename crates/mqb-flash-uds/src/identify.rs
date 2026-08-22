//! Control-module identification — work out *which* ECU is on the bus.
//!
//! Making the user pick the module from a dropdown before anything has been
//! read is a safety problem: picking `dq381` when a DQ250 is attached puts the
//! wrong crypto, block layout and erase policy on the wire.
//!
//! * The four supported modules occupy only three CAN channels
//!   ([`IDENT_CHANNELS`]), so the channel alone already narrows the answer.
//! * Where a channel hosts more than one module, a handful of identification
//!   DIDs ([`IDENT_DIDS`]) rank the candidates.
//! * The Simos variants sharing `0x7E0` name themselves: the Boot Loader
//!   Identification record ([`DID_BOOT_LOADER_IDENTIFICATION`]) starts with the
//!   `FlashInfo::project_name` the rest of the tool keys off, resolving the
//!   channel outright.
//! * When the data cannot separate two modules we return both as
//!   [`Confidence::Ambiguous`] and let the wizard ask. We never invent a
//!   discriminator and never fall back to a default guess.
//!
//! The bus-touching half ([`identify_on_channel`]) wraps the pure half
//! ([`candidates_from_dids`]) so the ranking rules are unit-testable.
//!
//! Transport construction lives in [`crate::flash`]; the wizard opens each
//! channel with [`crate::flash::make_isotp_config`] and
//! [`IdentChannel::probe_flash_info`].

use std::cmp::Reverse;
use std::collections::HashMap;

use automotive::TransportLayer;
use mqb_modules::{get_flash_info, module_names, FlashInfo};

use crate::flash::{open_extended_session, read_dids};

// ── DIDs read during identification ──────────────────────────────────────────

/// ASAM/ODX File Identifier — e.g. `"EV_ECM20TFS0208V0906259K\0"`.
///
/// Names the ECU family and embeds the spare part number of the software the
/// ECU was flashed with.
pub const DID_ODX_FILE_IDENTIFIER: u16 = 0xF19E;

/// ASAM/ODX File Version — e.g. `"001005"`.
///
/// ODIS keys off identifier + version as a pair, so carrying it lets the ECU be
/// looked up later.
pub const DID_ODX_FILE_VERSION: u16 = 0xF1A2;

/// VW Spare Part Number — 11 characters including a trailing pad space,
/// e.g. `"8V0906264M "`.
pub const DID_SPARE_PART_NUMBER: u16 = 0xF187;

/// VW System Name Or Engine Type — e.g. `"2.0l R4 TFSI "`.
pub const DID_SYSTEM_NAME: u16 = 0xF197;

/// Boot Loader Identification — e.g. `"SC8.1 CB.00.00.I0 C02.00 SC8 "`.
///
/// The best discriminator on the engine channel: the string opens with the
/// project prefix of the running bootloader, and the three Simos variants that
/// share `0x7E0` use three different ones (`SC8`, `SCB`, `SCG`) — the same
/// strings as `FlashInfo::project_name`. Unlike the spare part number, which VW
/// reuses across ECU generations, this comes from the ECU's own bootloader.
///
/// Answered in the ordinary extended session, and answered from CBOOT too
/// (`full_flash_log/filtered.txt`: `62 f1 a3 58 31 33`, `"X13"`, while `0xF197`
/// and `0xF1AD` are being rejected with NRC `0x31`), so an ECU sitting in the
/// bootloader after an interrupted flash still identifies itself here.
pub const DID_BOOT_LOADER_IDENTIFICATION: u16 = 0xF1F4;

/// The DIDs [`identify_on_channel`] reads, in request order.
///
/// Five records rather than the 38-record [`mqb_modules::DATA_RECORDS`] sweep:
/// this runs once per candidate channel, and a full sweep per channel would
/// cost over a hundred requests before the user has chosen a file.
pub const IDENT_DIDS: &[u16] = &[
    DID_ODX_FILE_IDENTIFIER,
    DID_ODX_FILE_VERSION,
    DID_SPARE_PART_NUMBER,
    DID_SYSTEM_NAME,
    DID_BOOT_LOADER_IDENTIFICATION,
];

// ── Informational records ────────────────────────────────────────────────────

/// One record shown to the user on the identification page.
///
/// These play no part in ranking candidates — they exist so the wizard can show
/// what the module says about itself before anything is written to it.
#[derive(Debug, Clone, Copy)]
pub struct InfoField {
    /// The Data Identifier to read.
    pub did: u16,
    /// How the field is named to the user.
    pub label: &'static str,
    /// `true` when the record is an ASCII string; `false` renders as hex bytes.
    ///
    /// Mirrors `DataRecord::parse_type` in `mqb_modules`, kept here as a bool so
    /// the display order and the labels live in one table.
    pub text: bool,
}

/// The records the identification page displays, in display order.
///
/// A curated subset of [`mqb_modules::DATA_RECORDS`]: every entry is something a
/// user inspecting their control module would recognise. Live values (vehicle
/// speed, active session) and the undocumented records are left out — the point
/// is identity, not a data-logger view.
///
/// Every one of these costs a request on a channel that already answered, so
/// keep the table short enough that identification still feels immediate.
pub const INFO_FIELDS: &[InfoField] = &[
    InfoField {
        did: 0xF190,
        label: "VIN",
        text: true,
    },
    InfoField {
        did: DID_SPARE_PART_NUMBER,
        label: "VW spare part number",
        text: true,
    },
    InfoField {
        did: 0xF189,
        label: "Application software version",
        text: true,
    },
    InfoField {
        did: 0xF191,
        label: "ECU hardware number",
        text: true,
    },
    InfoField {
        did: 0xF1A3,
        label: "ECU hardware version",
        text: true,
    },
    InfoField {
        did: DID_SYSTEM_NAME,
        label: "System name / engine type",
        text: true,
    },
    InfoField {
        did: 0xF1AD,
        label: "Engine code letters",
        text: true,
    },
    InfoField {
        did: DID_BOOT_LOADER_IDENTIFICATION,
        label: "Boot loader identification",
        text: true,
    },
    InfoField {
        did: DID_ODX_FILE_IDENTIFIER,
        label: "ASAM/ODX file identifier",
        text: true,
    },
    InfoField {
        did: DID_ODX_FILE_VERSION,
        label: "ASAM/ODX file version",
        text: true,
    },
    InfoField {
        did: 0xF804,
        label: "Calibration ID",
        text: true,
    },
    InfoField {
        did: 0xF1AB,
        label: "Logical software block version",
        text: true,
    },
    InfoField {
        did: 0xF18C,
        label: "ECU serial number",
        text: true,
    },
    InfoField {
        did: 0xF17C,
        label: "VW FAZIT identification string",
        text: true,
    },
    InfoField {
        did: 0xF17E,
        label: "ECU production change number",
        text: true,
    },
    InfoField {
        did: 0xF1AA,
        label: "VW workshop system name",
        text: true,
    },
    InfoField {
        did: 0x0600,
        label: "Coding value",
        text: false,
    },
    InfoField {
        did: 0xF442,
        label: "Control module voltage",
        text: false,
    },
    InfoField {
        did: 0x295B,
        label: "Control module mileage",
        text: false,
    },
    InfoField {
        did: 0x0407,
        label: "Programming attempts",
        text: false,
    },
    InfoField {
        did: 0x0408,
        label: "Successful programming attempts",
        text: false,
    },
    InfoField {
        did: 0xF1F1,
        label: "Tuning protection SO2",
        text: false,
    },
];

/// The [`INFO_FIELDS`] DIDs that [`IDENT_DIDS`] does not already read.
///
/// Identification reads its five records first and ranks the channel on those;
/// this is the extra sweep, so nothing is requested twice.
pub fn extra_info_dids() -> Vec<u16> {
    INFO_FIELDS
        .iter()
        .map(|f| f.did)
        .filter(|did| !IDENT_DIDS.contains(did))
        .collect()
}

/// Render [`INFO_FIELDS`] against a raw DID map, skipping absent or empty
/// records.
///
/// A refused DID is normal — modules differ in what they answer — so it is left
/// out rather than shown as a blank row.
pub fn info_values(dids: &HashMap<u16, Vec<u8>>) -> Vec<(&'static str, String)> {
    INFO_FIELDS
        .iter()
        .filter_map(|field| {
            let bytes = dids.get(&field.did)?;
            let value = if field.text {
                decode(Some(bytes))?
            } else if bytes.is_empty() {
                return None;
            } else {
                bytes
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            Some((field.label, value))
        })
        .collect()
}

// ── Channels ─────────────────────────────────────────────────────────────────

/// What kind of controller a channel hosts, which selects the ranking rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// `0x7E0`/`0x7E8` — the engine ECU. Shared by every Simos 18 variant.
    SimosEngine,
    /// `0x7E1`/`0x7E9` — the transmission controller. Shared by DQ250 and DQ381.
    Transmission,
    /// `0x70F`/`0x779` — the Haldex AWD coupler.
    HaldexAwd,
}

/// One CAN channel to probe, and the supported modules that live on it.
#[derive(Debug, Clone, Copy)]
pub struct IdentChannel {
    /// Human-readable channel name for progress reporting.
    pub label: &'static str,
    /// Tester → ECU CAN identifier.
    pub txid: u32,
    /// ECU → tester CAN identifier.
    pub rxid: u32,
    /// Which ranking rules apply to this channel.
    pub kind: ChannelKind,
    /// Registry names of every supported module reachable here. More than one
    /// entry means the channel cannot be resolved by address alone.
    pub modules: &'static [&'static str],
}

impl IdentChannel {
    /// The [`FlashInfo`] to build the probe transport from. Any module on the
    /// channel would do — only the CAN identifiers matter for a read-only probe.
    ///
    /// # Panics
    /// If the channel names a module the registry does not know. A unit test
    /// covers that build-time inconsistency.
    pub fn probe_flash_info(&self) -> &'static FlashInfo {
        get_flash_info(self.modules[0])
            .unwrap_or_else(|| panic!("unknown module `{}` in IDENT_CHANNELS", self.modules[0]))
    }
}

/// Every channel the wizard should scan, in scan order.
///
/// The wizard opens a transport for [`IdentChannel::probe_flash_info`] itself
/// and then calls [`identify_on_channel`]. Engine first: the most commonly
/// flashed module, so the common case answers on the first probe.
pub const IDENT_CHANNELS: &[IdentChannel] = &[
    IdentChannel {
        label: "Engine (0x7E0)",
        txid: 0x7E0,
        rxid: 0x7E8,
        kind: ChannelKind::SimosEngine,
        modules: &["simos18", "simos1810", "simos184"],
    },
    IdentChannel {
        label: "Transmission (0x7E1)",
        txid: 0x7E1,
        rxid: 0x7E9,
        kind: ChannelKind::Transmission,
        modules: &["dq250", "dq381"],
    },
    IdentChannel {
        label: "Haldex AWD (0x70F)",
        txid: 0x70F,
        rxid: 0x779,
        kind: ChannelKind::HaldexAwd,
        modules: &["haldex"],
    },
];

/// Find the identification channel a [`FlashInfo`] belongs to, by CAN address.
pub fn channel_for(flash_info: &FlashInfo) -> Option<&'static IdentChannel> {
    let cmi = &flash_info.control_module_identifier;
    IDENT_CHANNELS
        .iter()
        .find(|c| c.txid == cmi.txid && c.rxid == cmi.rxid)
}

// ── Evidence ─────────────────────────────────────────────────────────────────

/// The identification strings read from the ECU.
///
/// Decoded lossily as UTF-8 and stripped of VW's NUL/space padding; a refused
/// DID, or one that was all padding, is [`None`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentStrings {
    /// [`DID_ODX_FILE_IDENTIFIER`], e.g. `"EV_ECM20TFS0208V0906259K"`.
    pub odx_file_identifier: Option<String>,
    /// [`DID_ODX_FILE_VERSION`], e.g. `"001005"`.
    pub odx_file_version: Option<String>,
    /// [`DID_SPARE_PART_NUMBER`], e.g. `"8V0906259K"`.
    pub spare_part_number: Option<String>,
    /// [`DID_SYSTEM_NAME`], e.g. `"2.0l R4 TFSI"`.
    pub system_name: Option<String>,
    /// [`DID_BOOT_LOADER_IDENTIFICATION`], e.g. `"SC8.1 CB.00.00.I0 C02.00 SC8"`.
    pub boot_loader_identification: Option<String>,
}

impl IdentStrings {
    /// Decode the identification DIDs out of a raw DID map.
    pub fn from_dids(dids: &HashMap<u16, Vec<u8>>) -> Self {
        Self {
            odx_file_identifier: decode(dids.get(&DID_ODX_FILE_IDENTIFIER)),
            odx_file_version: decode(dids.get(&DID_ODX_FILE_VERSION)),
            spare_part_number: decode(dids.get(&DID_SPARE_PART_NUMBER)),
            system_name: decode(dids.get(&DID_SYSTEM_NAME)),
            boot_loader_identification: decode(dids.get(&DID_BOOT_LOADER_IDENTIFICATION)),
        }
    }

    /// The project prefix the bootloader reports for itself, e.g. `"SC8"`, or
    /// [`None`] when the record was absent or not project-shaped.
    pub fn boot_loader_project(&self) -> Option<&str> {
        self.boot_loader_identification
            .as_deref()
            .and_then(project_from_boot_loader_identification)
    }

    /// The best available spare part number: the dedicated record, else the one
    /// embedded in the ODX file identifier.
    pub fn effective_spare_part_number(&self) -> Option<String> {
        if let Some(pn) = &self.spare_part_number {
            return Some(pn.to_ascii_uppercase());
        }
        self.odx_file_identifier
            .as_deref()
            .and_then(spare_part_from_odx_identifier)
    }

    /// A one-line summary for the reason text and for logs.
    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(v) = &self.odx_file_identifier {
            parts.push(format!("ODX ident {v}"));
        }
        if let Some(v) = &self.odx_file_version {
            parts.push(format!("version {v}"));
        }
        if let Some(v) = &self.spare_part_number {
            parts.push(format!("part number {v}"));
        }
        if let Some(v) = &self.system_name {
            parts.push(format!("system \"{v}\""));
        }
        if let Some(v) = &self.boot_loader_identification {
            parts.push(format!("bootloader \"{v}\""));
        }
        if parts.is_empty() {
            "no identification strings".to_owned()
        } else {
            parts.join(", ")
        }
    }
}

/// Decode one raw DID value, treating pure padding as absent.
fn decode(bytes: Option<&Vec<u8>>) -> Option<String> {
    let bytes = bytes?;
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Pull the 10-character spare part number off the tail of an ODX file
/// identifier: `"EV_ECM20TFS0208V0906259K"` → `"8V0906259K"`.
///
/// ODIS layer names carry a three-digit revision suffix
/// (`"…0906259Q_001"`) which is stripped first. [`None`] rather than a guess
/// when the tail is not part-number shaped.
fn spare_part_from_odx_identifier(ident: &str) -> Option<String> {
    if !ident.is_ascii() {
        return None;
    }
    let core = match ident.rfind('_') {
        Some(i) if ident.len() - i == 4 && ident[i + 1..].bytes().all(|b| b.is_ascii_digit()) => {
            &ident[..i]
        }
        _ => ident,
    };
    if core.len() < 10 {
        return None;
    }
    let tail = &core[core.len() - 10..];
    let plausible = tail.bytes().all(|b| b.is_ascii_alphanumeric())
        && tail.bytes().any(|b| b.is_ascii_digit())
        && tail.bytes().any(|b| b.is_ascii_alphabetic());
    plausible.then(|| tail.to_ascii_uppercase())
}

/// Pull the project prefix off the head of a Boot Loader Identification string:
/// `"SC8.1 CB.00.00.I0 C02.00 SC8"` → `"SC8"`.
///
/// The prefix runs to the first `.` or space. Anything that is not a short
/// alphanumeric token returns [`None`] so it falls through to weaker evidence
/// rather than resolving to a wrong module.
fn project_from_boot_loader_identification(ident: &str) -> Option<&str> {
    let head = ident
        .split(|c: char| c == '.' || c.is_whitespace())
        .next()?;
    let plausible = (2..=4).contains(&head.len())
        && head.bytes().all(|b| b.is_ascii_alphanumeric())
        && head.bytes().any(|b| b.is_ascii_alphabetic());
    plausible.then_some(head)
}

/// The registry module whose `project_name` is `project`, when exactly one has
/// it.
///
/// DQ250 and DQ381 share the project name `F`, so a lookup hitting more than
/// one module answers [`None`] rather than naming an arbitrary one.
fn module_with_project_name(project: &str) -> Option<&'static str> {
    let mut hits = module_names().into_iter().filter(|name| {
        get_flash_info(name).is_some_and(|info| {
            !info.project_name.is_empty() && info.project_name.eq_ignore_ascii_case(project)
        })
    });
    let only = hits.next()?;
    hits.next().is_none().then_some(only)
}

// ── Candidates ───────────────────────────────────────────────────────────────

/// How sure we are about a candidate, ordered least to most certain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// At least one other candidate on this channel is indistinguishable from
    /// this one with the data we have.  The user must choose.
    Ambiguous,
    /// Reachable on this channel, but nothing in the response singles it out.
    Possible,
    /// The identification strings match this module's known box code.
    Likely,
    /// No other supported module can answer on this channel.
    Confirmed,
}

/// One module that could be the ECU that answered.
#[derive(Clone)]
pub struct Candidate {
    /// The flashing configuration this candidate selects.
    pub flash_info: &'static FlashInfo,
    /// Registry name, as accepted by `--module` and
    /// [`mqb_modules::get_flash_info`].
    pub module_name: &'static str,
    /// How sure we are.
    pub confidence: Confidence,
    /// The strings the ECU returned, so the wizard can show its evidence.
    pub strings: IdentStrings,
    /// Why this candidate is being offered, in the user's language.
    pub reason: String,
}

// `FlashInfo` holds a `&'static dyn BlockCrypto` and is not Debug.
impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate")
            .field("module_name", &self.module_name)
            .field("confidence", &self.confidence)
            .field("strings", &self.strings)
            .field("reason", &self.reason)
            .finish()
    }
}

/// The result of probing one channel.
#[derive(Debug, Clone)]
pub struct ChannelIdentification {
    /// The channel that answered.
    pub channel: &'static IdentChannel,
    /// Raw DID bytes exactly as read, for logging and for the diagnostics tool.
    pub dids: HashMap<u16, Vec<u8>>,
    /// Ranked best-first; may hold more than one entry.
    pub candidates: Vec<Candidate>,
}

impl ChannelIdentification {
    /// True when the user has to break a tie.
    pub fn is_ambiguous(&self) -> bool {
        self.candidates.len() > 1
            && self
                .candidates
                .iter()
                .all(|c| c.confidence == Confidence::Ambiguous)
    }

    /// The single answer, when there is one.
    pub fn resolved(&self) -> Option<&Candidate> {
        match self.candidates.as_slice() {
            [only] => Some(only),
            _ => None,
        }
    }
}

/// Known-good box codes per Simos variant, from each module's
/// `patch_info.patch_box_code`.
///
/// The only in-tree evidence tying a part number to a variant, so it is a
/// positive match only: an absent part number says nothing. A unit test keeps
/// it in step with `mqb_modules`.
const SIMOS_VARIANT_BOX_CODES: &[(&str, &str)] = &[
    ("simos18", "8V0906259H"),
    ("simos1810", "5G0906259Q"),
    ("simos184", "80A906259F"),
];

/// Spare part numbers of the DQ250 begin with this.
///
/// Sole in-tree evidence: the `DQ250_MQB_0D9300012L_4516` dump named in
/// `VW_Flash/lib/crypto/dsg.py`. One sample is a hint, not a rule — it must
/// never resolve the DQ250/DQ381 tie.
/// raise DQ250 up the ranking but must never resolve the DQ250/DQ381 tie.
const DQ250_PART_NUMBER_PREFIX: &str = "0D9300012";

/// Marker that a control module is a petrol engine ECU in VW's ODX naming
/// (`EV_ECM<displacement>TFS<n><part number>`).
const SIMOS_ODX_PREFIX: &str = "EV_ECM";

/// Rank the modules that could have produced this DID map — pure, no bus.
///
/// Best-first. An empty map is not evidence of anything, so the result is
/// empty: identification never falls back to a default module.
pub fn candidates_from_dids(
    dids: &HashMap<u16, Vec<u8>>,
    channel: &IdentChannel,
) -> Vec<Candidate> {
    if dids.is_empty() {
        return Vec::new();
    }
    let strings = IdentStrings::from_dids(dids);
    match channel.kind {
        ChannelKind::SimosEngine => simos_candidates(&strings, channel),
        ChannelKind::Transmission => transmission_candidates(&strings),
        ChannelKind::HaldexAwd => haldex_candidates(&strings),
    }
}

/// Build one candidate, skipping it if the registry has lost the name.
fn candidate(
    module_name: &'static str,
    confidence: Confidence,
    strings: &IdentStrings,
    reason: String,
) -> Option<Candidate> {
    let flash_info = get_flash_info(module_name)?;
    Some(Candidate {
        flash_info,
        module_name,
        confidence,
        strings: strings.clone(),
        reason,
    })
}

/// Decide a channel from the bootloader's own project prefix, when it read.
///
/// [`None`] means "fall through to the weaker evidence": the record was
/// unreadable, not project-shaped, or ambiguous across this channel's modules.
/// A prefix naming a module the channel does not offer is *not* ignored — it
/// produces candidates that say so, because three confident-looking choices
/// would be worse than an explicit "this is something else".
fn boot_loader_candidates(
    strings: &IdentStrings,
    channel: &IdentChannel,
) -> Option<Vec<Candidate>> {
    let project = strings.boot_loader_project()?;
    let reported = strings
        .boot_loader_identification
        .as_deref()
        .unwrap_or(project);

    // Ambiguous project names (DQ250 and DQ381 are both `F`) cannot resolve
    // anything, so leave those channels to their own rules.
    let matches: Vec<&'static str> = channel
        .modules
        .iter()
        .copied()
        .filter(|name| {
            get_flash_info(name).is_some_and(|info| info.project_name.eq_ignore_ascii_case(project))
        })
        .collect();

    if let [only] = *matches.as_slice() {
        let reason = format!(
            "The bootloader identifies itself as project {project} (\"{reported}\"), which is \
             the {only} project name. No other module on this channel uses it."
        );
        return Some(
            candidate(only, Confidence::Confirmed, strings, reason)
                .into_iter()
                .collect(),
        );
    }
    if !matches.is_empty() {
        // More than one module on the channel claims this project name, so the
        // prefix says nothing here.
        return None;
    }

    let elsewhere = module_with_project_name(project);
    let reason = match elsewhere {
        Some(other) => format!(
            "The bootloader identifies itself as project {project} (\"{reported}\"), which is \
             the {other} project name — not one of the modules this channel flashes. Only \
             pick one of these if you know the bootloader is lying about itself."
        ),
        None => format!(
            "The bootloader identifies itself as project {project} (\"{reported}\"), which \
             matches none of the modules this tool knows. Flashing any of these would be a \
             guess."
        ),
    };
    let out: Vec<Candidate> = channel
        .modules
        .iter()
        .copied()
        .filter_map(|name| candidate(name, Confidence::Possible, strings, reason.clone()))
        .collect();
    (!out.is_empty()).then_some(out)
}

/// Rank `simos18` / `simos1810` / `simos184`, strongest evidence first:
///
/// 1. The bootloader's own project prefix ([`DID_BOOT_LOADER_IDENTIFICATION`]).
///    `SC8` / `SCB` / `SCG` are the three variants' `project_name`s, so a hit
///    resolves the channel — the other two are dropped, not demoted.
/// 2. The spare part number, when that record was unreadable. An exact box-code
///    hit promotes one variant but keeps the others: VW part numbers do not
///    encode the Simos generation, so a miss proves nothing.
fn simos_candidates(strings: &IdentStrings, channel: &IdentChannel) -> Vec<Candidate> {
    if let Some(c) = boot_loader_candidates(strings, channel) {
        return c;
    }

    let part = strings.effective_spare_part_number();
    let matched = part.as_deref().and_then(|pn| {
        SIMOS_VARIANT_BOX_CODES
            .iter()
            .find(|(_, code)| pn.starts_with(code))
            .map(|(name, _)| *name)
    });

    // An ECM that does not name itself an ECM may not be a Simos petrol ECU.
    let looks_like_ecm = strings
        .odx_file_identifier
        .as_deref()
        .map(|id| id.starts_with(SIMOS_ODX_PREFIX));

    let mut out = Vec::new();
    for (name, code) in SIMOS_VARIANT_BOX_CODES {
        let (confidence, reason) = match (matched, looks_like_ecm) {
            (Some(hit), _) if hit == *name => (
                Confidence::Likely,
                format!(
                    "Spare part number {} matches the known {name} box code {code} ({}).",
                    part.as_deref().unwrap_or("?"),
                    strings.summary()
                ),
            ),
            (Some(hit), _) => (
                Confidence::Possible,
                format!(
                    "Also flashable on 0x7E0, but the part number matches {hit} instead. \
                     Only pick {name} if you know this ECU is one."
                ),
            ),
            (None, Some(false)) => (
                Confidence::Possible,
                format!(
                    "Answered on the engine channel 0x7E0, but the ODX identifier does not \
                     start with {SIMOS_ODX_PREFIX} — this may not be a Simos ECU at all ({}).",
                    strings.summary()
                ),
            ),
            (None, _) => (
                Confidence::Ambiguous,
                format!(
                    "Simos 18 variants share 0x7E0 and nothing read back distinguishes them \
                     ({}). Choose the variant that matches your ECU.",
                    strings.summary()
                ),
            ),
        };
        if let Some(c) = candidate(name, confidence, strings, reason) {
            out.push(c);
        }
    }
    // Stable sort keeps the declaration order within one confidence level.
    out.sort_by_key(|c| Reverse(c.confidence));
    out
}

/// Rank the two transmission controllers.
///
/// DQ250 and DQ381 are indistinguishable at the transport layer and this repo
/// holds no data telling their identification strings apart, so this always
/// returns both as [`Confidence::Ambiguous`]; the `0D9300012` prefix only
/// changes the explanation.
fn transmission_candidates(strings: &IdentStrings) -> Vec<Candidate> {
    let part = strings.effective_spare_part_number();
    let dq250_hint = part
        .as_deref()
        .is_some_and(|pn| pn.starts_with(DQ250_PART_NUMBER_PREFIX));

    let shared = format!(
        "DQ250 and DQ381 both answer on 0x7E1 and report the same records, so this cannot be \
         decided automatically ({}).",
        strings.summary()
    );

    let (dq250_reason, dq381_reason) = if dq250_hint {
        (
            format!(
                "Spare part number {} starts with {DQ250_PART_NUMBER_PREFIX}, which is the only \
                 DQ250 part number known to this tool — a hint, not proof. {shared}",
                part.as_deref().unwrap_or("?")
            ),
            shared.clone(),
        )
    } else {
        (shared.clone(), shared.clone())
    };

    // Registry order in BOTH cases, carrying no preference — the caller must
    // present these as an explicit choice. The `0D9300012` hint rests on a
    // single source comment in the Python reference, far too thin to reorder
    // on, so it changes only the explanation shown to the user.
    let ordered: [(&'static str, String); 2] = [("dq250", dq250_reason), ("dq381", dq381_reason)];

    ordered
        .into_iter()
        .filter_map(|(name, reason)| candidate(name, Confidence::Ambiguous, strings, reason))
        .collect()
}

/// The Haldex coupler is the only supported module on 0x70F, so an answer
/// resolves it outright.
fn haldex_candidates(strings: &IdentStrings) -> Vec<Candidate> {
    let reason = format!(
        "0x70F/0x779 is used only by the Haldex AWD coupler among the supported modules ({}).",
        strings.summary()
    );
    candidate("haldex", Confidence::Confirmed, strings, reason)
        .into_iter()
        .collect()
}

// ── Bus probe ────────────────────────────────────────────────────────────────

/// Probe one already-open channel and rank what is on it.
///
/// `flash_info` is used only to find the matching [`IdentChannel`] from the CAN
/// addresses the transport was opened with.
///
/// [`None`] means nothing answered — a refused session, a timeout or an empty
/// DID map — which is the expected outcome on two of the three channels, so
/// failures are logged at debug level rather than surfaced as errors.
pub async fn identify_on_channel<T: TransportLayer>(
    transport: &T,
    flash_info: &'static FlashInfo,
) -> Option<ChannelIdentification> {
    let Some(channel) = channel_for(flash_info) else {
        tracing::debug!(
            txid = flash_info.control_module_identifier.txid,
            "No identification channel for these CAN identifiers"
        );
        return None;
    };

    // A module that will not open an extended session will not answer the reads.
    if let Err(e) = open_extended_session(transport).await {
        tracing::debug!(channel = channel.label, "No extended session: {e}");
        return None;
    }

    let mut dids = read_dids(transport, IDENT_DIDS).await;
    if dids.is_empty() {
        tracing::debug!(
            channel = channel.label,
            "Session opened but no DIDs readable"
        );
        return None;
    }

    // Only a channel that already answered pays for the informational sweep, so
    // the silent addresses in a scan cost nothing extra.
    dids.extend(read_dids(transport, &extra_info_dids()).await);

    let candidates = candidates_from_dids(&dids, channel);
    tracing::info!(
        channel = channel.label,
        candidates = candidates.len(),
        "Identified control module"
    );
    Some(ChannelIdentification {
        channel,
        dids,
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(u16, &str)]) -> HashMap<u16, Vec<u8>> {
        entries
            .iter()
            .map(|(did, text)| (*did, text.as_bytes().to_vec()))
            .collect()
    }

    fn channel(kind: ChannelKind) -> &'static IdentChannel {
        IDENT_CHANNELS.iter().find(|c| c.kind == kind).unwrap()
    }

    fn names(candidates: &[Candidate]) -> Vec<&'static str> {
        candidates.iter().map(|c| c.module_name).collect()
    }

    // ── Informational records ───────────────────────────────────────────────

    #[test]
    fn extra_info_dids_never_repeats_an_identification_read() {
        let extra = extra_info_dids();
        for did in &extra {
            assert!(!IDENT_DIDS.contains(did), "0x{did:04X} read twice");
        }
        // The overlap is real: the info table reuses the identification records.
        assert!(extra.len() < INFO_FIELDS.len());
    }

    #[test]
    fn info_fields_are_known_data_records() {
        for field in INFO_FIELDS {
            assert!(
                mqb_modules::DATA_RECORDS
                    .iter()
                    .any(|r| r.address == field.did && (r.parse_type == 0) == field.text),
                "0x{:04X} ({}) disagrees with DATA_RECORDS",
                field.did,
                field.label
            );
        }
    }

    #[test]
    fn info_values_skips_refused_and_padding_only_records() {
        let dids: HashMap<u16, Vec<u8>> = [
            (0xF190u16, b"WVWZZZAUZJW000000".to_vec()),
            (DID_SYSTEM_NAME, b"2.0l R4 TFSI \0".to_vec()),
            (0xF1AD, b"   ".to_vec()),
            (0xF442, vec![0x03, 0x2C]),
            (0x0600, Vec::new()),
        ]
        .into_iter()
        .collect();

        let shown = info_values(&dids);
        let labels: Vec<&str> = shown.iter().map(|(l, _)| *l).collect();
        assert_eq!(
            labels,
            vec!["VIN", "System name / engine type", "Control module voltage"]
        );
        assert_eq!(shown[1].1, "2.0l R4 TFSI");
        assert_eq!(shown[2].1, "03 2C");
    }
    // ── Channel table ───────────────────────────────────────────────────────

    #[test]
    fn every_channel_module_resolves_and_matches_the_channel_addresses() {
        for ch in IDENT_CHANNELS {
            for name in ch.modules {
                let info = get_flash_info(name)
                    .unwrap_or_else(|| panic!("registry has no module `{name}`"));
                let cmi = &info.control_module_identifier;
                assert_eq!(cmi.txid, ch.txid, "{name} txid");
                assert_eq!(cmi.rxid, ch.rxid, "{name} rxid");
            }
        }
    }

    #[test]
    fn channels_cover_the_four_supported_modules() {
        let all: Vec<&str> = IDENT_CHANNELS
            .iter()
            .flat_map(|c| c.modules)
            .copied()
            .collect();
        for expected in [
            "simos18",
            "simos1810",
            "simos184",
            "dq250",
            "dq381",
            "haldex",
        ] {
            assert!(all.contains(&expected), "{expected} is not scanned");
        }
        // Three unique channels for the four supported module families.
        assert_eq!(IDENT_CHANNELS.len(), 3);
    }

    #[test]
    fn channel_lookup_is_by_can_address() {
        let s18 = get_flash_info("simos18").unwrap();
        assert_eq!(channel_for(s18).unwrap().kind, ChannelKind::SimosEngine);
        let dq = get_flash_info("dq381").unwrap();
        assert_eq!(channel_for(dq).unwrap().kind, ChannelKind::Transmission);
        let hx = get_flash_info("haldex").unwrap();
        assert_eq!(channel_for(hx).unwrap().kind, ChannelKind::HaldexAwd);
    }

    #[test]
    fn simos_box_code_table_matches_the_module_patch_info() {
        for (name, code) in SIMOS_VARIANT_BOX_CODES {
            let info = get_flash_info(name).unwrap();
            let patch = info
                .patch_info
                .as_ref()
                .unwrap_or_else(|| panic!("{name} has no patch_info"));
            assert!(
                patch.patch_box_code.starts_with(code),
                "{name}: table says {code}, module says {}",
                patch.patch_box_code
            );
        }
        // The part-number path ranks from this table rather than from the
        // channel, so the two must name the same modules.
        let engine = channel(ChannelKind::SimosEngine);
        let tabled: Vec<&str> = SIMOS_VARIANT_BOX_CODES.iter().map(|(n, _)| *n).collect();
        assert_eq!(tabled, engine.modules.to_vec());
    }

    // ── String decoding ─────────────────────────────────────────────────────

    #[test]
    fn nul_and_space_padding_is_stripped() {
        // Real values captured from an 8V0906259K Simos 18.1.
        let dids = map(&[
            (DID_ODX_FILE_IDENTIFIER, "EV_ECM20TFS0208V0906259K\0"),
            (DID_ODX_FILE_VERSION, "001005"),
            (DID_SPARE_PART_NUMBER, "8V0906259K "),
            (DID_SYSTEM_NAME, "2.0l R4 TFSI "),
        ]);
        let s = IdentStrings::from_dids(&dids);
        assert_eq!(
            s.odx_file_identifier.as_deref(),
            Some("EV_ECM20TFS0208V0906259K")
        );
        assert_eq!(s.odx_file_version.as_deref(), Some("001005"));
        assert_eq!(s.spare_part_number.as_deref(), Some("8V0906259K"));
        assert_eq!(s.system_name.as_deref(), Some("2.0l R4 TFSI"));
    }

    #[test]
    fn part_number_is_recovered_from_the_odx_identifier_when_f187_is_missing() {
        // Value quoted in VW_Flash/lib/constants.py.
        let dids = map(&[(DID_ODX_FILE_IDENTIFIER, "EV_ECM18TFS0208V0906264L\0")]);
        let s = IdentStrings::from_dids(&dids);
        assert_eq!(s.spare_part_number, None);
        assert_eq!(
            s.effective_spare_part_number().as_deref(),
            Some("8V0906264L")
        );

        // ODIS layer names carry a "_001" revision suffix.
        assert_eq!(
            spare_part_from_odx_identifier("EV_ECM20TFS0205G0906259Q_001").as_deref(),
            Some("5G0906259Q"),
        );
        // Nothing part-number shaped -> no guess.
        assert_eq!(spare_part_from_odx_identifier("EV_ECM"), None);
    }

    // ── Simos channel ───────────────────────────────────────────────────────

    #[test]
    fn simos_shaped_identifier_produces_simos_candidates() {
        let dids = map(&[
            (DID_ODX_FILE_IDENTIFIER, "EV_ECM20TFS0208V0906259K\0"),
            (DID_SPARE_PART_NUMBER, "8V0906259K "),
            (DID_SYSTEM_NAME, "2.0l R4 TFSI "),
        ]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::SimosEngine));
        assert!(names(&c).contains(&"simos18"));
        // 8V0906259K is not one of the three known box codes, so no variant may
        // claim more than ambiguity.
        assert!(c.iter().all(|c| c.confidence == Confidence::Ambiguous));
        assert_eq!(
            c.len(),
            3,
            "all three Simos variants must stay on the table"
        );
        // The reason must show the user what it was decided from.
        assert!(c[0].reason.contains("8V0906259K"));
    }

    #[test]
    fn known_box_code_promotes_one_simos_variant_without_dropping_the_others() {
        let dids = map(&[(DID_SPARE_PART_NUMBER, "5G0906259Q ")]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::SimosEngine));
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].module_name, "simos1810");
        assert_eq!(c[0].confidence, Confidence::Likely);
        assert!(c[1..].iter().all(|c| c.confidence == Confidence::Possible));
    }

    #[test]
    fn a_non_ecm_identifier_on_0x7e0_is_flagged_rather_than_trusted() {
        let dids = map(&[(DID_ODX_FILE_IDENTIFIER, "EV_TCMDQ250021Q\0")]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::SimosEngine));
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|c| c.confidence == Confidence::Possible));
        assert!(c[0].reason.contains("may not be a Simos ECU"));
    }

    // ── Boot Loader Identification ──────────────────────────────────────────

    /// Bytes captured from an 8V0906259K Simos 18.1.
    const CAPTURED_BOOT_LOADER_IDENT: &str = "SC8.1 CB.00.00.I0 C02.00 SC8 ";

    #[test]
    fn the_captured_bootloader_string_resolves_the_engine_channel_outright() {
        let dids = map(&[
            (DID_ODX_FILE_IDENTIFIER, "EV_ECM20TFS0208V0906259K\0"),
            (DID_SPARE_PART_NUMBER, "8V0906259K "),
            (DID_BOOT_LOADER_IDENTIFICATION, CAPTURED_BOOT_LOADER_IDENT),
        ]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::SimosEngine));

        // Without the bootloader record this part number leaves all three
        // ambiguous — see the test above.
        assert_eq!(names(&c), vec!["simos18"]);
        assert_eq!(c[0].confidence, Confidence::Confirmed);
        assert!(c[0].reason.contains("SC8"));

        let ident = ChannelIdentification {
            channel: channel(ChannelKind::SimosEngine),
            dids,
            candidates: c,
        };
        assert!(!ident.is_ambiguous(), "the user must not be asked");
        assert_eq!(ident.resolved().unwrap().module_name, "simos18");
    }

    /// Each variant's prefix must select that variant and no other — asserted
    /// against the registry rather than a copy of the prefixes.
    #[test]
    fn every_engine_variant_is_selected_by_its_own_project_prefix() {
        let ch = channel(ChannelKind::SimosEngine);
        for module in ch.modules {
            let project = get_flash_info(module).unwrap().project_name;
            assert!(!project.is_empty(), "{module} has no project name");
            let dids = map(&[(
                DID_BOOT_LOADER_IDENTIFICATION,
                &format!("{project}.1 CB.00.00.I0 C02.00 {project} "),
            )]);
            let c = candidates_from_dids(&dids, ch);
            assert_eq!(names(&c), vec![*module], "prefix {project}");
            assert_eq!(c[0].confidence, Confidence::Confirmed);
        }
    }

    /// The prefix wins over a part number pointing elsewhere: the box code
    /// table is a correlation, the bootloader is the ECU's own statement.
    #[test]
    fn the_bootloader_prefix_outranks_a_conflicting_box_code() {
        let dids = map(&[
            // 5G0906259Q is the known simos1810 box code.
            (DID_SPARE_PART_NUMBER, "5G0906259Q "),
            (
                DID_BOOT_LOADER_IDENTIFICATION,
                "SCB.1 CB.00.00.I0 C02.00 SCB",
            ),
        ]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::SimosEngine));
        assert_eq!(names(&c), vec!["simos184"]);
        assert_eq!(c[0].confidence, Confidence::Confirmed);
    }

    /// A project this channel does not flash must be named in the explanation,
    /// not dressed up as one of the three.
    #[test]
    fn an_unlisted_project_is_reported_rather_than_forced_into_a_variant() {
        // SC2 is Simos 12.2 — a real module in the registry, not offered here.
        let dids = map(&[(DID_BOOT_LOADER_IDENTIFICATION, "SC2.1 CB.00.00.I0")]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::SimosEngine));
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|x| x.confidence == Confidence::Possible));
        assert!(c[0].reason.contains("SC2"));
        assert!(c[0].reason.contains("simos122"));

        // A project name nothing in the registry uses says exactly that.
        let dids = map(&[(DID_BOOT_LOADER_IDENTIFICATION, "ZZ9.1 CB.00.00.I0")]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::SimosEngine));
        assert_eq!(c.len(), 3);
        assert!(c[0].reason.contains("none of the modules this tool knows"));
    }

    /// Junk in `0xF1F4` falls through to the part-number evidence.
    #[test]
    fn an_unparseable_bootloader_record_falls_through() {
        for junk in ["", "   ", ".", "0.1", "TOOLONGPREFIX.1", "1234.5"] {
            let dids = map(&[
                (DID_BOOT_LOADER_IDENTIFICATION, junk),
                (DID_SPARE_PART_NUMBER, "5G0906259Q "),
            ]);
            let c = candidates_from_dids(&dids, channel(ChannelKind::SimosEngine));
            assert_eq!(c.len(), 3, "{junk:?} resolved something it should not have");
            assert_eq!(c[0].module_name, "simos1810", "{junk:?}");
            assert_eq!(c[0].confidence, Confidence::Likely, "{junk:?}");
        }
    }

    #[test]
    fn the_project_prefix_is_the_head_of_the_string() {
        assert_eq!(
            project_from_boot_loader_identification(CAPTURED_BOOT_LOADER_IDENT.trim()),
            Some("SC8")
        );
        assert_eq!(
            project_from_boot_loader_identification("SCG C02.00"),
            Some("SCG")
        );
        // No separator at all is still a prefix, as long as it is short.
        assert_eq!(project_from_boot_loader_identification("SCB"), Some("SCB"));
        // Not project-shaped -> no guess.
        for junk in ["", ".SC8", "SC8XXXX", "1", "12345"] {
            assert_eq!(
                project_from_boot_loader_identification(junk),
                None,
                "{junk:?}"
            );
        }
    }

    /// DQ250 and DQ381 share the project name `F`, so the prefix cannot decide
    /// that channel.
    #[test]
    fn a_project_name_shared_by_two_modules_names_neither() {
        assert_eq!(module_with_project_name("F"), None);
        assert_eq!(module_with_project_name("SC8"), Some("simos18"));
        assert_eq!(module_with_project_name(""), None);
    }

    // ── Transmission channel ────────────────────────────────────────────────

    #[test]
    fn transmission_channel_returns_exactly_two_ambiguous_candidates() {
        let dids = map(&[
            (DID_ODX_FILE_IDENTIFIER, "EV_TCMDQ250021\0"),
            (DID_SYSTEM_NAME, "DQ250 "),
        ]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::Transmission));
        assert_eq!(names(&c), vec!["dq250", "dq381"]);
        assert!(c.iter().all(|c| c.confidence == Confidence::Ambiguous));
        // Without the part-number hint neither may claim any edge.
        assert_eq!(c[0].reason, c[1].reason);

        let ident = ChannelIdentification {
            channel: channel(ChannelKind::Transmission),
            dids,
            candidates: c,
        };
        assert!(ident.is_ambiguous());
        assert!(ident.resolved().is_none());
    }

    #[test]
    fn dq250_part_number_prefix_explains_but_never_resolves() {
        // 0D9300012L is the DQ250 dump named in VW_Flash/lib/crypto/dsg.py.
        let hinted = candidates_from_dids(
            &map(&[(DID_SPARE_PART_NUMBER, "0D9300012L ")]),
            channel(ChannelKind::Transmission),
        );
        let plain = candidates_from_dids(
            &map(&[(DID_SPARE_PART_NUMBER, "0GC300012A ")]),
            channel(ChannelKind::Transmission),
        );

        for c in [&hinted, &plain] {
            assert_eq!(
                names(c),
                vec!["dq250", "dq381"],
                "DQ381 must never be dropped"
            );
            assert!(
                c.iter().all(|x| x.confidence == Confidence::Ambiguous),
                "the hint is a single source comment — it must never resolve the choice"
            );
        }

        // The hint changes only the explanation, and only DQ250's.
        assert!(hinted[0].reason.contains("hint, not proof"));
        assert!(!hinted[1].reason.contains("hint, not proof"));

        // Without it, neither candidate carries any preference at all.
        assert_eq!(
            plain[0].reason, plain[1].reason,
            "with no hint the two candidates must be indistinguishable"
        );
        assert!(!plain[0].reason.contains("hint, not proof"));
        assert!(!plain.iter().any(|c| c.reason.contains("0D9300012")));
    }

    // ── Haldex channel ──────────────────────────────────────────────────────

    #[test]
    fn haldex_channel_resolves_outright() {
        let dids = map(&[(DID_SPARE_PART_NUMBER, "0CQ598549 ")]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::HaldexAwd));
        assert_eq!(names(&c), vec!["haldex"]);
        assert_eq!(c[0].confidence, Confidence::Confirmed);

        let ident = ChannelIdentification {
            channel: channel(ChannelKind::HaldexAwd),
            dids,
            candidates: c,
        };
        assert!(!ident.is_ambiguous());
        assert_eq!(ident.resolved().unwrap().module_name, "haldex");
    }

    // ── No evidence ─────────────────────────────────────────────────────────

    #[test]
    fn an_empty_did_map_never_guesses() {
        let empty = HashMap::new();
        for ch in IDENT_CHANNELS {
            assert!(
                candidates_from_dids(&empty, ch).is_empty(),
                "{} guessed with no evidence",
                ch.label
            );
        }
    }

    #[test]
    fn a_channel_that_answers_with_padding_only_still_counts_as_present() {
        // An empty-but-present reply is still evidence about the channel.
        let dids = map(&[(DID_SPARE_PART_NUMBER, "          ")]);
        let c = candidates_from_dids(&dids, channel(ChannelKind::HaldexAwd));
        assert_eq!(names(&c), vec!["haldex"]);
        assert!(c[0].reason.contains("no identification strings"));
    }

    #[test]
    fn confidence_orders_from_ambiguous_to_confirmed() {
        assert!(Confidence::Ambiguous < Confidence::Possible);
        assert!(Confidence::Possible < Confidence::Likely);
        assert!(Confidence::Likely < Confidence::Confirmed);
    }
}
