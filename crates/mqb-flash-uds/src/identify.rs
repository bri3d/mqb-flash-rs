//! Control-module identification — work out *which* ECU is on the bus.
//!
//! The flashing wizard's first real step is "what am I plugged into?".  Making
//! the user pick the module from a dropdown before anything has been read is
//! both a usability problem and a safety problem: picking `dq381` when a DQ250
//! is attached puts the wrong crypto, the wrong block layout and the wrong
//! erase policy on the wire.
//!
//! Identification here is deliberately *evidence-based and honest*:
//!
//! * The four supported modules occupy only **three** CAN channels
//!   ([`IDENT_CHANNELS`]), so the channel alone already narrows the answer.
//! * On a channel that hosts more than one module we read a handful of
//!   identification DIDs ([`IDENT_DIDS`]) and rank the candidates.
//! * When the data cannot separate two modules we return **both**, flagged
//!   [`Confidence::Ambiguous`], and let the wizard ask the user.  We never
//!   invent a discriminator, and we never fall back to a default guess.
//!
//! The bus-touching half ([`identify_on_channel`]) is a thin wrapper around the
//! pure half ([`candidates_from_dids`]) so the ranking rules are unit-testable
//! with no adapter, no runtime and no vehicle.
//!
//! Transport construction is interface-specific and lives in [`crate::flash`];
//! the wizard opens each channel itself using
//! [`crate::flash::make_isotp_config`] with [`IdentChannel::probe_flash_info`].

use std::collections::HashMap;

use automotive::TransportLayer;
use mqb_modules::{get_flash_info, FlashInfo};

use crate::flash::{open_extended_session, read_dids};

// ── DIDs read during identification ──────────────────────────────────────────

/// ASAM/ODX File Identifier — e.g. `"EV_ECM20TFS0208V0906259K\0"`.
///
/// The most informative single record: it names the ECU family and embeds the
/// spare part number of the software the ECU was flashed with.
pub const DID_ODX_FILE_IDENTIFIER: u16 = 0xF19E;

/// ASAM/ODX File Version — e.g. `"001005"`.
///
/// ODIS treats identifier + version as the key *pair*; carrying it lets the
/// wizard (or the diagnostics tool) look the ECU up later.
pub const DID_ODX_FILE_VERSION: u16 = 0xF1A2;

/// VW Spare Part Number — 11 characters including a trailing pad space,
/// e.g. `"8V0906264M "`.
pub const DID_SPARE_PART_NUMBER: u16 = 0xF187;

/// VW System Name Or Engine Type — e.g. `"2.0l R4 TFSI "`.
pub const DID_SYSTEM_NAME: u16 = 0xF197;

/// The DIDs [`identify_on_channel`] reads, in request order.
///
/// Deliberately four records rather than the 38-record
/// [`mqb_modules::DATA_RECORDS`] sweep: identification runs once per candidate
/// channel, and a full sweep per channel would cost over a hundred requests
/// before the user has even chosen a file.
pub const IDENT_DIDS: &[u16] = &[
    DID_ODX_FILE_IDENTIFIER,
    DID_ODX_FILE_VERSION,
    DID_SPARE_PART_NUMBER,
    DID_SYSTEM_NAME,
];

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
    /// Registry names ([`mqb_modules::get_flash_info`]) of every supported
    /// module reachable here.  More than one entry means the channel cannot be
    /// resolved by address alone.
    pub modules: &'static [&'static str],
}

impl IdentChannel {
    /// The [`FlashInfo`] to build the probe transport from.
    ///
    /// Any module on the channel would do — only the CAN identifiers matter for
    /// a read-only DID probe — so the first is used.
    ///
    /// # Panics
    /// If the channel names a module the registry does not know; that is a
    /// build-time inconsistency and is covered by a unit test.
    pub fn probe_flash_info(&self) -> &'static FlashInfo {
        get_flash_info(self.modules[0])
            .unwrap_or_else(|| panic!("unknown module `{}` in IDENT_CHANNELS", self.modules[0]))
    }
}

/// Every channel the wizard should scan, in the order it should scan them.
///
/// The wizard drives the scan: for each entry it opens a transport for
/// [`IdentChannel::probe_flash_info`] using its own interface handling and then
/// calls [`identify_on_channel`].  Engine first because it is by far the most
/// commonly flashed module, so the common case answers on the first probe.
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
/// Values are decoded as UTF-8 (lossily) and stripped of the NUL and space
/// padding VW pads these records with; a DID the ECU refused, or answered with
/// nothing but padding, is [`None`].
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
}

impl IdentStrings {
    /// Decode the four identification DIDs out of a raw DID map.
    pub fn from_dids(dids: &HashMap<u16, Vec<u8>>) -> Self {
        Self {
            odx_file_identifier: decode(dids.get(&DID_ODX_FILE_IDENTIFIER)),
            odx_file_version: decode(dids.get(&DID_ODX_FILE_VERSION)),
            spare_part_number: decode(dids.get(&DID_SPARE_PART_NUMBER)),
            system_name: decode(dids.get(&DID_SYSTEM_NAME)),
        }
    }

    /// The best available spare part number.
    ///
    /// Prefers the dedicated record and falls back to the part number embedded
    /// in the ODX file identifier, because some modules answer one but not the
    /// other.
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
/// (`"EV_ECM20TFS0205G0906259Q_001"`) which is stripped first.  Returns [`None`]
/// rather than a guess when the tail does not look like a part number at all.
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

// ── Candidates ───────────────────────────────────────────────────────────────

/// How sure we are about a candidate.
///
/// Ordered least to most certain, so `Ord` compares the way a reader expects
/// (`Confidence::Ambiguous < Confidence::Confirmed`).
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
///
/// [`candidates_from_dids`] returns these ranked best-first.
#[derive(Clone)]
pub struct Candidate {
    /// The flashing configuration this candidate selects.
    pub flash_info: &'static FlashInfo,
    /// Registry name, as accepted by `--module` and
    /// [`mqb_modules::get_flash_info`].
    pub module_name: &'static str,
    /// How sure we are.
    pub confidence: Confidence,
    /// The strings the ECU actually returned, so the wizard can show the user
    /// what the decision was based on.
    pub strings: IdentStrings,
    /// Why this candidate is being offered, in the user's language.
    pub reason: String,
}

// FlashInfo holds a `&'static dyn BlockCrypto` and does not implement Debug, so
// Candidate cannot derive it; identify the module by name instead.
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

/// Known-good box codes per Simos variant, taken from each module's
/// `patch_info.patch_box_code` (the ECU each variant's patch was built for).
///
/// This is the *only* in-tree evidence tying a part number to a Simos variant,
/// so it is used as a positive match and never as an exclusion: a part number
/// that is absent here says nothing at all.  A unit test keeps it in step with
/// `mqb_modules`.
const SIMOS_VARIANT_BOX_CODES: &[(&str, &str)] = &[
    ("simos18", "8V0906259H"),
    ("simos1810", "5G0906259Q"),
    ("simos184", "80A906259F"),
];

/// Spare part numbers of the DQ250 begin with this.
///
/// Sole in-tree evidence: the `DQ250_MQB_0D9300012L_4516` flash dump named in
/// `VW_Flash/lib/crypto/dsg.py`.  One sample is a *hint*, not a rule — it can
/// raise DQ250 up the ranking but must never resolve the DQ250/DQ381 tie.
const DQ250_PART_NUMBER_PREFIX: &str = "0D9300012";

/// Marker that a control module is a petrol engine ECU in VW's ODX naming
/// (`EV_ECM<displacement>TFS<n><part number>`).
const SIMOS_ODX_PREFIX: &str = "EV_ECM";

/// Rank the modules that could have produced this DID map — pure, no bus.
///
/// Returns candidates best-first.  An **empty map means the ECU said nothing**,
/// which is not evidence of anything, so the result is empty: identification
/// never falls back to a default module.
pub fn candidates_from_dids(
    dids: &HashMap<u16, Vec<u8>>,
    channel: &IdentChannel,
) -> Vec<Candidate> {
    if dids.is_empty() {
        return Vec::new();
    }
    let strings = IdentStrings::from_dids(dids);
    match channel.kind {
        ChannelKind::SimosEngine => simos_candidates(&strings),
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

/// Rank `simos18` / `simos1810` / `simos184`.
///
/// An exact hit on a variant's known box code promotes that variant, but the
/// other two are still returned: VW part numbers do not encode the Simos
/// generation, so a miss proves nothing.
fn simos_candidates(strings: &IdentStrings) -> Vec<Candidate> {
    let part = strings.effective_spare_part_number();
    let matched = part.as_deref().and_then(|pn| {
        SIMOS_VARIANT_BOX_CODES
            .iter()
            .find(|(_, code)| pn.starts_with(code))
            .map(|(name, _)| *name)
    });

    // An ECM that does not name itself an ECM is a warning sign: something
    // other than a Simos petrol ECU may be answering on 0x7E0.
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
    out.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    out
}

/// Rank the two transmission controllers.
///
/// DQ250 and DQ381 are byte-identical at the transport layer — same CAN
/// addresses, same session behaviour — and this repo holds no data that tells
/// their identification strings apart.  So this always returns **both**, always
/// [`Confidence::Ambiguous`]; the `0D9300012` prefix only reorders them.
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

    // The order is registry order in BOTH cases and carries no preference —
    // the caller must present these as an explicit choice, never as
    // "first one wins". The `0D9300012` hint rests on a single source comment
    // in the Python reference, which is far too thin to reorder on; it changes
    // only the explanation shown to the user. Both stay `Ambiguous` so no
    // caller can mistake this for a resolved identification.
    let ordered: [(&'static str, String); 2] = [("dq250", dq250_reason), ("dq381", dq381_reason)];

    ordered
        .into_iter()
        .filter_map(|(name, reason)| candidate(name, Confidence::Ambiguous, strings, reason))
        .collect()
}

/// The Haldex coupler is the only supported module on 0x70F, so an answer there
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
/// `flash_info` supplies the CAN addresses the transport was opened with; it is
/// only used to find the matching [`IdentChannel`], not as an assumption about
/// what will answer.
///
/// Returns [`None`] when the module does not answer — a refused session, a
/// timeout or an empty DID map all mean "nothing here", which is exactly what a
/// scan of three channels expects on two of them.  Failures are logged at debug
/// level rather than surfaced as errors for that reason.
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

    // The identification DIDs are readable in the extended session; a module
    // that will not open one is not going to answer the reads either.
    if let Err(e) = open_extended_session(transport).await {
        tracing::debug!(channel = channel.label, "No extended session: {e}");
        return None;
    }

    let dids = read_dids(transport, IDENT_DIDS).await;
    if dids.is_empty() {
        tracing::debug!(
            channel = channel.label,
            "Session opened but no DIDs readable"
        );
        return None;
    }

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

        // Without it, neither candidate carries any preference at all. This is
        // the assertion that has teeth: if the hint ever leaks into the no-hint
        // path, or starts reordering, this fails.
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
        // The ECU replied — that is evidence about the channel even though the
        // strings are empty — so the Haldex channel still resolves.
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
