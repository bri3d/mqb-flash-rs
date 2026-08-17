//! Moving an immobilizer identity onto an ECU over the wire.
//!
//! The download service ([`crate::diag`]) rewrites most of the immobilizer
//! record — VIN, `noKeySecu`, `idxTun`, flags, `ctDatBasFazit` — but the record
//! it carries has **no slot for `noKeyMst`**. Instead the flags leave the ECU in
//! `stStatFct` 4, where `ImoComAuth` *learns* `noKeyMst` from whatever master
//! answers it: the value implied by an accepted reply is latched on the first
//! exchange and, if it repeats on the second, committed together with
//! `stStatFct = 2`.
//!
//! So adapting ECU B into car A is two steps on one bus:
//!
//! 1. a **download** that transplants A's record into B, keyed with **B's
//!    current** `noKeySecu`; and
//! 2. a **learn**, in which some master hands over A's `noKeyMst`.
//!
//! Step 2 is deliberately separate. A tester connected through the vehicle
//! gateway cannot see CAN `0x010`/`0x011` and so cannot play the master at all —
//! in that case the download is left to stand and the car's own cluster
//! completes the learn on the next ignition cycle. [`crate::auth::ImmoMaster`]
//! is only needed when the tool is on the powertrain bus directly.
//!
//! What a download **cannot** move, because `node_fcn24` never writes it:
//! `idxLab` (production data, and the selector for the master key),
//! `noKeySlave` (a platform value), `bLock` and `bInhAcsMem`.

use crate::auth::master_key_for_idx_lab;
use crate::diag::{
    download_flag_names, download_plaintext, download_value, key_proof, DiagError, DownloadCommand,
    DOWNLOAD_FLAG_ADAPTATION, DOWNLOAD_FLAG_AUTH_MUTE, DOWNLOAD_FLAG_LIM_MOD_ENA,
    DOWNLOAD_FLAG_TRIG_FCT_DI, DOWNLOAD_FLAG_VLD_CHK_DI, DOWNLOAD_PLAINTEXT_LEN,
    DOWNLOAD_VALUE_LEN,
};
use crate::state::{
    decode_2ed, decode_2ee, decode_2ef, decode_2ff, ImmoSnapshot, ImmoState, DID_CHALLENGE,
    DID_EXTENDED, DID_FAZIT, DID_IDENTITY_CKS, DID_STATE, DID_STATUS_BITS, DID_VIN,
};
use mqb_nvcrypt::ImmoSecrets;

/// Rebuild the download flags byte from a record, so a transplant carries the
/// donor's flag set rather than a hard-coded `0x80`.
///
/// Bit 7 is not optional: `node_fcn24` refuses a record without it, so every
/// download drops the ECU into adaptation mode whether or not that is wanted.
pub fn download_flags(source: &ImmoSecrets) -> u8 {
    let mut flags = DOWNLOAD_FLAG_ADAPTATION;
    for (set, bit) in [
        (source.b_auth_mute, DOWNLOAD_FLAG_AUTH_MUTE),
        (source.b_vld_chk_di, DOWNLOAD_FLAG_VLD_CHK_DI),
        (source.b_trig_fct_di, DOWNLOAD_FLAG_TRIG_FCT_DI),
        (source.b_lim_mod_ena, DOWNLOAD_FLAG_LIM_MOD_ENA),
    ] {
        if set {
            flags |= bit;
        }
    }
    flags
}

/// A download, built and ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadPlan {
    /// The VIN the record carries.
    pub vin: String,
    /// The `noKeySecu` being written — the donor's.
    pub no_key_secu: [u8; 16],
    /// The donor's `noKeyMst`. The record has no slot for it; it has to be
    /// learned over CAN afterwards, or supplied by the car's own cluster.
    pub no_key_mst: u16,
    /// The `idxTun` / PClass being written.
    pub idx_tun: u8,
    /// The flags byte, `plaintext[0x22]`.
    pub flags: u8,
    pub ct_dat_bas_fazit: u8,
    pub command: DownloadCommand,
    /// The 48-byte record before encryption.
    pub plaintext: [u8; DOWNLOAD_PLAINTEXT_LEN],
    /// The 52-byte DID `0x2E2` value.
    pub payload: [u8; DOWNLOAD_VALUE_LEN],
    /// The key the payload is encrypted under — the **target's current** key,
    /// not the one being written.
    pub encrypted_under: [u8; 16],
    /// True when the record's identity is the target's own, i.e. this is a
    /// PClass or VIN change rather than a transplant.
    pub same_ecu: bool,
}

impl DownloadPlan {
    /// The full `2E 02 E2 …` request bytes.
    pub fn request_frame(&self) -> Vec<u8> {
        crate::diag::wdbi_frame(crate::diag::DID_DOWNLOAD, &self.payload)
    }

    /// Human-readable names of the flags this record sets.
    pub fn flag_names(&self) -> Vec<&'static str> {
        download_flag_names(self.flags)
    }
}

/// Build the download that turns `target` into `donor`.
///
/// `target` is the ECU on the bench — its *current* key encrypts the request —
/// and `donor` is the identity to move onto it. `idx_tun` and `vin` override
/// the donor's values when given.
pub fn adapt_plan(
    target: &ImmoSecrets,
    donor: &ImmoSecrets,
    idx_tun: Option<u8>,
    vin: Option<&str>,
) -> Result<DownloadPlan, DiagError> {
    let vin = vin.unwrap_or(&donor.vin).to_string();
    let idx_tun = idx_tun.unwrap_or(donor.idx_tun);
    let flags = download_flags(donor);
    let command = DownloadCommand::SetKeyAndAdopt;

    let plaintext = download_plaintext(
        &vin,
        &donor.no_key_secu,
        idx_tun,
        flags,
        donor.ct_dat_bas_fazit,
        command,
    )?;
    let payload = download_value(&target.no_key_secu, &plaintext);

    Ok(DownloadPlan {
        vin,
        no_key_secu: donor.no_key_secu,
        no_key_mst: donor.no_key_mst,
        idx_tun,
        flags,
        ct_dat_bas_fazit: donor.ct_dat_bas_fazit,
        command,
        plaintext,
        payload,
        encrypted_under: target.no_key_secu,
        same_ecu: target.no_key_secu == donor.no_key_secu,
    })
}

/// The download that changes only `idxTun` / PClass on one ECU.
///
/// Structurally an adaptation of an ECU onto itself: every other field is
/// written back as it stands. Bit 7 of the flags cannot be dropped, so the ECU
/// still lands in `stStatFct` 4 and has to be told its own `noKeyMst` again.
pub fn pclass_plan(ecu: &ImmoSecrets, idx_tun: u8) -> Result<DownloadPlan, DiagError> {
    adapt_plan(ecu, ecu, Some(idx_tun), None)
}

/// The download that changes only the VIN on one ECU.
///
/// This rewrites the *immobilizer* record only. Other NVRAM channels carrying
/// vehicle identity are untouched.
pub fn vin_plan(ecu: &ImmoSecrets, vin: &str) -> Result<DownloadPlan, DiagError> {
    adapt_plan(ecu, ecu, None, Some(vin))
}

// ── Preflight ─────────────────────────────────────────────────────────────────

/// How much a preflight finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightLevel {
    /// The download would fail, or would succeed and leave a useless ECU.
    Blocker,
    /// Worth knowing before committing, but not disqualifying.
    Warning,
}

/// One preflight finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightItem {
    pub level: PreflightLevel,
    pub message: String,
}

impl PreflightItem {
    fn blocker(message: impl Into<String>) -> Self {
        Self {
            level: PreflightLevel::Blocker,
            message: message.into(),
        }
    }

    fn warning(message: impl Into<String>) -> Self {
        Self {
            level: PreflightLevel::Warning,
            message: message.into(),
        }
    }
}

/// Convenience view over a preflight result.
pub trait PreflightExt {
    /// The blocking findings.
    fn blockers(&self) -> Vec<&PreflightItem>;
    /// Whether anything blocks the download.
    fn is_blocked(&self) -> bool {
        !self.blockers().is_empty()
    }
}

impl PreflightExt for [PreflightItem] {
    fn blockers(&self) -> Vec<&PreflightItem> {
        self.iter()
            .filter(|i| i.level == PreflightLevel::Blocker)
            .collect()
    }
}

/// Prove the ECU on the bus holds `no_key_secu`, using DID `0x2F9`.
///
/// Returns `None` when the ECU did not answer the DID or the surrounding reads
/// are incomplete, which is different from "the key is wrong" and is reported
/// differently.
pub fn snapshot_key_proof(snapshot: &ImmoSnapshot, no_key_secu: &[u8; 16]) -> Option<bool> {
    let cks = snapshot.raw(DID_IDENTITY_CKS)?;
    let fazit = snapshot.raw(DID_FAZIT)?;
    let vin = snapshot.raw(DID_VIN)?;
    let adapt = snapshot.raw(DID_STATE)?;
    let live = snapshot.raw(DID_STATUS_BITS)?;
    let challenge = snapshot.raw(DID_CHALLENGE)?;
    Some(key_proof(
        cks,
        no_key_secu,
        fazit,
        vin,
        adapt,
        live,
        challenge,
    ))
}

/// Everything that would make the download fail, or make it succeed and leave a
/// useless ECU.
///
/// `target` is the dump believed to belong to the ECU on the bus. `same_ecu`
/// says the record being written is the target's own (a PClass or VIN change),
/// in which case the `idxLab` comparison — which is about the *donor car's*
/// cluster — does not apply.
pub fn adapt_preflight(
    plan: &DownloadPlan,
    snapshot: &ImmoSnapshot,
    target: &ImmoSecrets,
    donor_idx_lab: Option<u8>,
    same_ecu: bool,
) -> Vec<PreflightItem> {
    let mut out = Vec::new();

    let state = snapshot.raw(DID_STATE).and_then(decode_2ed);
    let bits = snapshot.raw(DID_STATUS_BITS).and_then(decode_2ee);
    let lockout = snapshot.raw(crate::state::DID_LOCKOUT).and_then(decode_2ef);
    let ext = snapshot.raw(DID_EXTENDED).and_then(decode_2ff);

    // ── The key must be the one the ECU actually holds ────────────────────
    //
    // This is a read, so unlike a trial download it proves the key without
    // risking the wrong-attempt lockout ladder.
    match snapshot_key_proof(snapshot, &target.no_key_secu) {
        None => out.push(PreflightItem::blocker(
            "DID 0x2F9 did not answer, so the dump's noKeySecu could not be checked against the \
             ECU before writing. A wrong key fails the record CRC and arms the download lockout.",
        )),
        Some(true) => {}
        Some(false) => {
            if snapshot_key_proof(snapshot, &plan.no_key_secu) == Some(true) {
                out.push(PreflightItem::blocker(
                    "this ECU already holds the DONOR key — it looks adapted already. Re-run with \
                     the dumps the other way round to undo it.",
                ));
            } else {
                out.push(PreflightItem::blocker(
                    "DID 0x2F9 does not match the target dump's noKeySecu: wrong dump, wrong \
                     Device ID, or this is not the ECU that dump came from.",
                ));
            }
        }
    }

    // ── The service's own preconditions ───────────────────────────────────
    match bits {
        Some(b) if !b.ignition_on => out.push(PreflightItem::blocker(
            "ignition is off — the download service refuses with error 0x14.",
        )),
        None => out.push(PreflightItem::blocker(
            "DID 0x2EE did not answer, so the ignition state could not be checked.",
        )),
        _ => {}
    }

    if let Some(lo) = lockout {
        if lo.download_lockout_minutes != 0 {
            out.push(PreflightItem::blocker(format!(
                "a download lockout is active with {} minute(s) remaining (error 0x19).",
                lo.download_lockout_minutes
            )));
        }
    }

    if let Some(st) = state {
        let immo_state = ImmoState::from_raw(st.st_stat_fct);
        if immo_state.is_dead() {
            out.push(PreflightItem::blocker(format!(
                "the ECU is in {} — the download is refused in this state.",
                immo_state.label()
            )));
        }
    }

    // ── The anti-tuning interlock ─────────────────────────────────────────
    //
    // CheckTuning runs after every adopt and forces stStatFct to 'B' when
    // idxTun is absent from the variant-coded allow-list, which would leave the
    // ECU adapted but unable to authenticate. This one fails silently: the
    // download is accepted and the car still will not start.
    match ext {
        None => out.push(PreflightItem::blocker(
            "DID 0x2FF did not answer, so the power-class allow-list could not be checked. \
             Writing an idxTun the variant coding disallows would force stStatFct to 'B'.",
        )),
        Some(e) if e.str_var_tun.iter().all(|&b| b == 0) => out.push(PreflightItem::blocker(
            "this ECU's power-class allow-list (strVarTun) is all zeroes, so CheckTuning forces \
             stStatFct to 'B' whatever idxTun is written.",
        )),
        Some(e) if !e.str_var_tun.contains(&plan.idx_tun) => {
            out.push(PreflightItem::blocker(format!(
                "idxTun 0x{:02X} is not in this ECU's allow-list [{}] — CheckTuning would force \
                 stStatFct to 'B' and the engine would not start. Choose a value the variant \
                 coding allows.",
                plan.idx_tun,
                hex_list(&e.str_var_tun)
            )));
        }
        Some(_) => {}
    }

    // ── Consequences worth knowing ────────────────────────────────────────
    //
    // Bit 7 of the flags byte cannot be dropped, so *every* download leaves the
    // ECU in adaptation mode. Until some master completes the learn the engine
    // will not start — and a tester behind the vehicle gateway cannot play that
    // master itself.
    out.push(PreflightItem::warning(format!(
        "the download leaves the ECU in adaptation mode (stStatFct 4). It will not start until a \
         master teaches it noKeyMst {:04X} — either this tool on the powertrain bus, or the car's \
         own cluster on the next ignition cycle.",
        plan.no_key_mst
    )));

    if let Some(reported) = snapshot.vin() {
        let reported = reported.trim_end_matches('\0');
        if reported != target.vin {
            out.push(PreflightItem::warning(format!(
                "the ECU reports VIN {reported} but the target dump says {} — the dump is stale, \
                 though the key proof above still governs.",
                target.vin
            )));
        }
    }

    if same_ecu {
        if let Some(e) = ext {
            if e.idx_tun == plan.idx_tun && plan.vin == target.vin {
                out.push(PreflightItem::warning(format!(
                    "the ECU already reports idxTun 0x{:02X} and this VIN — the download would \
                     rewrite the record to the same values and still cost a noKeyMst relearn.",
                    e.idx_tun
                )));
            }
        }
    } else if let Some(st) = state {
        // idxLab selects the master key both sides hash, comes from production
        // data, and no download can change it. If the donor car's differs, that
        // car's cluster and this ECU can never agree.
        match donor_idx_lab {
            Some(donor_lab) if donor_lab != st.idx_lab => {
                out.push(PreflightItem::warning(format!(
                    "idxLab differs: this ECU is 0x{:02X} (master key {}), the donor car 0x{:02X} \
                     (master key {}). idxLab is production data and is not part of the record, so \
                     no download can change it — the donor car's cluster will never agree on a \
                     master key with this ECU.",
                    st.idx_lab,
                    hex_bytes(&master_key_for_idx_lab(st.idx_lab)),
                    donor_lab,
                    hex_bytes(&master_key_for_idx_lab(donor_lab)),
                )));
            }
            Some(_) => {}
            None => out.push(PreflightItem::warning(format!(
                "the donor car's idxLab is unknown; this ECU uses 0x{:02X} (master key {}). Read \
                 DID 0x2ED on the donor car — if they differ, the swap cannot authenticate there.",
                st.idx_lab,
                hex_bytes(&master_key_for_idx_lab(st.idx_lab)),
            ))),
        }
    }

    if let Some(e) = ext {
        if e.last_error != 0 {
            out.push(PreflightItem::warning(format!(
                "the last immobilizer error was 0x{:02X} — {}.",
                e.last_error,
                crate::diag::imo_error_name(e.last_error)
            )));
        }
    }

    out
}

fn hex_list(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::aes128_encrypt_block;
    use crate::diag::identity_checksum;
    use crate::state::{ImmoSupport, DID_LOCKOUT, IMMO_DIDS_FULL};
    use mqb_modules::modules::simos18::S18_FLASH_INFO;
    use mqb_nvcrypt::StStatFct;
    use std::collections::HashMap;

    const TARGET_KEY: [u8; 16] = [
        0x59, 0x67, 0xF8, 0xFB, 0xF7, 0xAF, 0x63, 0x4F, 0x17, 0xCF, 0x78, 0x65, 0xF1, 0x83, 0x24,
        0xC3,
    ];
    const DONOR_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const TARGET_VIN: &str = "1VWAT7A31FC022915";
    const DONOR_VIN: &str = "WVWZZZ1KZAW000001";
    const FAZIT: [u8; 23] = [b'F'; 23];
    const CHALLENGE: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    const IDX_LAB: u8 = 0x0D;

    fn secrets(key: [u8; 16], vin: &str, idx_tun: u8, no_key_mst: u16) -> ImmoSecrets {
        ImmoSecrets {
            no_key_secu: key,
            no_key_mst,
            idx_tun,
            vin: vin.into(),
            ct_dat_bas_fazit: 0x01,
            st_stat_fct: StStatFct::Adapted,
            b_auth_mute: false,
            b_vld_chk_di: false,
            b_trig_fct_di: false,
            b_lim_mod_ena: false,
            b_lock: false,
            b_inh_acs_mem: false,
            channel: Some(6),
        }
    }

    fn target() -> ImmoSecrets {
        secrets(TARGET_KEY, TARGET_VIN, 0x6A, 0x2735)
    }

    fn donor() -> ImmoSecrets {
        secrets(DONOR_KEY, DONOR_VIN, 0x6A, 0x9E42)
    }

    /// DID 0x2ED, ten bytes.
    fn p2ed(st_stat_fct: u8) -> Vec<u8> {
        let mut v = vec![0u8; 10];
        v[0] = st_stat_fct;
        v[1] = 0x01; // ctDatBasFazit
        v[2] = IDX_LAB;
        v
    }

    /// DID 0x2EE. 0x04 / 0xFC is the fully healthy released reading.
    fn p2ee(b0: u8, b1: u8) -> Vec<u8> {
        let mut v = vec![0u8; 10];
        v[0] = b0;
        v[1] = b1;
        v
    }

    /// DID 0x2FF, nineteen bytes.
    fn p2ff(idx_tun: u8, allow: [u8; 5], last_error: u8) -> Vec<u8> {
        let mut v = vec![0u8; 19];
        v[0] = 0x53; // 'S' â€” a production ECU
        v[9] = idx_tun;
        v[10..15].copy_from_slice(&allow);
        v[15..18].copy_from_slice(&[0x08, 0x02, 0x00]);
        v[18] = last_error;
        v
    }

    /// A synthetic ECU: the DIDs it answers, and the key it actually holds.
    struct Ecu {
        key: [u8; 16],
        vin: String,
        state: Vec<u8>,
        bits: Vec<u8>,
        lockout: Vec<u8>,
        extended: Vec<u8>,
        answers_2f9: bool,
    }

    impl Default for Ecu {
        fn default() -> Self {
            Self {
                key: TARGET_KEY,
                vin: TARGET_VIN.into(),
                state: p2ed(2),
                bits: p2ee(0x04, 0xFC),
                lockout: vec![0u8; 6],
                extended: p2ff(0x6A, [0x6A, 0, 0, 0, 0], 0),
                answers_2f9: true,
            }
        }
    }

    impl Ecu {
        fn snapshot(&self) -> ImmoSnapshot {
            let support = ImmoSupport::for_module(&S18_FLASH_INFO).unwrap();
            let mut dids: HashMap<u16, Vec<u8>> = HashMap::new();
            dids.insert(DID_CHALLENGE, CHALLENGE.to_vec());
            dids.insert(DID_STATE, self.state.clone());
            dids.insert(DID_STATUS_BITS, self.bits.clone());
            dids.insert(DID_VIN, self.vin.as_bytes().to_vec());
            dids.insert(DID_FAZIT, FAZIT.to_vec());
            dids.insert(DID_LOCKOUT, self.lockout.clone());
            if !self.extended.is_empty() {
                dids.insert(DID_EXTENDED, self.extended.clone());
            }
            if self.answers_2f9 {
                // The ECU signs whatever it just reported, under the key it
                // really holds â€” which is what makes this a proof of the key.
                let cks = identity_checksum(
                    &self.key,
                    &FAZIT,
                    self.vin.as_bytes(),
                    &self.state,
                    &self.bits,
                    &CHALLENGE,
                )
                .unwrap();
                dids.insert(DID_IDENTITY_CKS, cks.to_vec());
            }
            ImmoSnapshot::from_dids(support, dids)
        }
    }

    fn preflight(ecu: &Ecu, plan: &DownloadPlan, donor_idx_lab: Option<u8>) -> Vec<PreflightItem> {
        adapt_preflight(
            plan,
            &ecu.snapshot(),
            &target(),
            donor_idx_lab,
            plan.same_ecu,
        )
    }

    fn blocker_texts(items: &[PreflightItem]) -> Vec<String> {
        items.blockers().iter().map(|i| i.message.clone()).collect()
    }

    /// The transplant record must carry the donor's whole identity and be
    /// encrypted under the **target's** key. Getting that backwards is the one
    /// mistake the ECU cannot report: the record just fails its CRC and the
    /// attempt walks the lockout ladder.
    #[test]
    fn adapt_plan_carries_the_donor_and_is_keyed_by_the_target() {
        let plan = adapt_plan(&target(), &donor(), None, None).unwrap();

        assert_eq!(&plan.plaintext[0x00..0x11], DONOR_VIN.as_bytes());
        assert_eq!(&plan.plaintext[0x11..0x21], &DONOR_KEY);
        assert_eq!(plan.plaintext[0x21], 0x6A);
        assert_eq!(plan.plaintext[0x22], DOWNLOAD_FLAG_ADAPTATION);
        assert_eq!(plan.plaintext[0x24], 3);
        assert_eq!(plan.no_key_mst, 0x9E42);
        assert_eq!(plan.encrypted_under, TARGET_KEY);
        assert!(!plan.same_ecu);

        let mut block = [0u8; 16];
        block.copy_from_slice(&plan.plaintext[0..16]);
        assert_eq!(
            &plan.payload[0..16],
            aes128_encrypt_block(&TARGET_KEY, &block)
        );
        assert_ne!(
            &plan.payload[0..16],
            aes128_encrypt_block(&DONOR_KEY, &block)
        );

        assert_eq!(plan.request_frame().len(), 55);
    }

    /// The donor's flag set travels with the record, not just a bare 0x80.
    #[test]
    fn download_flags_carry_the_donors_flags() {
        let mut d = donor();
        d.b_lim_mod_ena = true;
        d.b_auth_mute = true;
        let plan = adapt_plan(&target(), &d, None, None).unwrap();
        assert_eq!(
            plan.flags,
            DOWNLOAD_FLAG_ADAPTATION | DOWNLOAD_FLAG_LIM_MOD_ENA | DOWNLOAD_FLAG_AUTH_MUTE
        );
        assert!(plan.flag_names().contains(&"bLimModEna"));
    }

    /// A PClass change moves idxTun and nothing else, but still cannot drop the
    /// adaptation bit â€” so it still costs a noKeyMst relearn.
    #[test]
    fn pclass_plan_changes_only_idx_tun() {
        let t = target();
        let plan = pclass_plan(&t, 0x88).unwrap();
        assert_eq!(plan.idx_tun, 0x88);
        assert_eq!(plan.vin, TARGET_VIN);
        assert_eq!(plan.no_key_secu, TARGET_KEY);
        assert_eq!(plan.encrypted_under, TARGET_KEY);
        assert_eq!(plan.no_key_mst, t.no_key_mst);
        assert!(plan.same_ecu);
        assert_ne!(plan.flags & DOWNLOAD_FLAG_ADAPTATION, 0);
    }

    /// A VIN change likewise leaves the identity alone.
    #[test]
    fn vin_plan_changes_only_the_vin() {
        let plan = vin_plan(&target(), DONOR_VIN).unwrap();
        assert_eq!(plan.vin, DONOR_VIN);
        assert_eq!(plan.idx_tun, 0x6A);
        assert_eq!(plan.no_key_secu, TARGET_KEY);
        assert!(plan.same_ecu);
    }

    #[test]
    fn a_malformed_vin_is_refused() {
        assert!(vin_plan(&target(), "TOO SHORT").is_err());
    }

    /// A healthy ECU holding the target key clears every blocker â€” but always
    /// carries the adaptation-mode warning, because no download can avoid it.
    #[test]
    fn a_healthy_ecu_has_no_blockers() {
        let plan = adapt_plan(&target(), &donor(), None, None).unwrap();
        let items = preflight(&Ecu::default(), &plan, Some(IDX_LAB));
        assert!(
            !items.is_blocked(),
            "unexpected blockers: {:?}",
            blocker_texts(&items)
        );
        assert!(
            items
                .iter()
                .any(|i| i.message.contains("adaptation mode (stStatFct 4)")),
            "the relearn consequence must always be stated"
        );
    }

    /// The key proof is what stands between a typo and a lockout, so each way
    /// it can fail has to be named distinctly.
    #[test]
    fn key_proof_gates_the_write() {
        let plan = adapt_plan(&target(), &donor(), None, None).unwrap();

        // The ECU holds a key that is neither dump's.
        let stranger = Ecu {
            key: [0xAB; 16],
            ..Default::default()
        };
        assert!(blocker_texts(&preflight(&stranger, &plan, Some(IDX_LAB)))
            .iter()
            .any(|m| m.contains("does not match the target dump")));

        // The ECU already holds the donor key: it is adapted already.
        let already = Ecu {
            key: DONOR_KEY,
            ..Default::default()
        };
        assert!(blocker_texts(&preflight(&already, &plan, Some(IDX_LAB)))
            .iter()
            .any(|m| m.contains("already holds the DONOR key")));

        // The ECU refuses DID 0x2F9: unproven, which is not the same as wrong.
        let silent = Ecu {
            answers_2f9: false,
            ..Default::default()
        };
        assert!(blocker_texts(&preflight(&silent, &plan, Some(IDX_LAB)))
            .iter()
            .any(|m| m.contains("0x2F9 did not answer")));
    }

    /// The anti-tuning interlock fails silently on the ECU â€” the download is
    /// accepted and the car still will not start â€” so preflight has to catch
    /// every way it can trip.
    #[test]
    fn the_tuning_interlock_blocks_the_write() {
        let plan = adapt_plan(&target(), &donor(), None, None).unwrap();

        let disallowed = Ecu {
            extended: p2ff(0x6A, [0x11, 0x22, 0, 0, 0], 0),
            ..Default::default()
        };
        assert!(blocker_texts(&preflight(&disallowed, &plan, Some(IDX_LAB)))
            .iter()
            .any(|m| m.contains("not in this ECU's allow-list")));

        let empty = Ecu {
            extended: p2ff(0x6A, [0; 5], 0),
            ..Default::default()
        };
        assert!(blocker_texts(&preflight(&empty, &plan, Some(IDX_LAB)))
            .iter()
            .any(|m| m.contains("all zeroes")));

        // An unreadable allow-list must block too: an unchecked interlock is
        // not the same as a passed one.
        let silent = Ecu {
            extended: Vec::new(),
            ..Default::default()
        };
        assert!(blocker_texts(&preflight(&silent, &plan, Some(IDX_LAB)))
            .iter()
            .any(|m| m.contains("0x2FF did not answer")));
    }

    /// The download service's own preconditions.
    #[test]
    fn service_preconditions_block_the_write() {
        let plan = adapt_plan(&target(), &donor(), None, None).unwrap();

        let ignition_off = Ecu {
            bits: p2ee(0x00, 0xFC),
            ..Default::default()
        };
        assert!(
            blocker_texts(&preflight(&ignition_off, &plan, Some(IDX_LAB)))
                .iter()
                .any(|m| m.contains("ignition is off"))
        );

        let mut lockout = vec![0u8; 6];
        lockout[0] = 7;
        let locked_out = Ecu {
            lockout,
            ..Default::default()
        };
        assert!(blocker_texts(&preflight(&locked_out, &plan, Some(IDX_LAB)))
            .iter()
            .any(|m| m.contains("download lockout is active with 7")));

        for dead in [10u8, 0x58, 0x63] {
            let ecu = Ecu {
                state: p2ed(dead),
                ..Default::default()
            };
            assert!(
                blocker_texts(&preflight(&ecu, &plan, Some(IDX_LAB)))
                    .iter()
                    .any(|m| m.contains("refused in this state")),
                "stStatFct {dead:#04X} must block"
            );
        }
    }

    /// `idxLab` is production data no download can change, so a mismatch means
    /// the donor car's cluster can never agree with this ECU.
    #[test]
    fn idx_lab_mismatch_is_a_warning_not_a_blocker() {
        let plan = adapt_plan(&target(), &donor(), None, None).unwrap();

        let items = preflight(&Ecu::default(), &plan, Some(0x10));
        assert!(!items.is_blocked());
        assert!(items
            .iter()
            .any(|i| i.message.contains("idxLab differs") && i.message.contains("never agree")));

        // Not knowing it at all still deserves a word.
        let items = preflight(&Ecu::default(), &plan, None);
        assert!(items
            .iter()
            .any(|i| i.message.contains("donor car's idxLab is unknown")));

        // ... but on a same-ECU write there is no donor car, so the warning
        // would be nonsense and must not appear.
        let pclass = pclass_plan(&target(), 0x6A).unwrap();
        let items = preflight(&Ecu::default(), &pclass, None);
        assert!(!items.iter().any(|i| i.message.contains("idxLab")));
    }

    /// Rewriting a record to the values it already holds still costs a relearn,
    /// which is worth saying before someone spends one.
    #[test]
    fn a_no_op_pclass_write_is_flagged() {
        let plan = pclass_plan(&target(), 0x6A).unwrap();
        let items = preflight(&Ecu::default(), &plan, None);
        assert!(items
            .iter()
            .any(|i| i.message.contains("already reports idxTun")));
    }

    /// A stale dump is worth mentioning, but the key proof is what decides.
    #[test]
    fn a_vin_mismatch_is_only_a_warning() {
        let plan = adapt_plan(&target(), &donor(), None, None).unwrap();
        let other_vin = Ecu {
            vin: "WAUZZZ8V1FA000123".into(),
            ..Default::default()
        };
        let items = preflight(&other_vin, &plan, Some(IDX_LAB));
        // The ECU signs the VIN it reported, so the key proof still holds;
        // only the staleness warning should appear.
        assert!(
            !items.is_blocked(),
            "unexpected blockers: {:?}",
            blocker_texts(&items)
        );
        assert!(items
            .iter()
            .any(|i| i.message.contains("the dump is stale")));
    }

    #[test]
    fn the_last_immobilizer_error_is_surfaced() {
        let plan = adapt_plan(&target(), &donor(), None, None).unwrap();
        let errored = Ecu {
            extended: p2ff(0x6A, [0x6A, 0, 0, 0, 0], 0x1D),
            ..Default::default()
        };
        let items = preflight(&errored, &plan, Some(IDX_LAB));
        assert!(items
            .iter()
            .any(|i| i.message.contains("0x1D") && i.message.contains("download failed (CRC)")));
    }

    /// The read order matters: DID 0x2F9 is refused unless services 1/3/4/9 ran
    /// first, and every key proof above depends on it answering.
    #[test]
    fn the_full_did_list_puts_the_prerequisites_first() {
        let cks_at = IMMO_DIDS_FULL
            .iter()
            .position(|&d| d == DID_IDENTITY_CKS)
            .expect("0x2F9 is in the full list");
        for prerequisite in [DID_CHALLENGE, DID_STATE, DID_STATUS_BITS, DID_VIN] {
            let at = IMMO_DIDS_FULL
                .iter()
                .position(|&d| d == prerequisite)
                .unwrap();
            assert!(
                at < cks_at,
                "DID {prerequisite:#06X} must be read before 0x2F9"
            );
        }
    }
}
