//! The live-state tab: what the immobilizer says about itself, right now.
//!
//! Everything here comes from unauthenticated `ReadDataByIdentifier` requests
//! in the default session — no keys, no dump, no SecurityAccess. It therefore
//! works against any ECU on the bus, including one whose NVRAM cannot be read.

use iced::widget::{button, checkbox, column, row, text, Column, Space};
use iced::{Alignment, Element};

use mqb_immo::state::{
    decode_2ed, decode_2ee, decode_2ef, decode_2ff, lock_status, DID_EXTENDED, DID_LOCKOUT,
    DID_STATE, DID_STATUS_BITS,
};
use mqb_immo::{imo_error_name, master_key_for_idx_lab, LockStatus, Severity};

use crate::secrets::{hex, hex_spaced};
use crate::state::{Message, State};
use crate::theme;
use crate::widgets::{coloured, field, gap, group, panel};

pub fn view(state: &State) -> Element<'_, Message> {
    let controls = row![
        button(text("Read now").size(13)).on_press_maybe(
            state
                .connection
                .is_connected()
                .then_some(Message::RefreshPressed)
        ),
        checkbox(state.polling)
            .label("Keep refreshing")
            .on_toggle(Message::PollingToggled)
            .size(15)
            .text_size(12),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    let mut col: Column<Message> = column![controls].spacing(12);

    if let Some(error) = &state.live_error {
        col = col.push(panel(coloured(error.clone(), theme::danger)));
    }

    let Some(live) = state.live.as_ref() else {
        col = col.push(coloured(
            if state.connection.is_connected() {
                "No reading yet — press Read now."
            } else {
                "Connect to an interface to read the immobilizer state."
            },
            theme::muted,
        ));
        return col.into();
    };

    let snapshot = &live.snapshot;
    col = col.push(verdict(live));
    col = col.push(gap(2.0));

    // ── Adaptation status (DID 0x2ED) ─────────────────────────────────────
    if let Some(adapt) = snapshot.raw(DID_STATE).and_then(decode_2ed) {
        let key = master_key_for_idx_lab(adapt.idx_lab);
        col = col.push(group(
            "Adaptation status — DID 0x2ED",
            vec![
                field(
                    "stStatFct",
                    format!(
                        "0x{:02X}  {}",
                        adapt.st_stat_fct,
                        mqb_immo::ImmoState::from_raw(adapt.st_stat_fct).label()
                    ),
                ),
                field("ctDatBasFazit", format!("0x{:02X}", adapt.ct_dat_bas_fazit)),
                field(
                    "idxLab",
                    format!("0x{:02X} → master key {}", adapt.idx_lab, hex(&key)),
                ),
                field("bLimModEna", yes_no(adapt.b_lim_mod_ena)),
            ],
        ));
    }

    // ── Live state (DID 0x2EE) ────────────────────────────────────────────
    if let Some(bits) = snapshot.raw(DID_STATUS_BITS).and_then(decode_2ee) {
        col = col.push(group(
            "Live state — DID 0x2EE",
            vec![
                field("Ignition", if bits.ignition_on { "on" } else { "OFF" }),
                field("bMstRespRx", yes_no(bits.b_mst_resp_rx)),
                field("bMstCksVld", yes_no(bits.b_mst_cks_vld)),
                field("bMstKeyVld", yes_no(bits.b_mst_key_vld)),
                field("stStatFct == 2", yes_no(bits.st_is_2)),
                field("stStatFct != 3", yes_no(bits.st_not_3)),
                field("bInhAcsMem", yes_no(bits.b_inh_acs_mem)),
            ],
        ));
    }

    // ── Lockouts (DID 0x2EF) ──────────────────────────────────────────────
    if let Some(lockout) = snapshot.raw(DID_LOCKOUT).and_then(decode_2ef) {
        let mut rows = vec![
            field(
                "Download lockout",
                minutes(lockout.download_lockout_minutes),
            ),
            field("Login lockout", minutes(lockout.login_lockout_minutes)),
        ];
        if lockout.download_lockout_minutes != 0 || lockout.login_lockout_minutes != 0 {
            rows.push(coloured(
                "A wrong key arms this ladder: 5, 10, 20, 40, 80, 160 then 255 minutes. It \
                 counts down only with the ignition on.",
                theme::warning,
            ));
        }
        col = col.push(group("Lockout timers — DID 0x2EF", rows));
    }

    // ── Snapshot (DID 0x2FF) ──────────────────────────────────────────────
    if let Some(ext) = snapshot.raw(DID_EXTENDED).and_then(decode_2ff) {
        let allow = hex_spaced(&ext.str_var_tun);
        let member = ext.str_var_tun.contains(&ext.idx_tun);
        let mut rows = vec![
            field(
                "Marker",
                format!(
                    "0x{:02X} '{}'{}",
                    ext.marker,
                    ext.marker as char,
                    if ext.is_hardware_sample() {
                        "  — hardware sample"
                    } else {
                        ""
                    }
                ),
            ),
            field("idxTun / PClass", format!("0x{:02X}", ext.idx_tun)),
            field("Allow-list (strVarTun)", allow),
            field("Imo version", ext.version_string()),
            field("ctAuthLos", counter(ext.auth_loss_count())),
            field("ctWrAccNvm", counter(ext.nvm_write_count())),
            field(
                "Last error",
                format!(
                    "0x{:02X}  {}",
                    ext.last_error,
                    imo_error_name(ext.last_error)
                ),
            ),
        ];
        rows.push(if member {
            coloured(
                "idxTun is in the allow-list, so the anti-tuning check passes.",
                theme::good,
            )
        } else {
            coloured(
                "idxTun is NOT in the allow-list. CheckTuning forces stStatFct to 'B' and the \
                 engine will not start; recovery needs noKeySecu, which only exists in a DFlash \
                 dump.",
                theme::danger,
            )
        });
        col = col.push(group("Snapshot — DID 0x2FF", rows));
    }

    // ── Identity ──────────────────────────────────────────────────────────
    let mut identity = Vec::new();
    if let Some(vin) = snapshot.vin() {
        identity.push(field("VIN (0xF190)", vin));
    }
    if let Some(fazit) = snapshot.fazit() {
        identity.push(field("FAZIT (0xF17C)", fazit));
    }
    if let Some(challenge) = snapshot.challenge() {
        identity.push(field("Challenge (0x2E0)", hex_spaced(&challenge)));
    }
    match snapshot.identity_checksum() {
        Some(cks) => identity.push(field("Identity checksum (0x2F9)", hex_spaced(cks))),
        None => identity.push(coloured(
            "DID 0x2F9 did not answer, so no dump's key can be proved against this ECU without \
             risking the lockout ladder.",
            theme::warning,
        )),
    }
    if !identity.is_empty() {
        col = col.push(group("Identity", identity));
    }

    // ── Findings ──────────────────────────────────────────────────────────
    if !live.report.findings.is_empty() {
        let mut rows: Vec<Element<Message>> = Vec::new();
        for finding in &live.report.findings {
            let pick = match finding.severity {
                Severity::Ok => theme::good as fn(&iced::Theme) -> iced::Color,
                Severity::Warn => theme::danger,
                Severity::Unknown => theme::unknown,
            };
            rows.push(coloured(finding.message.clone(), pick));
            rows.push(
                text(finding.detail.clone())
                    .size(11)
                    .style(|t: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme::muted(t)),
                    })
                    .into(),
            );
            rows.push(Space::new().height(4.0).into());
        }
        col = col.push(group("Assessment", rows));
    }

    col.into()
}

/// The one-line answer: is this ECU released, and if not, why not.
fn verdict(live: &crate::connection::LiveState) -> Element<'_, Message> {
    let bits = live.snapshot.raw(DID_STATUS_BITS).and_then(decode_2ee);
    let Some(bits) = bits else {
        return panel(coloured(
            "DID 0x2EE did not answer, so whether the ECU is released cannot be said.",
            theme::unknown,
        ));
    };

    let (headline, reason, pick): (_, _, fn(&iced::Theme) -> iced::Color) = match lock_status(&bits)
    {
        LockStatus::MasterVerified => (
            "UNLOCKED",
            "the ECU has accepted the master — CrcMaster and the PIN both verified. Note that \
             for authentication variants B and C full release also needs a bit DID 0x2EE does \
             not publish.",
            theme::good,
        ),
        LockStatus::IgnitionOff => (
            "LOCKED",
            "the ignition is off; the ECU does not authenticate on bench power alone.",
            theme::unknown,
        ),
        LockStatus::NoMasterReply => (
            "LOCKED",
            "no master reply — nothing is answering on CAN 0x011, which is the normal reading \
             on a bench harness with no cluster.",
            theme::unknown,
        ),
        LockStatus::CrcMasterRejected => (
            "LOCKED",
            "CrcMaster was rejected — the wrong noKeySecu, idxLab or idxTun.",
            theme::danger,
        ),
        LockStatus::PinRejected => (
            "LOCKED",
            "CrcMaster was accepted but the PIN mask was rejected — the wrong noKeyMst.",
            theme::danger,
        ),
    };

    panel(
        column![
            text(headline)
                .size(20)
                .style(move |t: &iced::Theme| iced::widget::text::Style {
                    color: Some(pick(t))
                }),
            text(reason)
                .size(12)
                .style(|t: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme::muted(t)),
                }),
        ]
        .spacing(4),
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn minutes(value: u8) -> String {
    if value == 0 {
        "none".into()
    } else {
        format!("{value} minute(s) remaining")
    }
}

/// The two counters in DID `0x2FF` are quantized, so exact values above 99 do
/// not survive; say so rather than printing a rounded number as if it were one.
fn counter(value: Option<u32>) -> String {
    match value {
        Some(n) if n < 100 => n.to_string(),
        Some(n) => format!("~{n}"),
        None => "saturated (≥ 54 999)".into(),
    }
}
