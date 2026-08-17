//! The identity tab: writing a new immobilizer record over UDS.
//!
//! One `2E 02 E2` write carries the VIN, `noKeySecu`, `idxTun`, the flags and
//! `ctDatBasFazit`, encrypted under the key the ECU holds **now**. It needs no
//! login and no SecurityAccess — possession of that key is the authorisation.
//!
//! The record has no slot for `noKeyMst`, and the flags byte cannot drop bit 7,
//! so every download leaves the ECU in `stStatFct` 4 waiting to be told the PIN.
//! That second step is deliberately **not** part of this screen: a tester
//! connected through the vehicle gateway cannot see CAN `0x010`/`0x011` and so
//! cannot supply it. The car's own cluster does it on the next ignition cycle;
//! on a bench, the master tab does.

use iced::widget::{button, checkbox, column, row, text, text_input, Column, Space};
use iced::{Alignment, Element, Length};

use mqb_immo::adapt::PreflightExt;
use mqb_immo::PreflightLevel;

use crate::secrets::{hex, hex_spaced};
use crate::state::{IdentityMode, Message, State, Tab, Which};
use crate::theme;
use crate::view_secrets;
use crate::widgets::{coloured, field, group, panel, MONO};

pub fn view(state: &State) -> Element<'_, Message> {
    let mut col: Column<Message> = column![].spacing(12);

    // What kind of write.
    let mut modes = column![].spacing(4);
    for mode in IdentityMode::ALL {
        modes = modes.push(iced::widget::radio(
            mode.label(),
            mode,
            Some(state.identity_mode),
            Message::IdentityModeChanged,
        ));
    }
    col = col.push(panel(
        column![text("What to write").size(15), modes, mode_note(state)].spacing(8),
    ));

    // Where the keys come from.
    col = col.push(view_secrets::view(
        state,
        Which::Target,
        "The ECU on the bus (its current key encrypts the write)",
    ));
    if state.identity_mode == IdentityMode::Transplant {
        col = col.push(view_secrets::view(
            state,
            Which::Donor,
            "The donor identity to write onto it",
        ));
    }

    col = col.push(overrides(state));
    col = col.push(
        button(text("Build the download").size(13))
            .on_press_maybe(state.target.is_ready().then_some(Message::BuildPlanPressed)),
    );

    if let Some(error) = &state.plan_error {
        col = col.push(panel(coloured(error.clone(), theme::warning)));
    }

    if let Some(plan) = &state.plan {
        col = col.push(plan_panel(state, plan));
        col = col.push(preflight_panel(state));
        col = col.push(send_panel(state));
    }

    if let Some(result) = &state.download_result {
        col = col.push(match result {
            Ok(message) => panel(
                column![
                    coloured(message.clone(), theme::good),
                    coloured(
                        "The change lives in ImoDat's RAM copy only. Power the ECU down cleanly \
                         so it is written to NVRAM — pulling power loses it.",
                        theme::warning,
                    ),
                ]
                .spacing(4),
            ),
            Err(error) => panel(coloured(
                format!("The ECU rejected the download: {error}"),
                theme::danger,
            )),
        });
    }

    col.into()
}

fn mode_note(state: &State) -> Element<'_, Message> {
    coloured(
        match state.identity_mode {
            IdentityMode::Transplant => {
                "Moves the donor's whole identity — VIN, noKeySecu, idxTun, flags and \
                 ctDatBasFazit — onto the ECU on the bus. idxLab, noKeySlave, bLock and \
                 bInhAcsMem cannot be moved."
            }
            IdentityMode::PowerClass => {
                "The download service is the only way to write idxTun, so a power-class change \
                 rewrites the whole record with every other field left as it stands."
            }
            IdentityMode::Vin => {
                "Rewrites the immobilizer record's VIN. Other NVRAM channels carrying vehicle \
                 identity are untouched."
            }
        },
        theme::muted,
    )
}

fn overrides(state: &State) -> Element<'_, Message> {
    let mut rows: Vec<Element<Message>> = Vec::new();

    let wants_idx_tun = state.identity_mode != IdentityMode::Vin;
    if wants_idx_tun {
        let hint = match (state.reported_idx_tun(), state.reported_allow_list()) {
            (Some(current), Some(allow)) => format!(
                "ECU reports 0x{current:02X}; allow-list {}",
                hex_spaced(&allow)
            ),
            _ => "connect and refresh to see the ECU's allow-list".into(),
        };
        rows.push(
            row![
                text("idxTun / PClass").size(12).width(Length::Fixed(130.0)),
                text_input(
                    if state.identity_mode == IdentityMode::PowerClass {
                        "the new value, in hex"
                    } else {
                        "blank = keep the donor's"
                    },
                    &state.idx_tun_input
                )
                .on_input(Message::IdxTunChanged)
                .width(Length::Fixed(140.0))
                .size(12)
                .font(MONO),
                text(hint)
                    .size(11)
                    .style(|t: &iced::Theme| iced::widget::text::Style {
                        color: Some(theme::muted(t)),
                    }),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
        );
    }

    if state.identity_mode != IdentityMode::PowerClass {
        rows.push(
            row![
                text("VIN").size(12).width(Length::Fixed(130.0)),
                text_input(
                    if state.identity_mode == IdentityMode::Vin {
                        "the new VIN, 17 characters"
                    } else {
                        "blank = keep the donor's"
                    },
                    &state.vin_input
                )
                .on_input(Message::VinChanged)
                .width(Length::Fixed(240.0))
                .size(12)
                .font(MONO),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
        );
    }

    if state.identity_mode == IdentityMode::Transplant {
        rows.push(
            row![
                text("Donor idxLab").size(12).width(Length::Fixed(130.0)),
                text_input(
                    "read DID 0x2ED on the donor car",
                    &state.donor_idx_lab_input
                )
                .on_input(Message::DonorIdxLabChanged)
                .width(Length::Fixed(140.0))
                .size(12)
                .font(MONO),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .into(),
        );
        rows.push(coloured(
            "idxLab selects the master key both sides hash. It is production data, so no \
             download can change it — if the donor car's differs, that car's cluster and this \
             ECU can never agree.",
            theme::muted,
        ));
    }

    panel(column![text("Values").size(15)].spacing(8).extend(rows))
}

fn plan_panel<'a>(state: &'a State, plan: &'a mqb_immo::DownloadPlan) -> Element<'a, Message> {
    let target = state.target.secrets.as_ref();
    let change = |label: &'static str, before: String, after: String| -> Element<'a, Message> {
        let changed = before != after;
        let line = format!(
            "{before}  →  {after}{}",
            if changed { "   [change]" } else { "" }
        );
        if changed {
            coloured(format!("{label:<16}{line}"), theme::warning)
        } else {
            field(label, line)
        }
    };

    let mut rows = Vec::new();
    if let Some(target) = target {
        rows.push(change("VIN", target.vin.clone(), plan.vin.clone()));
        rows.push(change(
            "noKeySecu",
            hex(&target.no_key_secu),
            hex(&plan.no_key_secu),
        ));
        rows.push(change(
            "idxTun",
            format!("{:02X}", target.idx_tun),
            format!("{:02X}", plan.idx_tun),
        ));
        rows.push(change(
            "ctDatBasFazit",
            format!("{:02X}", target.ct_dat_bas_fazit),
            format!("{:02X}", plan.ct_dat_bas_fazit),
        ));
    }
    rows.push(field(
        "Flags",
        format!("{:02X}   {}", plan.flags, plan.flag_names().join(", ")),
    ));
    rows.push(field(
        "Command",
        format!("{}   {}", plan.command.raw(), plan.command.label()),
    ));
    rows.push(field(
        "noKeyMst",
        format!(
            "{:04X}  — no slot in the record; learned over CAN afterwards",
            plan.no_key_mst
        ),
    ));
    rows.push(field("Encrypted under", hex(&plan.encrypted_under)));
    rows.push(field("Plaintext", hex(&plan.plaintext)));
    rows.push(field("Request", hex(&plan.request_frame())));

    group("The download", rows)
}

fn preflight_panel(state: &State) -> Element<'_, Message> {
    if state.preflight.is_empty() {
        return panel(coloured(
            "No checks were run, because there is no live reading of the ECU. Connect and \
             refresh the Live tab before sending anything.",
            theme::warning,
        ));
    }

    let mut rows: Vec<Element<Message>> = Vec::new();
    for item in &state.preflight {
        let pick: fn(&iced::Theme) -> iced::Color = match item.level {
            PreflightLevel::Blocker => theme::danger,
            PreflightLevel::Warning => theme::warning,
        };
        let prefix = match item.level {
            PreflightLevel::Blocker => "BLOCKER  ",
            PreflightLevel::Warning => "warning  ",
        };
        rows.push(coloured(format!("{prefix}{}", item.message), pick));
    }
    if state.preflight.blockers().is_empty() {
        rows.push(coloured("No blockers.", theme::good));
    }
    group("Preflight", rows)
}

fn send_panel(state: &State) -> Element<'_, Message> {
    let blocked = !state.preflight.blockers().is_empty();
    // No preflight items at all means no live reading was available — nothing
    // was checked, which is not the same as everything passing.
    let unchecked = state.preflight.is_empty();
    let connected = state.connection.is_connected();

    let mut col: Column<Message> = column![].spacing(8);

    col = col.push(coloured(
        "This write leaves the ECU in adaptation mode. It will not start until a master \
         supplies noKeyMst — the car's own cluster on the next ignition cycle, or the Master \
         tab if this tool is on the powertrain bus.",
        theme::warning,
    ));

    if !state.connection.has_raw_can() {
        col = col.push(coloured(
            "This connection cannot play the master, so the PIN step will have to be done by \
             the car's cluster.",
            theme::muted,
        ));
    }

    // The label has to say what is actually being agreed to. "I have read the
    // checks" is a lie when there were none.
    let confirm_label = if blocked {
        "Send anyway, over the blockers above"
    } else if unchecked {
        "Send with nothing checked against a live ECU"
    } else {
        "I have read the plan and the checks above"
    };
    col = col.push(
        checkbox(state.confirm_download)
            .label(confirm_label)
            .on_toggle(Message::ConfirmDownloadToggled)
            .size(15)
            .text_size(12),
    );

    let can_send = connected && state.confirm_download && !state.sending;
    let label = if state.sending {
        "Sending…"
    } else {
        "Send the download"
    };
    col = col.push(
        row![
            button(text(label).size(13))
                .on_press_maybe(can_send.then_some(Message::SendDownloadPressed)),
            Space::new().width(10.0),
            button(text("Go to the master tab").size(12))
                .on_press(Message::TabSelected(Tab::Master)),
        ]
        .align_y(Alignment::Center),
    );

    if !connected {
        col = col.push(coloured("Not connected.", theme::muted));
    }
    if unchecked {
        col = col.push(coloured(
            "Nothing has been checked against a live ECU: neither the key, nor the ignition, \
             nor the anti-tuning allow-list.",
            theme::danger,
        ));
    }

    panel(col)
}
