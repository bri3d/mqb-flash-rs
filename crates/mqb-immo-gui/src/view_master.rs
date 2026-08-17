//! The master-emulator tab: playing the instrument cluster.
//!
//! The ECU asks on CAN `0x010` and expects an answer on `0x011` within its
//! retry window. Everything the master needs comes out of the ECU's own
//! encrypted NVRAM — `noKeySecu`, `noKeyMst` and `idxTun` — plus `idxLab`,
//! which is not in the record but which a live ECU publishes unauthenticated in
//! DID `0x2ED`.

use iced::widget::{button, column, row, text, Column, Space};
use iced::{Alignment, Element, Length};

use mqb_immo::{describe_ecu_status, ecu_status_hint};

use crate::secrets::{hex, hex_spaced};
use crate::state::{master_key_candidates, MasterKeyMode, Message, State, Which};
use crate::theme;
use crate::view_secrets;
use crate::widgets::{coloured, field, group, panel, MONO};

pub fn view(state: &State) -> Element<'_, Message> {
    let mut col: Column<Message> = column![].spacing(12);

    col = col.push(view_secrets::view(
        state,
        Which::Target,
        "The ECU's secrets",
    ));

    col = col.push(key_panel(state));
    col = col.push(controls(state));

    if let Some(update) = &state.master.latest {
        let status_line = describe_ecu_status(update.ecu_status);
        let pick: fn(&iced::Theme) -> iced::Color = if update.authenticated {
            theme::good
        } else if update.ecu_status.is_some() {
            theme::danger
        } else {
            theme::unknown
        };

        let mut rows = vec![
            coloured(status_line, pick),
            field(
                "Variant",
                update
                    .variant
                    .map(|v| v.label().to_string())
                    .unwrap_or_else(|| "unknown".into()),
            ),
            field("Exchanges", update.exchanges.to_string()),
            field(
                "Master key in use",
                format!(
                    "{}{}",
                    hex(&update.master_key),
                    if update.master_key_confirmed {
                        "  (confirmed by the ECU)"
                    } else {
                        "  (not yet confirmed)"
                    }
                ),
            ),
            field(
                "noKeySlave",
                match update.no_key_slave {
                    Some(value) => format!("{}  (recovered)", hex(&value)),
                    None => "not recovered — only the ECU→master direction uses it".into(),
                },
            ),
            field("Last request", hex_spaced(&update.request)),
            field(
                "Last reply",
                match &update.reply {
                    Some(reply) => hex_spaced(reply),
                    None => "none due".into(),
                },
            ),
        ];

        if let Some(hint) = ecu_status_hint(update.ecu_status) {
            rows.push(coloured(hint, theme::warning));
        }

        col = col.push(group("Exchange", rows));
    }

    if !state.master.frames.is_empty() {
        let log = state
            .master
            .frames
            .iter()
            .rev()
            .take(24)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        col = col.push(panel(
            column![
                row![
                    text("Frames").size(15),
                    Space::new().width(Length::Fill),
                    button(text("Clear").size(12)).on_press(Message::ClearMasterLog),
                ]
                .align_y(Alignment::Center),
                text(log).size(11).font(MONO),
            ]
            .spacing(6),
        ));
    }

    col.into()
}

fn key_panel(state: &State) -> Element<'_, Message> {
    let modes = [
        (
            MasterKeyMode::FromEcu,
            "Read idxLab from the ECU (DID 0x2ED)",
        ),
        (
            MasterKeyMode::Narrow,
            "Narrow the three candidates from traffic",
        ),
        (MasterKeyMode::Manual, "Use a specific key"),
    ];
    let mut picker = column![].spacing(4);
    for (mode, label) in modes {
        picker = picker.push(iced::widget::radio(
            label,
            mode,
            Some(state.master.key_mode()),
            Message::MasterKeyModeChanged,
        ));
    }

    let mut col: Column<Message> = column![text("Master key").size(15), picker].spacing(8);

    if state.master.key_mode() == MasterKeyMode::Manual {
        col = col.push(
            row![
                text("Key").size(12).width(Length::Fixed(60.0)),
                iced::widget::text_input("4 bytes of hex", &state.master.key_hex)
                    .on_input(Message::MasterKeyHexChanged)
                    .width(Length::Fixed(200.0))
                    .size(12)
                    .font(MONO),
                text(format!(
                    "candidates: {}",
                    master_key_candidates().join(", ")
                ))
                .size(11)
                .style(|t: &iced::Theme| iced::widget::text::Style {
                    color: Some(theme::muted(t)),
                }),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        );
    }

    if let Some(idx_lab) = state.reported_idx_lab() {
        col = col.push(field(
            "ECU reports idxLab",
            format!(
                "0x{idx_lab:02X} → {}",
                hex(&mqb_immo::master_key_for_idx_lab(idx_lab))
            ),
        ));
    }

    col = col.push(coloured(
        "idxLab is production data and is not in the immobilizer record, so a dump alone cannot \
         say which of the three master keys applies. A live ECU publishes it in the clear.",
        theme::muted,
    ));

    panel(col)
}

fn controls(state: &State) -> Element<'_, Message> {
    let ready = state.target.is_ready();
    let can_run = state.connection.has_raw_can();

    let start = button(text("Start answering").size(13)).on_press_maybe(
        (!state.master.running && ready && can_run).then_some(Message::StartMasterPressed),
    );
    let stop = button(text("Stop").size(13))
        .on_press_maybe(state.master.running.then_some(Message::StopMasterPressed));

    let mut col: Column<Message> = column![row![start, stop].spacing(10)].spacing(6);

    if !ready {
        col = col.push(coloured(
            "Load the ECU's secrets above before starting.",
            theme::warning,
        ));
    }
    if !can_run {
        col = col.push(coloured(
            "Master emulation needs a connection that exposes raw CAN frames on the powertrain \
             bus. Behind the vehicle gateway, or on a hardware ISO 15765 channel, the ECU's \
             requests on 0x010 are not visible at all.",
            theme::warning,
        ));
    }
    if state.master.running {
        let source = state
            .master
            .key_source
            .clone()
            .unwrap_or_else(|| "unknown".into());
        col = col.push(coloured(
            format!(
                "Answering 0x010 on 0x011 with key {} ({source}).",
                state
                    .master
                    .started_with
                    .map(|k| hex(&k))
                    .unwrap_or_else(|| "…".into())
            ),
            theme::good,
        ));
    }

    panel(col)
}
