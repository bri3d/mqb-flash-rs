//! The shared "where do this ECU's secrets come from" panel.
//!
//! Used by three tabs, so it is one widget rather than three near-copies.

use iced::widget::{button, column, row, text, text_input, Column, Space};
use iced::{Alignment, Element, Length};

use crate::secrets::{hex, SourceKind};
use crate::state::{ManualField, Message, State, Which};
use crate::theme;
use crate::widgets::{coloured, field, panel, MONO};

pub fn view<'a>(state: &'a State, which: Which, title: &'a str) -> Element<'a, Message> {
    let source = state.source(which);

    let mut kinds = row![].spacing(10).align_y(Alignment::Center);
    for kind in SourceKind::ALL {
        kinds = kinds.push(iced::widget::radio(
            kind.label(),
            kind,
            Some(source.kind()),
            move |k| Message::SourceKindChanged(which, k),
        ));
    }

    let body: Element<Message> = match source.kind() {
        SourceKind::Dump => dump_inputs(state, which),
        SourceKind::Record => record_inputs(state, which),
        SourceKind::Manual => manual_inputs(state, which),
    };

    let mut col: Column<Message> = column![text(title).size(15), kinds, body].spacing(8);

    if let Some(note) = &source.note {
        col = col.push(coloured(note.clone(), theme::muted));
    }
    if let Some(error) = &source.error {
        col = col.push(coloured(error.clone(), theme::danger));
    }

    if let Some(secrets) = &source.secrets {
        col = col.push(
            column![
                field("VIN", secrets.vin.clone()),
                field("noKeySecu", hex(&secrets.no_key_secu)),
                field("noKeyMst", format!("{:04X}", secrets.no_key_mst)),
                field("idxTun / PClass", format!("0x{:02X}", secrets.idx_tun)),
                field(
                    "ctDatBasFazit",
                    format!("0x{:02X}", secrets.ct_dat_bas_fazit)
                ),
                field(
                    "stStatFct",
                    format!(
                        "{}  ({})",
                        secrets.st_stat_fct.numeric(),
                        secrets.st_stat_fct.label()
                    )
                ),
                field(
                    "Source channel",
                    match secrets.channel {
                        Some(c) => format!("NVRAM channel {c}"),
                        None => "not from a dump".into(),
                    }
                ),
            ]
            .spacing(3),
        );
    }

    panel(col)
}

fn dump_inputs(state: &State, which: Which) -> Element<'_, Message> {
    let source = state.source(which);
    let dump_label = source
        .dump_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "no DFlash image chosen".into());
    let pflash_label = source
        .pflash_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "or read it from a program-flash dump".into());

    column![
        row![
            button(text("Choose DFlash image…").size(12)).on_press(Message::BrowseDump(which)),
            text(dump_label).size(11).font(MONO),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
        row![
            text("Device ID").size(12).width(Length::Fixed(80.0)),
            text_input("12 bytes of hex", &source.device_id_hex)
                .on_input(move |v| Message::DeviceIdChanged(which, v))
                .width(Length::Fixed(280.0))
                .size(12)
                .font(MONO),
            button(text("From program flash…").size(12)).on_press(Message::BrowsePflash(which)),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
        text(pflash_label)
            .size(11)
            .style(|t: &iced::Theme| iced::widget::text::Style {
                color: Some(theme::muted(t)),
            }),
        coloured(
            "The Device ID keys the encrypted NVRAM channels, so a dump alone is not enough. A \
             bank-0 program-flash read of the same ECU contains a copy.",
            theme::muted,
        ),
    ]
    .spacing(6)
    .into()
}

fn record_inputs(state: &State, which: Which) -> Element<'_, Message> {
    let source = state.source(which);
    column![
        text_input(
            "datStat + datDat as hex — 66 bytes or more",
            &source.record_hex
        )
        .on_input(move |v| Message::RecordHexChanged(which, v))
        .width(Length::Fill)
        .size(12)
        .font(MONO),
        coloured(
            "An already-decrypted record needs no Device ID. Its datDat CRC-16 is checked, so a \
             mistyped record is refused rather than used.",
            theme::muted,
        ),
    ]
    .spacing(6)
    .into()
}

fn manual_inputs(state: &State, which: Which) -> Element<'_, Message> {
    let manual = &state.source(which).manual;
    let entry = move |label: &'static str,
                      placeholder: &'static str,
                      value: &str,
                      which_field: ManualField|
          -> Element<'static, Message> {
        row![
            text(label).size(12).width(Length::Fixed(120.0)),
            text_input(placeholder, value)
                .on_input(move |v| Message::ManualFieldChanged(which, which_field, v))
                .width(Length::Fixed(340.0))
                .size(12)
                .font(MONO),
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
    };

    column![
        entry(
            "noKeySecu",
            "16 bytes of hex",
            &manual.no_key_secu,
            ManualField::NoKeySecu
        ),
        entry(
            "noKeyMst",
            "2 bytes of hex, e.g. afbb",
            &manual.no_key_mst,
            ManualField::NoKeyMst
        ),
        entry(
            "idxTun",
            "1 byte of hex, e.g. 6a",
            &manual.idx_tun,
            ManualField::IdxTun
        ),
        entry("VIN", "17 characters", &manual.vin, ManualField::Vin),
        entry(
            "ctDatBasFazit",
            "1 byte of hex (default 01)",
            &manual.ct_dat_bas_fazit,
            ManualField::CtDatBasFazit
        ),
        Space::new().height(2.0),
        coloured(
            "Hand-entered fields carry no record flags — bAuthMute, bVldChkDi, bTrigFctDi and \
             bLimModEna are written clear. Use a dump or a record if those matter.",
            theme::warning,
        ),
    ]
    .spacing(6)
    .into()
}
