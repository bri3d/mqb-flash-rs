//! The DFlash tab: decrypt an NVRAM image, read it, and write an edited
//! immobilizer record back.
//!
//! Two layers of CRC and one layer of Hitag2 stand between an edit and a valid
//! image, and the tool fixes all three. An edit is only ever written back after
//! it has been re-read from the staged bytes and confirmed, so a failure leaves
//! the loaded image untouched.

use iced::widget::{button, checkbox, column, row, text, text_input, Column, Space};
use iced::{Alignment, Element, Length};

use mqb_nvcrypt::{Dump, GenerationSource, StStatFct, IMMO_CHANNELS};

use crate::secrets::{hex, hex_spaced};
use crate::state::{Message, State, Which};
use crate::theme;
use crate::view_secrets;
use crate::widgets::{coloured, field, group, panel, MONO};

pub fn view(state: &State) -> Element<'_, Message> {
    let mut col: Column<Message> = column![].spacing(12);

    col = col.push(view_secrets::view(
        state,
        Which::Target,
        "The image and its Device ID",
    ));

    let Some(dump) = state.target.dump.as_ref() else {
        col = col.push(coloured(
            "Choose a DFlash image above. The 'DFlash dump' source is the one this tab works \
             with — a record or hand-entered fields carry no image to edit.",
            theme::muted,
        ));
        return col.into();
    };

    col = col.push(image_summary(dump));
    col = col.push(channel_table(state, dump));

    if state.target.keys.is_some() {
        col = col.push(channel_picker(state));
        if state.dflash.selected_channel.is_some() {
            col = col.push(editor(state));
            col = col.push(save_panel(state));
        }
    }

    col.into()
}

fn image_summary(dump: &Dump) -> Element<'_, Message> {
    let generation = match dump.generation() {
        Some(g) => {
            let source = match g.source {
                GenerationSource::PageHeaderConfirmed => {
                    "page header, confirmed by the record CRCs"
                }
                GenerationSource::PageHeaderDisputed { .. } => {
                    "page header — the record CRCs disagree"
                }
                GenerationSource::PageHeader => "page header",
                GenerationSource::BruteForced => "recovered from the record CRCs",
            };
            format!("0x{:08X}  ({source})", g.value)
        }
        None => "not recoverable — records cannot be validated or rewritten".into(),
    };

    group(
        "Image",
        vec![
            field("Size", format!("{} bytes", dump.bytes().len())),
            field("Records", dump.records().len().to_string()),
            field("Live channels", dump.channels().len().to_string()),
            field("Page headers", dump.page_headers().len().to_string()),
            field("Generation counter", generation),
        ],
    )
}

/// Every live channel, with what each CRC layer says about it.
fn channel_table<'a>(state: &'a State, dump: &'a Dump) -> Element<'a, Message> {
    let keys = state.target.keys;
    let header = row![
        cell("ch", 44.0),
        cell("len", 44.0),
        cell("writes", 56.0),
        cell("record CRC", 92.0),
        cell("content CRC", 96.0),
        cell("content", 320.0),
    ]
    .spacing(6);

    let mut rows: Vec<Element<Message>> = vec![header.into()];
    for channel in dump.channels() {
        let Some(record) = dump.latest(channel) else {
            continue;
        };
        let analysis = dump.analyze(record, keys.as_ref());
        let outer = match analysis.alignment {
            Some(a) => a.label(),
            None => "FAIL",
        };
        let inner = if analysis.encrypted {
            "encrypted"
        } else if analysis.inner_crc.is_some() {
            "ok"
        } else {
            "none"
        };
        let preview: String = analysis
            .content
            .iter()
            .take(40)
            .map(|&b| {
                if (0x20..0x7F).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        rows.push(
            row![
                cell(format!("{channel:02X}"), 44.0),
                cell(record.slot_len().to_string(), 44.0),
                cell(dump.write_count(channel).to_string(), 56.0),
                cell(outer, 92.0),
                cell(inner, 96.0),
                cell(preview, 320.0),
            ]
            .spacing(6)
            .into(),
        );
    }

    let mut col: Column<Message> = column![text("Channels").size(15)].spacing(3);
    for entry in rows {
        col = col.push(entry);
    }
    if keys.is_none() {
        col = col.push(coloured(
            "Without the Device ID the encrypted channels — the immobilizer's among them — show \
             as ciphertext.",
            theme::warning,
        ));
    }
    panel(col)
}

fn channel_picker(state: &State) -> Element<'_, Message> {
    let survey = state.target.survey.as_ref();
    let mut buttons = row![].spacing(8).align_y(Alignment::Center);
    for channel in IMMO_CHANNELS {
        let readable = survey
            .map(|s| s.valid_channels().contains(&channel))
            .unwrap_or(false);
        let label = text(format!("Channel {channel}")).size(12);
        let mut control = button(label);
        if readable && state.dflash.selected_channel != Some(channel) {
            control = control.on_press(Message::DflashChannelSelected(channel));
        }
        buttons = buttons.push(control);
    }

    let mut col: Column<Message> = column![text("Immobilizer record").size(15), buttons].spacing(8);

    if let Some(survey) = survey {
        let valid = survey.valid_channels();
        if valid.is_empty() {
            col = col.push(coloured(
                "None of channels 6, 7 or 8 decrypted — check the Device ID.",
                theme::danger,
            ));
        } else if !survey.copies_agree() {
            col = col.push(coloured(
                format!(
                    "The three copies do not agree: channel(s) {} differ. The firmware votes \
                     between them, so this image is inconsistent.",
                    survey
                        .disagreeing_channels()
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                theme::danger,
            ));
        } else {
            col = col.push(coloured(
                format!(
                    "Channels {} all hold the same identity.",
                    valid
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                theme::good,
            ));
        }
    }

    panel(col)
}

fn editor(state: &State) -> Element<'_, Message> {
    let entry = |label: &'static str,
                 placeholder: &'static str,
                 value: &str,
                 on_input: fn(String) -> Message,
                 width: f32|
     -> Element<'static, Message> {
        row![
            text(label).size(12).width(Length::Fixed(130.0)),
            text_input(placeholder, value)
                .on_input(on_input)
                .width(Length::Fixed(width))
                .size(12)
                .font(MONO),
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .into()
    };

    let mut states = row![].spacing(10).align_y(Alignment::Center);
    for (index, value) in StStatFct::all().iter().enumerate() {
        states = states.push(iced::widget::radio(
            format!("{} — {}", value.numeric(), value.label()),
            index,
            Some(state.dflash.st_stat_index),
            move |i| Message::DflashStStatChanged(StStatFct::all()[i.min(3)]),
        ));
    }

    let mut col: Column<Message> = column![
        text("Edit the record").size(15),
        entry(
            "VIN",
            "17 characters",
            &state.dflash.vin_input,
            Message::DflashVinChanged,
            240.0
        ),
        entry(
            "idxTun / PClass",
            "1 byte of hex",
            &state.dflash.idx_tun_input,
            Message::DflashIdxTunChanged,
            120.0
        ),
        entry(
            "noKeyMst",
            "2 bytes of hex",
            &state.dflash.no_key_mst_input,
            Message::DflashNoKeyMstChanged,
            140.0
        ),
        entry(
            "noKeySecu",
            "16 bytes of hex",
            &state.dflash.no_key_secu_input,
            Message::DflashNoKeySecuChanged,
            340.0
        ),
        entry(
            "ctDatBasFazit",
            "1 byte of hex",
            &state.dflash.ct_fazit_input,
            Message::DflashCtFazitChanged,
            120.0
        ),
        column![text("stStatFct").size(12), states].spacing(4),
    ]
    .spacing(8);

    if let Some(error) = &state.dflash.edit_error {
        col = col.push(coloured(error.clone(), theme::danger));
    }

    if let Some(record) = &state.dflash.edited {
        col = col.push(
            column![
                field(
                    "datStat CRC",
                    crc_line(record.dat_stat_crc(), record.dat_stat_crc_ok())
                ),
                field(
                    "datDat CRC",
                    crc_line(record.dat_dat_crc(), record.dat_dat_crc_ok())
                ),
                field(
                    "VIN copy (CBOOT)",
                    match (record.vin_copy(), record.vin_copy_ok()) {
                        (Some(copy), Some(true)) => format!("{copy}  (matches)"),
                        (Some(copy), _) => format!("{copy}  (stale)"),
                        _ => "absent from this record".into(),
                    }
                ),
                field(
                    "ctDatStat / ctDatDat",
                    format!("{} / {}", record.ct_dat_stat(), record.ct_dat_dat())
                ),
                field(
                    "bInhAcsMem",
                    if record.b_inh_acs_mem() {
                        "set"
                    } else {
                        "clear"
                    }
                ),
                field("bLock", if record.b_lock() { "set" } else { "clear" }),
                field(
                    "bLimModEna",
                    if record.b_lim_mod_ena() {
                        "set"
                    } else {
                        "clear"
                    }
                ),
                field("Encoded record", hex_spaced(&record.encode()[..66])),
            ]
            .spacing(3),
        );
    }

    col = col.push(coloured(
        "Fields not edited here — the write counters, noRndOld, bLock, bInhAcsMem and the flag \
         byte — are carried through byte for byte. Both CCITT CRCs are recomputed on save.",
        theme::muted,
    ));

    col =
        col.push(row![button(text("Revert").size(12)).on_press(Message::DflashRevert)].spacing(8));

    panel(col)
}

fn save_panel(state: &State) -> Element<'_, Message> {
    let ready = state.dflash.edited.is_some() && state.dflash.edit_error.is_none();
    let has_generation = state
        .target
        .dump
        .as_ref()
        .and_then(|d| d.generation())
        .is_some();

    let mut col: Column<Message> = column![text("Save").size(15)].spacing(8);

    col = col.push(coloured(
        "Saving rewrites the immobilizer record in all three of channels 6, 7 and 8 — the \
         firmware votes between them, so leaving one behind would produce an image it \
         disagrees with. The Hitag2 ciphertext, the record CRC and both CCITT CRCs are \
         recomputed; every other channel is left untouched.",
        theme::muted,
    ));

    if !has_generation {
        col = col.push(coloured(
            "The flash generation counter could not be recovered from this image, so no record \
             CRC can be recomputed and nothing can be written back.",
            theme::danger,
        ));
    }

    col = col.push(
        checkbox(state.dflash.confirm_write)
            .label("Write a modified copy of this image")
            .on_toggle(Message::DflashConfirmWriteToggled)
            .size(15)
            .text_size(12),
    );

    let can_save = ready && has_generation && state.dflash.confirm_write;
    col = col.push(
        button(text("Save as…").size(13))
            .on_press_maybe(can_save.then_some(Message::DflashSavePressed)),
    );

    if let Some(result) = &state.dflash.save_result {
        col = col.push(match result {
            Ok(message) => coloured(message.clone(), theme::good),
            Err(error) => coloured(error.clone(), theme::danger),
        });
    }

    panel(col)
}

fn crc_line(value: u16, ok: bool) -> String {
    format!("{value:04X}  {}", if ok { "OK" } else { "FAIL" })
}

fn cell<'a>(body: impl Into<String>, width: f32) -> Element<'a, Message> {
    text(body.into())
        .size(11)
        .font(MONO)
        .width(Length::Fixed(width))
        .into()
}

/// Kept for the hex helper's use in this module's field rendering.
#[allow(dead_code)]
fn unused_hex(bytes: &[u8]) -> String {
    hex(bytes)
}

/// Spacer used when a panel needs separating.
#[allow(dead_code)]
fn spacer<'a>() -> Element<'a, Message> {
    Space::new().height(6.0).into()
}
