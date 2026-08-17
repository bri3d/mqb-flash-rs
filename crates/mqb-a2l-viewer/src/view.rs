use iced::widget::rule::{horizontal as horizontal_rule, vertical as vertical_rule};
use iced::widget::{
    button, checkbox, column, container, mouse_area, pick_list, row, scrollable, text, text_input,
};
use iced::{Alignment, Color, Element, Length, Theme};

use mqb_a2l::CharacteristicType;

use crate::state::{Msg, State};
use crate::theme::*;
use crate::view_compare::view_compare;
use crate::view_single::view_values;
use crate::FILTER_ID;
use crate::MONO;

pub fn view(state: &State) -> Element<'_, Msg> {
    let left = view_left_panel(state);
    let right = view_right_panel(state);

    let divider = mouse_area(
        container(vertical_rule(1))
            .width(8)
            .height(Length::Fill)
            .align_x(Alignment::Center),
    )
    .on_press(Msg::SplitDragStart)
    .interaction(iced::mouse::Interaction::ResizingHorizontally);

    row![
        container(left).width(state.split_x).height(Length::Fill),
        divider,
        container(right)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(10),
    ]
    .into()
}

fn view_left_panel(state: &State) -> Element<'_, Msg> {
    let mut col = column![].spacing(6).padding(8);

    // ── File buttons ────────────────────────────────────────────────
    let a2l_label = if state.loading_a2l {
        "Loading..."
    } else if state.a2l.is_some() {
        "A2L loaded"
    } else {
        "Load A2L"
    };
    let bin_label = if state.loading_bin {
        "Loading..."
    } else if state.binary.is_some() {
        "BIN 1 loaded"
    } else {
        "Load BIN 1"
    };
    col = col.push(
        row![
            button(text(a2l_label).size(13))
                .on_press(Msg::LoadA2l)
                .width(Length::FillPortion(1)),
            button(text(bin_label).size(13))
                .on_press(Msg::LoadBin)
                .width(Length::FillPortion(1)),
        ]
        .spacing(4),
    );

    // BIN 2 button (always available once BIN 1 loaded)
    if state.binary.is_some() {
        let bin2_label = if state.loading_bin2 {
            "Loading..."
        } else if state.binary2.is_some() {
            "BIN 2 loaded"
        } else {
            "Load BIN 2"
        };
        col = col.push(
            button(text(bin2_label).size(13))
                .on_press(Msg::LoadBin2)
                .width(Length::Fill),
        );
    }

    // Show file paths
    if let Some(p) = &state.a2l_path {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        col = col.push(
            text(format!("A2L: {name}"))
                .size(11)
                .color_maybe(None::<Color>),
        );
    }
    if let Some(p) = &state.bin_path {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        col = col.push(text(format!("BIN 1: {name}")).size(11));
    }
    if let Some(p) = &state.bin2_path {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        col = col.push(text(format!("BIN 2: {name}")).size(11));
    }

    // Errors
    if let Some(e) = &state.a2l_error {
        col = col.push(text(e).size(11).color(error_color()));
    }
    if let Some(e) = &state.bin_error {
        col = col.push(text(e).size(11).color(error_color()));
    }
    if let Some(e) = &state.bin2_error {
        col = col.push(text(e).size(11).color(error_color()));
    }

    // Show detected module (if a BIN is loaded)
    if state.binary.is_some() {
        col = col.push(
            container(text(format!("Module: {}", state.module)).size(12)).style(|theme: &Theme| {
                container::Style {
                    text_color: Some(muted_text(theme)),
                    ..Default::default()
                }
            }),
        );
    }

    // ── Compare controls ────────────────────────────────────────────
    if state.binary2.is_some() {
        col = col.push(
            row![checkbox(state.compare_mode)
                .label("Compare")
                .on_toggle(Msg::ToggleCompare)
                .size(14)
                .text_size(13),]
            .spacing(8)
            .align_y(Alignment::Center),
        );
        if state.compare_mode {
            let changed_label = if state.computing_changes {
                "Changed only (computing...)".to_string()
            } else {
                format!("Changed only ({})", state.changed_set.len())
            };
            col = col.push(
                row![checkbox(state.show_changed_only)
                    .label(changed_label)
                    .on_toggle(Msg::ToggleChangedOnly)
                    .size(14)
                    .text_size(13),]
                .spacing(8)
                .align_y(Alignment::Center),
            );
            if !state.axis_changed_values_same.is_empty() {
                let rescale_count = if state.hide_rescale_uniform {
                    state.axis_changed_values_same.len() - state.rescale_uniform.len()
                } else {
                    state.axis_changed_values_same.len()
                };
                let rescale_label = format!("Rescale issues only ({rescale_count})");
                col = col.push(
                    row![checkbox(state.show_rescale_only)
                        .label(rescale_label)
                        .on_toggle(Msg::ToggleRescaleOnly)
                        .size(14)
                        .text_size(13),]
                    .spacing(8)
                    .align_y(Alignment::Center),
                );
                if state.show_rescale_only && !state.rescale_uniform.is_empty() {
                    let uniform_label =
                        format!("Hide uniform ({} hidden)", state.rescale_uniform.len());
                    col = col.push(
                        container(
                            row![checkbox(state.hide_rescale_uniform)
                                .label(uniform_label)
                                .on_toggle(Msg::ToggleHideUniform)
                                .size(14)
                                .text_size(12),]
                            .spacing(8)
                            .align_y(Alignment::Center),
                        )
                        .padding(iced::Padding {
                            top: 0.0,
                            right: 0.0,
                            bottom: 0.0,
                            left: 20.0,
                        }),
                    );
                }
            }
        }
    }

    // Axis filter indicator
    if let Some(axis_name) = &state.axis_filter {
        col = col.push(
            row![
                container(text(format!("Axis: {axis_name}")).size(12).font(MONO)).style(
                    |theme: &Theme| container::Style {
                        text_color: Some(tag_color_curve(theme)),
                        ..Default::default()
                    }
                ),
                button(text("X").size(11)).on_press(Msg::ClearAxisFilter),
            ]
            .spacing(4)
            .align_y(Alignment::Center),
        );
    }

    // Category selector
    if !state.categories.is_empty() {
        let cat_row = if state.selected_category.is_some() {
            row![
                pick_list(
                    state.categories.clone(),
                    state.selected_category.clone(),
                    Msg::CategoryChanged,
                )
                .text_size(12)
                .width(Length::Fill),
                button(text("X").size(11)).on_press(Msg::ClearCategory),
            ]
            .spacing(4)
            .align_y(Alignment::Center)
        } else {
            row![pick_list(
                state.categories.clone(),
                state.selected_category.clone(),
                Msg::CategoryChanged,
            )
            .text_size(12)
            .placeholder("All categories")
            .width(Length::Fill),]
            .spacing(4)
            .align_y(Alignment::Center)
        };
        col = col.push(cat_row);
    }

    col = col.push(horizontal_rule(1));

    // Filter
    col = col.push(
        text_input("Search characteristics...", &state.filter)
            .on_input(Msg::FilterChanged)
            .id(FILTER_ID)
            .size(13),
    );

    // Count
    if state.a2l.is_some() {
        let label = if state.total_matches == state.filtered.len() {
            format!("{} characteristics", state.total_matches)
        } else {
            format!(
                "{} shown / {} matching",
                state.filtered.len(),
                state.total_matches
            )
        };
        col = col.push(text(label).size(11));
    }

    // Characteristic list
    if let Some(a2l) = &state.a2l {
        let show_changed_dot = state.compare_mode && !state.changed_set.is_empty();
        let mut list_col = column![].spacing(1);
        for &idx in &state.filtered {
            let ch = &a2l.characteristics[idx];
            let is_selected = state.selected == Some(idx);
            let is_changed = show_changed_dot && state.changed_set.contains(&idx);
            let is_rescale_suspect =
                show_changed_dot && state.axis_changed_values_same.contains(&idx);
            let type_tag = match ch.char_type {
                CharacteristicType::Value => "V",
                CharacteristicType::Curve => "C",
                CharacteristicType::Map => "M",
                CharacteristicType::ValBlk => "B",
                CharacteristicType::Ascii => "A",
                CharacteristicType::Cuboid => "3",
                _ => "?",
            };
            let char_type = ch.char_type;
            let has_desc = !ch.description.is_empty();

            let row_content: Element<'_, Msg> = if is_selected {
                let mut name_row = row![text(type_tag)
                    .size(11)
                    .font(MONO)
                    .color(Color::WHITE)
                    .width(16),]
                .spacing(4)
                .align_y(Alignment::Center);
                if is_rescale_suspect {
                    name_row = name_row.push(
                        text("!!")
                            .size(10)
                            .font(MONO)
                            .color(Color::from_rgb(1.0, 0.3, 0.6)),
                    );
                } else if is_changed {
                    name_row =
                        name_row.push(text("●").size(8).color(Color::from_rgb(1.0, 0.85, 0.4)));
                }
                name_row = name_row.push(text(&ch.name).size(12).color(Color::WHITE));

                let mut item_col = column![name_row].spacing(0);
                if has_desc {
                    item_col = item_col.push(
                        text(&ch.description)
                            .size(10)
                            .color(Color::from_rgba(1.0, 1.0, 1.0, 0.7)),
                    );
                }
                item_col.into()
            } else {
                let mut name_row = row![container(text(type_tag).size(11).font(MONO).width(16))
                    .style(move |theme: &Theme| {
                        let c = match char_type {
                            CharacteristicType::Value => tag_color_value(theme),
                            CharacteristicType::Curve => tag_color_curve(theme),
                            CharacteristicType::Map => tag_color_map(theme),
                            _ => tag_color_other(theme),
                        };
                        container::Style {
                            text_color: Some(c),
                            ..Default::default()
                        }
                    }),]
                .spacing(4)
                .align_y(Alignment::Center);
                if is_rescale_suspect {
                    name_row = name_row.push(container(text("!!").size(10).font(MONO)).style(
                        move |theme: &Theme| container::Style {
                            text_color: Some(rescale_warning_color(theme)),
                            ..Default::default()
                        },
                    ));
                } else if is_changed {
                    name_row =
                        name_row.push(container(text("●").size(8)).style(move |theme: &Theme| {
                            container::Style {
                                text_color: Some(changed_indicator_color(theme)),
                                ..Default::default()
                            }
                        }));
                }
                name_row = name_row.push(text(&ch.name).size(12));

                let mut item_col = column![name_row].spacing(0);
                if has_desc {
                    item_col = item_col.push(container(text(&ch.description).size(10)).style(
                        |theme: &Theme| container::Style {
                            text_color: Some(muted_text(theme)),
                            ..Default::default()
                        },
                    ));
                }
                item_col.into()
            };

            let sel_bg = selected_bg();
            let item = mouse_area(
                container(row_content)
                    .style(move |_theme: &Theme| container::Style {
                        background: if is_selected {
                            Some(sel_bg.into())
                        } else {
                            None
                        },
                        ..Default::default()
                    })
                    .padding([3, 4])
                    .width(Length::Fill),
            )
            .on_press(Msg::SelectChar(idx));

            list_col = list_col.push(item);
        }
        col = col.push(
            scrollable(list_col)
                .id(crate::CHAR_LIST_ID)
                .height(Length::Fill),
        );
    }

    col.into()
}

fn view_right_panel(state: &State) -> Element<'_, Msg> {
    let Some(a2l) = &state.a2l else {
        return container(text("Load an A2L file to get started.").size(14))
            .center(Length::Fill)
            .into();
    };
    let Some(idx) = state.selected else {
        return container(text("Select a characteristic from the list.").size(14))
            .center(Length::Fill)
            .into();
    };

    let ch = &a2l.characteristics[idx];
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let unit = cm.map(|c| c.unit.as_str()).unwrap_or("");
    let fmt = ch.format.as_deref().unwrap_or("");

    let mut col = column![].spacing(6);

    // Header
    col = col.push(text(&ch.name).size(18));
    if !ch.description.is_empty() {
        col = col.push(
            container(text(&ch.description).size(12)).style(|theme: &Theme| container::Style {
                text_color: Some(muted_text(theme)),
                ..Default::default()
            }),
        );
    }

    // Show category if known
    if let Some(cats) = state.char_to_cats.get(&idx) {
        let cat_text = cats.join(", ");
        col = col.push(
            container(text(format!("Section: {cat_text}")).size(11)).style(|theme: &Theme| {
                container::Style {
                    text_color: Some(muted_text(theme)),
                    ..Default::default()
                }
            }),
        );
    }

    col = col.push(
        row![
            text(format!("{:?}", ch.char_type)).size(12).font(MONO),
            text(format!("{:#010X}", ch.address)).size(12).font(MONO),
            text(format!("unit={unit}")).size(12),
            text(format!("fmt={fmt}")).size(12),
        ]
        .spacing(12),
    );

    // Show axis references as clickable links
    let axis_labels = ["X", "Y", "Z"];
    for (ai, ax) in ch.axes.iter().enumerate() {
        if let Some(ref pts_name) = ax.axis_pts_ref {
            let ax_unit = a2l
                .compu_methods
                .get(&ax.compu_method_ref)
                .map(|c| c.unit.as_str())
                .unwrap_or("");
            let label = axis_labels.get(ai).unwrap_or(&"?");
            let axis_name = pts_name.clone();
            col = col.push(
                row![
                    text(format!("{label}-axis:")).size(11),
                    button(text(pts_name).size(11).font(MONO))
                        .on_press(Msg::FilterByAxis(axis_name))
                        .padding([1, 6])
                        .style(button::secondary),
                    container(text(format!("({ax_unit})")).size(11)).style(|theme: &Theme| {
                        container::Style {
                            text_color: Some(muted_text(theme)),
                            ..Default::default()
                        }
                    }),
                ]
                .spacing(6)
                .align_y(Alignment::Center),
            );
        }
    }

    col = col.push(horizontal_rule(1));

    // Values — single mode or compare mode
    if state.compare_mode && state.binary2.is_some() {
        // View options toolbar
        let pct_btn = button(text("%").size(12).font(MONO))
            .on_press(Msg::TogglePercent)
            .padding([2, 8])
            .style(if state.show_percent {
                button::primary
            } else {
                button::secondary
            });
        let toolbar = row![
            pct_btn,
            text("P").size(10).color(Color::from_rgb(0.45, 0.45, 0.45)),
        ]
        .spacing(4)
        .align_y(Alignment::Center);
        col = col.push(toolbar);

        // Compare mode
        if state.binary.is_none() {
            col = col.push(
                container(text("Load firmware binary 1 to view values.").size(13)).style(
                    |theme: &Theme| container::Style {
                        text_color: Some(warning_color(theme)),
                        ..Default::default()
                    },
                ),
            );
        } else {
            let is_rescale_suspect = state
                .selected
                .map(|i| state.axis_changed_values_same.contains(&i))
                .unwrap_or(false);
            col = col.push(view_compare(
                &state.cached_values,
                &state.cached_values2,
                ch,
                a2l,
                is_rescale_suspect,
                state.show_percent,
            ));
        }
    } else {
        // Single mode
        if state.binary.is_none() {
            col = col.push(
                container(text("Load a firmware binary to view values.").size(13)).style(
                    |theme: &Theme| container::Style {
                        text_color: Some(warning_color(theme)),
                        ..Default::default()
                    },
                ),
            );
        } else if let Some(values) = &state.cached_values {
            col = col.push(view_values(values, ch, a2l));
        } else {
            col = col.push(
                text("Could not read this characteristic.")
                    .size(13)
                    .color(error_color()),
            );
        }
    }

    scrollable(col).into()
}
