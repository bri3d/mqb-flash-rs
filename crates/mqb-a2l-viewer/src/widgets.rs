use iced::widget::rule::horizontal as horizontal_rule;
use iced::widget::{column, container, row, text};
use iced::Theme;

use crate::state::Msg;
use crate::theme::{diff_cell_colors, map_cell_colors, map_header_colors};
use crate::MONO;

/// Build a 2D map table (X header + Y×X data grid) as a column.
pub fn map_table<'a>(
    x: &[f64],
    y: &[f64],
    data: &[Vec<f64>],
    lower: f64,
    upper: f64,
) -> iced::widget::Column<'a, Msg> {
    let cell_w: f32 = 80.0;

    // X-axis header row
    let mut header = row![].spacing(0);
    header = header.push(
        container(text("").size(11))
            .width(cell_w)
            .style(|theme: &Theme| {
                let (bg, _) = map_header_colors(theme);
                container::Style {
                    background: Some(bg.into()),
                    ..Default::default()
                }
            }),
    );
    for xi in x {
        let v = format_val(*xi);
        header = header.push(
            container(text(v).size(11).font(MONO))
                .width(cell_w)
                .align_x(iced::alignment::Horizontal::Right)
                .padding([0, 4])
                .style(|theme: &Theme| {
                    let (bg, fg) = map_header_colors(theme);
                    container::Style {
                        background: Some(bg.into()),
                        text_color: Some(fg),
                        ..Default::default()
                    }
                }),
        );
    }
    let mut tbl = column![header, horizontal_rule(1)].spacing(0);

    // Data rows
    for (yi_idx, yi) in y.iter().enumerate() {
        let mut data_row = row![].spacing(0);
        data_row = data_row.push(
            container(text(format_val(*yi)).size(11).font(MONO))
                .width(cell_w)
                .align_x(iced::alignment::Horizontal::Right)
                .padding([0, 4])
                .style(|theme: &Theme| {
                    let (bg, fg) = map_header_colors(theme);
                    container::Style {
                        background: Some(bg.into()),
                        text_color: Some(fg),
                        ..Default::default()
                    }
                }),
        );
        if let Some(row_data) = data.get(yi_idx) {
            for val in row_data {
                let intensity = ((*val - lower) / (upper - lower).max(1e-9)).clamp(0.0, 1.0) as f32;
                let v = format_val(*val);
                data_row = data_row.push(
                    container(text(v).size(11).font(MONO))
                        .width(cell_w)
                        .align_x(iced::alignment::Horizontal::Right)
                        .padding([0, 4])
                        .style(move |theme: &Theme| {
                            let (bg, fg) = map_cell_colors(intensity, theme);
                            container::Style {
                                background: Some(bg.into()),
                                text_color: Some(fg),
                                ..Default::default()
                            }
                        }),
                );
            }
        }
        tbl = tbl.push(data_row);
    }
    tbl
}

/// Like `map_table`, but colors axis headers based on diff from old axis values.
/// `x_old`/`y_old` may differ in length from `x`/`y` — only matching indices are compared.
pub fn map_table_with_axis_diff<'a>(
    x_old: &[f64],
    y_old: &[f64],
    x: &[f64],
    y: &[f64],
    data: &[Vec<f64>],
    lower: f64,
    upper: f64,
) -> iced::widget::Column<'a, Msg> {
    let cell_w: f32 = 80.0;

    // X-axis header row
    let mut header = row![].spacing(0);
    header = header.push(
        container(text("").size(11))
            .width(cell_w)
            .style(|theme: &Theme| {
                let (bg, _) = map_header_colors(theme);
                container::Style {
                    background: Some(bg.into()),
                    ..Default::default()
                }
            }),
    );
    for (xi_idx, xi) in x.iter().enumerate() {
        let v = format_val(*xi);
        let pct = x_old
            .get(xi_idx)
            .map(|old| pct_diff(*old, *xi))
            .unwrap_or(f64::INFINITY);
        let changed = pct.abs() > 0.001;
        header = header.push(
            container(text(v).size(11).font(MONO))
                .width(cell_w)
                .align_x(iced::alignment::Horizontal::Right)
                .padding([0, 4])
                .style(move |theme: &Theme| {
                    if changed {
                        let (bg, fg) = diff_cell_colors(pct, theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    } else {
                        let (bg, fg) = map_header_colors(theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    }
                }),
        );
    }
    let mut tbl = column![header, horizontal_rule(1)].spacing(0);

    // Data rows
    for (yi_idx, yi) in y.iter().enumerate() {
        let mut data_row = row![].spacing(0);
        let y_pct = y_old
            .get(yi_idx)
            .map(|old| pct_diff(*old, *yi))
            .unwrap_or(f64::INFINITY);
        let y_changed = y_pct.abs() > 0.001;
        data_row = data_row.push(
            container(text(format_val(*yi)).size(11).font(MONO))
                .width(cell_w)
                .align_x(iced::alignment::Horizontal::Right)
                .padding([0, 4])
                .style(move |theme: &Theme| {
                    if y_changed {
                        let (bg, fg) = diff_cell_colors(y_pct, theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    } else {
                        let (bg, fg) = map_header_colors(theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    }
                }),
        );
        if let Some(row_data) = data.get(yi_idx) {
            for val in row_data {
                let intensity = ((*val - lower) / (upper - lower).max(1e-9)).clamp(0.0, 1.0) as f32;
                let v = format_val(*val);
                data_row = data_row.push(
                    container(text(v).size(11).font(MONO))
                        .width(cell_w)
                        .align_x(iced::alignment::Horizontal::Right)
                        .padding([0, 4])
                        .style(move |theme: &Theme| {
                            let (bg, fg) = map_cell_colors(intensity, theme);
                            container::Style {
                                background: Some(bg.into()),
                                text_color: Some(fg),
                                ..Default::default()
                            }
                        }),
                );
            }
        }
        tbl = tbl.push(data_row);
    }
    tbl
}

/// Diff map table: shows BIN 2 values (or % change) colored by difference from BIN 1.
/// Axis headers are also colored by diff from old axis values.
pub fn diff_map_table_with_axis_diff<'a>(
    x_old: &[f64],
    y_old: &[f64],
    x: &[f64],
    y: &[f64],
    z1: &[Vec<f64>],
    z2: &[Vec<f64>],
    show_percent: bool,
) -> iced::widget::Column<'a, Msg> {
    let cell_w: f32 = 80.0;

    // X-axis header row
    let mut header = row![].spacing(0);
    header = header.push(
        container(text("").size(11))
            .width(cell_w)
            .style(|theme: &Theme| {
                let (bg, _) = map_header_colors(theme);
                container::Style {
                    background: Some(bg.into()),
                    ..Default::default()
                }
            }),
    );
    for (xi_idx, xi) in x.iter().enumerate() {
        let v = format_val(*xi);
        let pct = x_old
            .get(xi_idx)
            .map(|old| pct_diff(*old, *xi))
            .unwrap_or(f64::INFINITY);
        let changed = pct.abs() > 0.001;
        header = header.push(
            container(text(v).size(11).font(MONO))
                .width(cell_w)
                .align_x(iced::alignment::Horizontal::Right)
                .padding([0, 4])
                .style(move |theme: &Theme| {
                    if changed {
                        let (bg, fg) = diff_cell_colors(pct, theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    } else {
                        let (bg, fg) = map_header_colors(theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    }
                }),
        );
    }
    let mut tbl = column![header, horizontal_rule(1)].spacing(0);

    // Data rows
    for (yi_idx, yi) in y.iter().enumerate() {
        let mut data_row = row![].spacing(0);
        let y_pct = y_old
            .get(yi_idx)
            .map(|old| pct_diff(*old, *yi))
            .unwrap_or(f64::INFINITY);
        let y_changed = y_pct.abs() > 0.001;
        data_row = data_row.push(
            container(text(format_val(*yi)).size(11).font(MONO))
                .width(cell_w)
                .align_x(iced::alignment::Horizontal::Right)
                .padding([0, 4])
                .style(move |theme: &Theme| {
                    if y_changed {
                        let (bg, fg) = diff_cell_colors(y_pct, theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    } else {
                        let (bg, fg) = map_header_colors(theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    }
                }),
        );

        let row1 = z1.get(yi_idx);
        let row2 = z2.get(yi_idx);

        if let Some(row2_data) = row2 {
            for (xi_idx, val2) in row2_data.iter().enumerate() {
                let val1 = row1.and_then(|r| r.get(xi_idx)).copied().unwrap_or(0.0);
                let pct = pct_diff(val1, *val2);
                let v = if show_percent {
                    format_pct(pct)
                } else {
                    format_val(*val2)
                };

                data_row = data_row.push(
                    container(text(v).size(11).font(MONO))
                        .width(cell_w)
                        .align_x(iced::alignment::Horizontal::Right)
                        .padding([0, 4])
                        .style(move |theme: &Theme| {
                            let (bg, fg) = diff_cell_colors(pct, theme);
                            container::Style {
                                background: Some(bg.into()),
                                text_color: Some(fg),
                                ..Default::default()
                            }
                        }),
                );
            }
        }
        tbl = tbl.push(data_row);
    }
    tbl
}

pub fn format_val(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e9 {
        format!("{:.1}", v)
    } else {
        format!("{:.4}", v)
    }
}

/// Percentage difference: (new - old) / |old| * 100.
pub fn pct_diff(old: f64, new: f64) -> f64 {
    if old.abs() < 1e-15 {
        if (new - old).abs() < 1e-15 {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        (new - old) / old.abs() * 100.0
    }
}

/// Format percentage for display.
pub fn format_pct(pct: f64) -> String {
    if pct.is_infinite() {
        if pct > 0.0 {
            "+∞%".to_string()
        } else {
            "-∞%".to_string()
        }
    } else if pct.abs() < 0.001 {
        "0.0%".to_string()
    } else {
        let sign = if pct > 0.0 { "+" } else { "" };
        format!("{sign}{:.1}%", pct)
    }
}
