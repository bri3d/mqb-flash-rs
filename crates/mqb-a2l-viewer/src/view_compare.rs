use iced::widget::{column, container, horizontal_rule, row, scrollable, text};
use iced::{Alignment, Element, Theme};

use mqb_a2l::reader::CharacteristicValues;
use mqb_a2l::{A2lFile, Characteristic};

use crate::state::Msg;
use crate::theme::{diff_cell_colors, diff_pct_color, error_color, muted_text, rescale_warning_bg, rescale_warning_color, warning_color};
use crate::view_single::{view_curve, view_values};
use crate::widgets::{diff_map_table, format_pct, format_val, map_table, pct_diff};
use crate::MONO;

pub fn view_compare<'a>(
    v1: &'a Option<CharacteristicValues>,
    v2: &'a Option<CharacteristicValues>,
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
    rescale_suspect: bool,
) -> Element<'a, Msg> {
    match (v1, v2) {
        (Some(val1), Some(val2)) => view_compare_pair(val1, val2, ch, a2l, rescale_suspect),
        (Some(val1), None) => {
            column![
                text("BIN 1").size(13),
                view_values(val1, ch, a2l),
                text("BIN 2: could not read").size(13).color(error_color()),
            ]
            .spacing(8)
            .into()
        }
        (None, Some(val2)) => {
            column![
                text("BIN 1: could not read").size(13).color(error_color()),
                text("BIN 2").size(13),
                view_values(val2, ch, a2l),
            ]
            .spacing(8)
            .into()
        }
        (None, None) => {
            text("Could not read this characteristic from either binary.")
                .size(13)
                .color(error_color())
                .into()
        }
    }
}

fn rescale_warning_banner<'a>() -> Element<'a, Msg> {
    container(
        text("Axis changed but map values are identical — may need rescaling")
            .size(13),
    )
    .padding([6, 10])
    .style(|theme: &Theme| container::Style {
        background: Some(rescale_warning_bg(theme).into()),
        text_color: Some(rescale_warning_color(theme)),
        border: iced::Border {
            color: rescale_warning_color(theme),
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    })
    .into()
}

fn view_compare_pair<'a>(
    v1: &'a CharacteristicValues,
    v2: &'a CharacteristicValues,
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
    rescale_suspect: bool,
) -> Element<'a, Msg> {
    let mut outer = column![].spacing(8);
    if rescale_suspect {
        outer = outer.push(rescale_warning_banner());
    }
    let content: Element<'a, Msg> = match (v1, v2) {
        (CharacteristicValues::Scalar(a), CharacteristicValues::Scalar(b)) => {
            view_compare_scalar(*a, *b, ch, a2l)
        }
        (CharacteristicValues::Ascii(a), CharacteristicValues::Ascii(b)) => {
            view_compare_ascii(a, b)
        }
        (CharacteristicValues::Curve { x: x1, y: y1 }, CharacteristicValues::Curve { x: x2, y: y2 }) => {
            view_compare_curve(x1, y1, x2, y2, ch, a2l)
        }
        (CharacteristicValues::Map { x: x1, y: y1, z: z1 }, CharacteristicValues::Map { x: x2, y: y2, z: z2 }) => {
            view_compare_map(x1, y1, z1, x2, y2, z2, ch, a2l)
        }
        (CharacteristicValues::ValBlk(a), CharacteristicValues::ValBlk(b)) => {
            view_compare_val_blk(a, b, ch, a2l)
        }
        _ => {
            // Type mismatch — show both separately
            column![
                text("BIN 1").size(13),
                view_values(v1, ch, a2l),
                horizontal_rule(1),
                text("BIN 2").size(13),
                view_values(v2, ch, a2l),
            ]
            .spacing(8)
            .into()
        }
    };
    outer = outer.push(content);
    outer.into()
}

fn view_compare_scalar<'a>(v1: f64, v2: f64, ch: &'a Characteristic, a2l: &'a A2lFile) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let unit = cm.map(|c| c.unit.as_str()).unwrap_or("");

    let delta = v2 - v1;
    let pct = pct_diff(v1, v2);
    let pct_str = format_pct(pct);

    let sign = if delta > 0.0 { "+" } else { "" };
    let delta_str = format!("{sign}{}", format_val(delta));

    let mut col = column![].spacing(4);

    // Check for verbal conversion
    if let Some(cm) = cm {
        let verb1 = cm.conversion.to_verbal(v1 as i64, &a2l.compu_vtabs);
        let verb2 = cm.conversion.to_verbal(v2 as i64, &a2l.compu_vtabs);
        if let (Some(l1), Some(l2)) = (verb1, verb2) {
            col = col.push(text(format!("BIN 1:  {l1} (raw: {})", v1 as i64)).size(16));
            let same = v1 as i64 == v2 as i64;
            let label2 = format!("BIN 2:  {l2} (raw: {})", v2 as i64);
            col = col.push(
                container(text(label2).size(16))
                    .style(move |theme: &Theme| container::Style {
                        text_color: Some(if same { muted_text(theme) } else { diff_pct_color(1.0, theme) }),
                        ..Default::default()
                    })
            );
            return col.into();
        }
    }

    col = col.push(text(format!("BIN 1:  {:.6} {unit}", v1)).size(16));
    col = col.push(
        row![
            text(format!("BIN 2:  {:.6} {unit}", v2)).size(16),
            container(text(format!("  ({delta_str}, {pct_str})")).size(14))
                .style(move |theme: &Theme| container::Style {
                    text_color: Some(diff_pct_color(pct, theme)),
                    ..Default::default()
                }),
        ]
        .align_y(Alignment::Center)
    );

    col.into()
}

fn view_compare_ascii<'a>(a: &'a str, b: &'a str) -> Element<'a, Msg> {
    let same = a == b;
    let mut col = column![].spacing(4);
    col = col.push(text(format!("BIN 1:  \"{a}\"")).size(14).font(MONO));
    if same {
        col = col.push(
            container(text(format!("BIN 2:  \"{b}\"  (identical)")).size(14).font(MONO))
                .style(|theme: &Theme| container::Style {
                    text_color: Some(muted_text(theme)),
                    ..Default::default()
                })
        );
    } else {
        col = col.push(
            container(text(format!("BIN 2:  \"{b}\"  (changed)")).size(14).font(MONO))
                .style(|theme: &Theme| container::Style {
                    text_color: Some(diff_pct_color(1.0, theme)),
                    ..Default::default()
                })
        );
    }
    col.into()
}

fn view_compare_curve<'a>(
    x1: &'a [f64], y1: &'a [f64],
    x2: &'a [f64], y2: &'a [f64],
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let val_unit = cm.map(|c| c.unit.as_str()).unwrap_or("");
    let axis_unit = ch.axes.first()
        .and_then(|ax| a2l.compu_methods.get(&ax.compu_method_ref))
        .map(|c| c.unit.as_str())
        .unwrap_or("");

    let axes_same = x1 == x2;

    let axis_name = ch.axes.first()
        .and_then(|ax| ax.axis_pts_ref.as_deref());

    // Different lengths — show two independent tables
    if x1.len() != x2.len() {
        let mut col = column![].spacing(8);
        let size_msg = if let Some(name) = axis_name {
            format!("Axis sizes differ: {} vs {} points ({name})", x1.len(), x2.len())
        } else {
            format!("Axis sizes differ: {} vs {} points", x1.len(), x2.len())
        };
        col = col.push(
            container(text(size_msg).size(12))
                .style(|theme: &Theme| container::Style {
                    text_color: Some(warning_color(theme)),
                    ..Default::default()
                })
        );
        col = col.push(text("BIN 1").size(13));
        col = col.push(view_curve(x1, y1, ch, a2l));
        col = col.push(horizontal_rule(1));
        col = col.push(text("BIN 2").size(13));
        col = col.push(view_curve(x2, y2, ch, a2l));
        return col.into();
    }

    let mut col = column![].spacing(0);

    if axes_same {
        // Same axes — aligned comparison
        col = col.push(
            row![
                text(format!("X ({axis_unit})")).size(12).width(100).font(MONO),
                text(format!("BIN 1 ({val_unit})")).size(12).width(100).font(MONO),
                text(format!("BIN 2 ({val_unit})")).size(12).width(100).font(MONO),
                text("Δ").size(12).width(80).font(MONO),
                text("%").size(12).width(70).font(MONO),
            ]
            .spacing(4),
        );
        col = col.push(horizontal_rule(1));

        let len = x1.len().min(y1.len()).min(y2.len());
        for i in 0..len {
            let xi = x1[i];
            let v1 = y1[i];
            let v2 = y2[i];
            let delta = v2 - v1;
            let pct = pct_diff(v1, v2);
            let sign = if delta > 0.0 { "+" } else { "" };
            let delta_str = format!("{sign}{}", format_val(delta));
            let pct_str = format_pct(pct);

            col = col.push(
                row![
                    text(format_val(xi)).size(12).width(100).font(MONO),
                    text(format_val(v1)).size(12).width(100).font(MONO),
                    container(text(format_val(v2)).size(12).width(100).font(MONO))
                        .style(move |theme: &Theme| {
                            let (bg, fg) = diff_cell_colors(pct, theme);
                            container::Style {
                                background: Some(bg.into()),
                                text_color: Some(fg),
                                ..Default::default()
                            }
                        }),
                    container(text(delta_str).size(12).width(80).font(MONO))
                        .style(move |theme: &Theme| container::Style {
                            text_color: Some(diff_pct_color(pct, theme)),
                            ..Default::default()
                        }),
                    container(text(pct_str).size(12).width(70).font(MONO))
                        .style(move |theme: &Theme| container::Style {
                            text_color: Some(diff_pct_color(pct, theme)),
                            ..Default::default()
                        }),
                ]
                .spacing(4),
            );
        }
    } else {
        // Same length, different axis values — show both X columns
        let axis_msg = if let Some(name) = axis_name {
            format!("Axis breakpoints differ ({name})")
        } else {
            "Axis breakpoints differ between BINs".to_string()
        };
        col = col.push(
            container(text(axis_msg).size(12))
                .style(|theme: &Theme| container::Style {
                    text_color: Some(warning_color(theme)),
                    ..Default::default()
                })
        );
        col = col.push(
            row![
                text(format!("X1 ({axis_unit})")).size(12).width(90).font(MONO),
                text(format!("BIN 1 ({val_unit})")).size(12).width(90).font(MONO),
                text(format!("X2 ({axis_unit})")).size(12).width(90).font(MONO),
                text(format!("BIN 2 ({val_unit})")).size(12).width(90).font(MONO),
                text("ΔX").size(12).width(70).font(MONO),
                text("ΔY").size(12).width(70).font(MONO),
                text("%Y").size(12).width(60).font(MONO),
            ]
            .spacing(4),
        );
        col = col.push(horizontal_rule(1));

        let len = x1.len().min(y1.len()).min(x2.len()).min(y2.len());
        for i in 0..len {
            let xv1 = x1[i];
            let xv2 = x2[i];
            let v1 = y1[i];
            let v2 = y2[i];
            let x_delta = xv2 - xv1;
            let y_delta = v2 - v1;
            let y_pct = pct_diff(v1, v2);
            let x_changed = (x_delta).abs() > 1e-9;
            let x_sign = if x_delta > 0.0 { "+" } else { "" };
            let y_sign = if y_delta > 0.0 { "+" } else { "" };
            let x_delta_str = if x_changed { format!("{x_sign}{}", format_val(x_delta)) } else { "".to_string() };
            let y_delta_str = format!("{y_sign}{}", format_val(y_delta));
            let y_pct_str = format_pct(y_pct);
            let x_pct = pct_diff(xv1, xv2);

            col = col.push(
                row![
                    text(format_val(xv1)).size(12).width(90).font(MONO),
                    text(format_val(v1)).size(12).width(90).font(MONO),
                    container(text(format_val(xv2)).size(12).width(90).font(MONO))
                        .style(move |theme: &Theme| {
                            if x_changed {
                                let (bg, fg) = diff_cell_colors(x_pct, theme);
                                container::Style {
                                    background: Some(bg.into()),
                                    text_color: Some(fg),
                                    ..Default::default()
                                }
                            } else {
                                container::Style::default()
                            }
                        }),
                    container(text(format_val(v2)).size(12).width(90).font(MONO))
                        .style(move |theme: &Theme| {
                            let (bg, fg) = diff_cell_colors(y_pct, theme);
                            container::Style {
                                background: Some(bg.into()),
                                text_color: Some(fg),
                                ..Default::default()
                            }
                        }),
                    container(text(x_delta_str).size(12).width(70).font(MONO))
                        .style(move |theme: &Theme| container::Style {
                            text_color: Some(diff_pct_color(x_pct, theme)),
                            ..Default::default()
                        }),
                    container(text(y_delta_str).size(12).width(70).font(MONO))
                        .style(move |theme: &Theme| container::Style {
                            text_color: Some(diff_pct_color(y_pct, theme)),
                            ..Default::default()
                        }),
                    container(text(y_pct_str).size(12).width(60).font(MONO))
                        .style(move |theme: &Theme| container::Style {
                            text_color: Some(diff_pct_color(y_pct, theme)),
                            ..Default::default()
                        }),
                ]
                .spacing(4),
            );
        }
    }

    col.into()
}

#[allow(clippy::too_many_arguments)]
fn view_compare_map<'a>(
    x1: &'a [f64], y1: &'a [f64], z1: &'a [Vec<f64>],
    x2: &'a [f64], y2: &'a [f64], z2: &'a [Vec<f64>],
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let val_unit = cm.map(|c| c.unit.as_str()).unwrap_or("");

    let axes_same = x1 == x2 && y1 == y2;

    let mut col = column![].spacing(8);

    if axes_same {
        // Same axes — aligned diff view
        col = col.push(text(format!("BIN 1 — {}x{} map (unit: {val_unit})", x1.len(), y1.len())).size(13));
        col = col.push(map_table(x1, y1, z1, ch.lower_limit, ch.upper_limit));

        col = col.push(text("BIN 2 — diff coloring (red=increase, green=decrease)").size(13));
        col = col.push(diff_map_table(x1, y1, z1, z2));
    } else {
        // Different axes — show both maps independently with axis change summary
        let x_same = x1 == x2;
        let y_same = y1 == y2;
        let size_same = x1.len() == x2.len() && y1.len() == y2.len();

        let x_axis_name = ch.axes.first()
            .and_then(|ax| ax.axis_pts_ref.as_deref());
        let y_axis_name = ch.axes.get(1)
            .and_then(|ax| ax.axis_pts_ref.as_deref());

        let mut notes = Vec::new();
        if !size_same {
            notes.push(format!("Grid size: {}x{} → {}x{}", x1.len(), y1.len(), x2.len(), y2.len()));
        }
        if !x_same {
            if let Some(name) = x_axis_name {
                notes.push(format!("X-axis changed ({name})"));
            } else {
                notes.push("X-axis breakpoints changed".to_string());
            }
        }
        if !y_same {
            if let Some(name) = y_axis_name {
                notes.push(format!("Y-axis changed ({name})"));
            } else {
                notes.push("Y-axis breakpoints changed".to_string());
            }
        }
        let note_text = notes.join(" · ");
        col = col.push(
            container(text(note_text).size(12))
                .style(|theme: &Theme| container::Style {
                    text_color: Some(warning_color(theme)),
                    ..Default::default()
                })
        );

        // BIN 1 map with its own axes
        col = col.push(text(format!("BIN 1 — {}x{} map (unit: {val_unit})", x1.len(), y1.len())).size(13));
        col = col.push(map_table(x1, y1, z1, ch.lower_limit, ch.upper_limit));

        // BIN 2 map with its own axes
        col = col.push(text(format!("BIN 2 — {}x{} map (unit: {val_unit})", x2.len(), y2.len())).size(13));
        col = col.push(map_table(x2, y2, z2, ch.lower_limit, ch.upper_limit));

        // If same grid size, also show a diff map aligned to BIN 2's axes
        if size_same {
            col = col.push(text("Difference (BIN 2 axes, red=increase, green=decrease)").size(13));
            col = col.push(diff_map_table(x2, y2, z1, z2));
        }
    }

    col = col.push(iced::widget::Space::new(0, 14));

    scrollable(col).direction(scrollable::Direction::Both {
        vertical: scrollable::Scrollbar::new(),
        horizontal: scrollable::Scrollbar::new(),
    }).into()
}

fn view_compare_val_blk<'a>(
    vals1: &'a [f64],
    vals2: &'a [f64],
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let unit = cm.map(|c| c.unit.as_str()).unwrap_or("");

    let mut col = column![].spacing(2);
    col = col.push(text(format!("{} values (unit: {unit})", vals1.len().max(vals2.len()))).size(12));

    // Header
    col = col.push(
        row![
            text("Idx").size(12).width(40).font(MONO),
            text("BIN 1").size(12).width(100).font(MONO),
            text("BIN 2").size(12).width(100).font(MONO),
            text("Δ").size(12).width(80).font(MONO),
            text("%").size(12).width(70).font(MONO),
        ]
        .spacing(4),
    );
    col = col.push(horizontal_rule(1));

    let len = vals1.len().max(vals2.len());
    for i in 0..len {
        let v1 = vals1.get(i).copied().unwrap_or(0.0);
        let v2 = vals2.get(i).copied().unwrap_or(0.0);
        let delta = v2 - v1;
        let pct = pct_diff(v1, v2);
        let sign = if delta > 0.0 { "+" } else { "" };
        let delta_str = format!("{sign}{}", format_val(delta));
        let pct_str = format_pct(pct);

        col = col.push(
            row![
                text(format!("[{i}]")).size(12).width(40).font(MONO),
                text(format_val(v1)).size(12).width(100).font(MONO),
                container(text(format_val(v2)).size(12).width(100).font(MONO))
                    .style(move |theme: &Theme| {
                        let (bg, fg) = diff_cell_colors(pct, theme);
                        container::Style {
                            background: Some(bg.into()),
                            text_color: Some(fg),
                            ..Default::default()
                        }
                    }),
                container(text(delta_str).size(12).width(80).font(MONO))
                    .style(move |theme: &Theme| container::Style {
                        text_color: Some(diff_pct_color(pct, theme)),
                        ..Default::default()
                    }),
                container(text(pct_str).size(12).width(70).font(MONO))
                    .style(move |theme: &Theme| container::Style {
                        text_color: Some(diff_pct_color(pct, theme)),
                        ..Default::default()
                    }),
            ]
            .spacing(4),
        );
    }

    col.into()
}
