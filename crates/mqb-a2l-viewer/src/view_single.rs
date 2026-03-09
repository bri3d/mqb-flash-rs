use iced::widget::{column, container, horizontal_rule, row, scrollable, text};
use iced::{Element, Length, Theme};

use mqb_a2l::reader::CharacteristicValues;
use mqb_a2l::{A2lFile, Characteristic};

use crate::state::Msg;
use crate::theme::map_header_colors;
use crate::widgets::{format_val, map_table};
use crate::MONO;

pub fn view_values<'a>(
    values: &'a CharacteristicValues,
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
) -> Element<'a, Msg> {
    match values {
        CharacteristicValues::Scalar(v) => view_scalar(*v, ch, a2l),
        CharacteristicValues::Ascii(s) => view_ascii(s),
        CharacteristicValues::Curve { x, y } => view_curve(x, y, ch, a2l),
        CharacteristicValues::Map { x, y, z } => view_map(x, y, z, ch, a2l),
        CharacteristicValues::Cuboid { x, y, z, w } => view_cuboid(x, y, z, w, ch, a2l),
        CharacteristicValues::ValBlk(vals) => view_val_blk(vals, ch, a2l),
    }
}

pub fn view_scalar<'a>(v: f64, ch: &'a Characteristic, a2l: &'a A2lFile) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let unit = cm.map(|c| c.unit.as_str()).unwrap_or("");

    if let Some(cm) = cm {
        if let Some(label) = cm.conversion.to_verbal(v as i64, &a2l.compu_vtabs) {
            return column![
                text(format!("{} (raw: {})", label, v as i64)).size(20),
            ].into();
        }
    }

    column![
        text(format!("{:.6} {}", v, unit)).size(20),
    ].into()
}

pub fn view_ascii<'a>(s: &'a str) -> Element<'a, Msg> {
    column![
        text(format!("\"{}\"", s)).size(16).font(MONO),
    ].into()
}

pub fn view_curve<'a>(
    x: &'a [f64],
    y: &'a [f64],
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let val_unit = cm.map(|c| c.unit.as_str()).unwrap_or("");
    let axis_unit = ch.axes.first()
        .and_then(|ax| a2l.compu_methods.get(&ax.compu_method_ref))
        .map(|c| c.unit.as_str())
        .unwrap_or("");

    let mut col = column![].spacing(0);

    col = col.push(
        row![
            text(format!("X ({axis_unit})")).size(12).width(120).font(MONO),
            text(format!("Y ({val_unit})")).size(12).width(120).font(MONO),
        ]
        .spacing(4),
    );
    col = col.push(horizontal_rule(1));

    for (xi, yi) in x.iter().zip(y.iter()) {
        col = col.push(
            row![
                text(format_val(*xi)).size(12).width(120).font(MONO),
                text(format_val(*yi)).size(12).width(120).font(MONO),
            ]
            .spacing(4),
        );
    }

    col.into()
}

pub fn view_map<'a>(
    x: &'a [f64],
    y: &'a [f64],
    z: &'a [Vec<f64>],
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let val_unit = cm.map(|c| c.unit.as_str()).unwrap_or("");

    let mut col = column![].spacing(0);
    col = col.push(text(format!("{}x{} map (unit: {val_unit})", x.len(), y.len())).size(12));
    col = col.push(map_table(x, y, z, ch.lower_limit, ch.upper_limit));
    col = col.push(iced::widget::Space::new(0, 14));

    scrollable(col).direction(scrollable::Direction::Both {
        vertical: scrollable::Scrollbar::new(),
        horizontal: scrollable::Scrollbar::new(),
    }).into()
}

pub fn view_cuboid<'a>(
    x: &'a [f64],
    y: &'a [f64],
    z: &'a [f64],
    w: &'a [Vec<Vec<f64>>],
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let val_unit = cm.map(|c| c.unit.as_str()).unwrap_or("");
    let z_unit = ch.axes.get(2)
        .and_then(|ax| a2l.compu_methods.get(&ax.compu_method_ref))
        .map(|c| c.unit.as_str())
        .unwrap_or("");

    let mut col = column![].spacing(8);
    col = col.push(text(format!(
        "{}x{}x{} cuboid (unit: {val_unit})",
        x.len(), y.len(), z.len()
    )).size(12));

    for (zi, zv) in z.iter().enumerate() {
        let Some(slice) = w.get(zi) else { continue };

        col = col.push(
            container(
                text(format!("Z[{zi}] = {} {z_unit}", format_val(*zv))).size(13)
            )
            .style(|theme: &Theme| {
                let (bg, fg) = map_header_colors(theme);
                container::Style {
                    background: Some(bg.into()),
                    text_color: Some(fg),
                    ..Default::default()
                }
            })
            .padding([2, 6])
            .width(Length::Fill)
        );

        col = col.push(map_table(x, y, slice, ch.lower_limit, ch.upper_limit));
    }

    col = col.push(iced::widget::Space::new(0, 14));

    scrollable(col).direction(scrollable::Direction::Both {
        vertical: scrollable::Scrollbar::new(),
        horizontal: scrollable::Scrollbar::new(),
    }).into()
}

pub fn view_val_blk<'a>(
    vals: &'a [f64],
    ch: &'a Characteristic,
    a2l: &'a A2lFile,
) -> Element<'a, Msg> {
    let cm = a2l.compu_methods.get(&ch.compu_method_ref);
    let unit = cm.map(|c| c.unit.as_str()).unwrap_or("");

    let is_verbal = cm.map(|c| matches!(c.conversion, mqb_a2l::Conversion::TabVerb { .. })).unwrap_or(false);

    let mut col = column![].spacing(2);
    col = col.push(text(format!("{} values (unit: {unit})", vals.len())).size(12));

    for (i, v) in vals.iter().enumerate() {
        let label = if is_verbal {
            if let Some(cm) = cm {
                cm.conversion.to_verbal(*v as i64, &a2l.compu_vtabs)
                    .map(|s| format!("[{i}] {s} ({})", *v as i64))
            } else {
                None
            }
        } else {
            None
        };
        let label = label.unwrap_or_else(|| format!("[{i}] {}", format_val(*v)));
        col = col.push(text(label).size(12).font(MONO));
    }

    col.into()
}
