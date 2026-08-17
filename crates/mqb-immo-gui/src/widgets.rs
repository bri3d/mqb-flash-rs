//! Small building blocks shared by the tabs.

use iced::widget::{column, container, row, text, Column, Space};
use iced::{Element, Font, Length};

use crate::state::Message;
use crate::theme;

pub const MONO: Font = Font::MONOSPACE;

/// A section heading.
pub fn heading<'a>(title: &'a str) -> Element<'a, Message> {
    text(title).size(16).into()
}

/// Explanatory prose under a heading.
pub fn blurb(body: &str) -> Element<'_, Message> {
    text(body)
        .size(12)
        .style(|t: &iced::Theme| iced::widget::text::Style {
            color: Some(theme::muted(t)),
        })
        .into()
}

/// A labelled value, monospaced so hex lines up.
pub fn field<'a>(label: &'a str, value: impl Into<String>) -> Element<'a, Message> {
    row![
        text(label)
            .size(12)
            .width(Length::Fixed(150.0))
            .style(|t: &iced::Theme| iced::widget::text::Style {
                color: Some(theme::muted(t)),
            }),
        text(value.into()).size(12).font(MONO),
    ]
    .spacing(8)
    .into()
}

/// A line of prose in one of the severity colours.
pub fn coloured<'a>(
    body: impl Into<String>,
    pick: fn(&iced::Theme) -> iced::Color,
) -> Element<'a, Message> {
    text(body.into())
        .size(12)
        .style(move |t: &iced::Theme| iced::widget::text::Style {
            color: Some(pick(t)),
        })
        .into()
}

/// A bordered panel.
pub fn panel<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .padding(10)
        .width(Length::Fill)
        .style(|t: &iced::Theme| container::Style {
            background: Some(theme::panel_background(t).into()),
            border: iced::border::rounded(4),
            ..Default::default()
        })
        .into()
}

/// Vertical breathing room.
pub fn gap<'a>(height: f32) -> Element<'a, Message> {
    Space::new().height(height).into()
}

/// A titled group of rows.
pub fn group<'a>(title: &'a str, rows: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    let mut col: Column<'a, Message> = column![heading(title)].spacing(6);
    for entry in rows {
        col = col.push(entry);
    }
    panel(col)
}
