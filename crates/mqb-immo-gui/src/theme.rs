//! Colours, picked so the same screen reads correctly in a light or a dark
//! theme.
//!
//! Severity is carried by both a colour and a word everywhere it appears —
//! "the immobilizer is locked" must survive being read on a washed-out laptop
//! screen in a workshop.

use iced::{Color, Theme};

pub fn is_dark(theme: &Theme) -> bool {
    let palette = theme.palette();
    palette.background.r + palette.background.g + palette.background.b < 1.5
}

pub fn muted(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(0.62, 0.62, 0.62)
    } else {
        Color::from_rgb(0.45, 0.45, 0.45)
    }
}

/// Something went wrong, or would.
pub fn danger(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(1.0, 0.45, 0.42)
    } else {
        Color::from_rgb(0.75, 0.12, 0.10)
    }
}

/// Worth reading before continuing.
pub fn warning(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(1.0, 0.78, 0.36)
    } else {
        Color::from_rgb(0.62, 0.40, 0.05)
    }
}

/// Confirmed good.
pub fn good(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(0.45, 0.85, 0.50)
    } else {
        Color::from_rgb(0.10, 0.52, 0.18)
    }
}

/// Could not be determined — deliberately distinct from "bad".
pub fn unknown(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(0.55, 0.72, 1.0)
    } else {
        Color::from_rgb(0.20, 0.38, 0.68)
    }
}

/// The background of a panel that needs to stand off the page.
pub fn panel_background(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(0.14, 0.14, 0.17)
    } else {
        Color::from_rgb(0.95, 0.95, 0.96)
    }
}
