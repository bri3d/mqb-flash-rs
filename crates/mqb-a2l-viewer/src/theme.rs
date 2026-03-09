use iced::{Color, Theme};

pub fn is_dark(theme: &Theme) -> bool {
    let p = theme.palette();
    p.background.r + p.background.g + p.background.b < 1.5
}

pub fn muted_text(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(0.6, 0.6, 0.6)
    } else {
        Color::from_rgb(0.5, 0.5, 0.5)
    }
}

pub fn error_color() -> Color {
    Color::from_rgb(1.0, 0.4, 0.4)
}

pub fn warning_color(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(1.0, 0.8, 0.4)
    } else {
        Color::from_rgb(0.6, 0.4, 0.1)
    }
}

pub fn tag_color_value(theme: &Theme) -> Color {
    if is_dark(theme) { Color::from_rgb(0.5, 0.85, 0.5) } else { Color::from_rgb(0.3, 0.55, 0.3) }
}
pub fn tag_color_curve(theme: &Theme) -> Color {
    if is_dark(theme) { Color::from_rgb(0.5, 0.7, 1.0) } else { Color::from_rgb(0.2, 0.4, 0.7) }
}
pub fn tag_color_map(theme: &Theme) -> Color {
    if is_dark(theme) { Color::from_rgb(1.0, 0.6, 0.4) } else { Color::from_rgb(0.7, 0.35, 0.2) }
}
pub fn tag_color_other(theme: &Theme) -> Color {
    muted_text(theme)
}

pub fn selected_bg() -> Color {
    Color::from_rgb(0.2, 0.45, 0.75)
}

/// Background + text for map cells.  Returns (bg, fg).
pub fn map_cell_colors(intensity: f32, theme: &Theme) -> (Color, Color) {
    if is_dark(theme) {
        let bg = Color::from_rgb(
            0.12 + 0.08 * intensity,
            0.14 + 0.18 * intensity,
            0.18 + 0.25 * intensity,
        );
        let fg = Color::from_rgb(
            0.75 + 0.2 * intensity,
            0.80 + 0.15 * intensity,
            0.85 + 0.10 * intensity,
        );
        (bg, fg)
    } else {
        let bg = Color::from_rgb(
            0.95 - 0.2 * intensity,
            0.95 - 0.1 * intensity,
            0.95 + 0.05 * intensity,
        );
        (bg, Color::from_rgb(0.1, 0.1, 0.1))
    }
}

/// Row-header background + text for map Y-axis labels.
pub fn map_header_colors(theme: &Theme) -> (Color, Color) {
    if is_dark(theme) {
        (Color::from_rgb(0.2, 0.2, 0.25), Color::from_rgb(0.8, 0.8, 0.85))
    } else {
        (Color::from_rgb(0.90, 0.90, 0.93), Color::from_rgb(0.1, 0.1, 0.1))
    }
}

/// Color for diff percentage text.
pub fn diff_pct_color(pct: f64, theme: &Theme) -> Color {
    if pct > 0.001 {
        if is_dark(theme) { Color::from_rgb(1.0, 0.5, 0.4) } else { Color::from_rgb(0.8, 0.15, 0.1) }
    } else if pct < -0.001 {
        if is_dark(theme) { Color::from_rgb(0.4, 0.9, 0.5) } else { Color::from_rgb(0.1, 0.55, 0.2) }
    } else {
        muted_text(theme)
    }
}

/// Background + text for diff map/curve cells. `pct_change` is percent difference.
pub fn diff_cell_colors(pct_change: f64, theme: &Theme) -> (Color, Color) {
    // Clamp to ±100% for color intensity scaling
    let intensity = (pct_change.abs().min(100.0) / 100.0) as f32;
    if is_dark(theme) {
        if pct_change > 0.001 {
            // Increase = red hue
            let bg = Color::from_rgb(
                0.15 + 0.30 * intensity,
                0.12 - 0.02 * intensity,
                0.12 - 0.02 * intensity,
            );
            let fg = Color::from_rgb(
                0.85 + 0.15 * intensity,
                0.75 - 0.25 * intensity,
                0.70 - 0.30 * intensity,
            );
            (bg, fg)
        } else if pct_change < -0.001 {
            // Decrease = green hue
            let bg = Color::from_rgb(
                0.10 - 0.02 * intensity,
                0.15 + 0.20 * intensity,
                0.12 - 0.02 * intensity,
            );
            let fg = Color::from_rgb(
                0.70 - 0.20 * intensity,
                0.85 + 0.15 * intensity,
                0.70 - 0.20 * intensity,
            );
            (bg, fg)
        } else {
            (Color::from_rgb(0.15, 0.15, 0.18), Color::from_rgb(0.6, 0.6, 0.6))
        }
    } else {
        if pct_change > 0.001 {
            let bg = Color::from_rgb(1.0, 0.92 - 0.25 * intensity, 0.90 - 0.30 * intensity);
            (bg, Color::from_rgb(0.1, 0.1, 0.1))
        } else if pct_change < -0.001 {
            let bg = Color::from_rgb(0.90 - 0.15 * intensity, 1.0 - 0.05 * intensity, 0.90 - 0.15 * intensity);
            (bg, Color::from_rgb(0.1, 0.1, 0.1))
        } else {
            (Color::from_rgb(0.96, 0.96, 0.96), Color::from_rgb(0.4, 0.4, 0.4))
        }
    }
}

/// Small colored dot for the characteristic list to indicate changed items.
pub fn changed_indicator_color(theme: &Theme) -> Color {
    if is_dark(theme) { Color::from_rgb(1.0, 0.7, 0.2) } else { Color::from_rgb(0.9, 0.55, 0.0) }
}
