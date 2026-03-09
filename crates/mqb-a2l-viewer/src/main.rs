//! mqb-a2l-viewer — A2L CHARACTERISTIC browser with firmware data display and BIN compare.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod data;
mod state;
mod theme;
mod update;
mod view;
mod view_compare;
mod view_single;
mod widgets;

use iced::widget::{scrollable, text_input as ti};
use iced::Font;

const MAX_DISPLAY: usize = 500;
const MONO: Font = Font::MONOSPACE;
const FILTER_ID: fn() -> ti::Id = || ti::Id::new("char_filter");
const CHAR_LIST_ID: fn() -> scrollable::Id = || scrollable::Id::new("char_list");

fn main() -> iced::Result {
    iced::application("MQB A2L Viewer", update::update, view::view)
        .window_size((1400.0_f32, 850.0_f32))
        .subscription(update::subscription)
        .run_with(|| (state::State::default(), ti::focus(FILTER_ID())))
}
