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

use iced::Font;

const MAX_DISPLAY: usize = 500;
const MONO: Font = Font::MONOSPACE;
const FILTER_ID: &str = "char_filter";
const CHAR_LIST_ID: &str = "char_list";

fn main() -> iced::Result {
    iced::application(
        || {
            (
                state::State::default(),
                iced::widget::operation::focus(FILTER_ID),
            )
        },
        update::update,
        view::view,
    )
    .title("MQB A2L Viewer")
    .window_size((1400.0_f32, 850.0_f32))
    .subscription(update::subscription)
    .run()
}
