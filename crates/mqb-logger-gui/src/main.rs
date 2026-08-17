//! mqb-logger-gui — A2L measurement browser and simostools CSV logger GUI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use iced::event::{self, Event};
use iced::mouse;
use iced::widget::rule::{horizontal as horizontal_rule, vertical as vertical_rule};
use iced::widget::{
    button, checkbox, column, container, mouse_area, row, scrollable, text, text_input,
};
use iced::{keyboard, Alignment, Color, Element, Length, Subscription, Task};

use mqb_a2l::{A2lFile, Conversion, DataType};

// ─── Entry point ─────────────────────────────────────────────────────────────

const FILTER_INPUT_ID: &str = "filter";
const EDIT_INPUT_ID: &str = "edit_field";

fn main() -> iced::Result {
    iced::application(
        || {
            (
                State::default(),
                iced::widget::operation::focus(FILTER_INPUT_ID),
            )
        },
        update,
        view,
    )
    .title("MQB Logger")
    .subscription(subscription)
    .window_size((1300.0_f32, 820.0_f32))
    .run()
}

// ─── CSV item ────────────────────────────────────────────────────────────────

/// One row in a simostools-format CSV log definition.
#[derive(Debug, Clone)]
struct CsvItem {
    name: String,
    unit: String,
    equation: String,
    format: String,
    /// ECU RAM address; `0xFFFF_FFFF` means derived/calculated (no direct read).
    address: u32,
    length: u32,
    signed: bool,
    prog_min: f64,
    prog_max: f64,
    warn_min: f64,
    warn_max: f64,
    smoothing: f64,
    enabled: bool,
    tabs: String,
    assign_to: String,
}

impl CsvItem {
    fn is_derived(&self) -> bool {
        self.address == 0xFFFF_FFFF
    }
}

// ─── Edit state ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum EditTarget {
    CsvName(usize),
    CsvEquation(usize),
}

// ─── State ───────────────────────────────────────────────────────────────────

const MAX_DISPLAY: usize = 500;

struct State {
    // A2L
    a2l_path: Option<PathBuf>,
    a2l: Option<Arc<A2lFile>>,
    loading_a2l: bool,
    a2l_error: Option<String>,
    /// address → index in `a2l.measurements`; rebuilt when A2L loads.
    a2l_addr_index: HashMap<u32, usize>,

    // Left-panel filter
    filter: String,
    filtered: Vec<usize>,
    total_matches: usize,

    // CSV / selection (right panel)
    csv_path: Option<PathBuf>,
    csv_items: Vec<CsvItem>,
    loading_csv: bool,
    csv_error: Option<String>,

    /// Inline edit in progress: (target field, draft text)
    editing: Option<(EditTarget, String)>,

    // Split pane
    split_x: f32,
    dragging_split: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            a2l_path: None,
            a2l: None,
            loading_a2l: false,
            a2l_error: None,
            a2l_addr_index: HashMap::new(),
            filter: String::new(),
            filtered: Vec::new(),
            total_matches: 0,
            csv_path: None,
            csv_items: Vec::new(),
            loading_csv: false,
            csv_error: None,
            editing: None,
            split_x: 760.0,
            dragging_split: false,
        }
    }
}

impl State {
    fn rebuild_filter(&mut self) {
        let Some(a2l) = &self.a2l else {
            self.filtered = Vec::new();
            self.total_matches = 0;
            return;
        };
        let filter = self.filter.to_lowercase();
        let mut all: Vec<usize> = a2l
            .measurements
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                filter.is_empty()
                    || m.name.to_lowercase().contains(&filter)
                    || m.description.to_lowercase().contains(&filter)
            })
            .map(|(i, _)| i)
            .collect();
        self.total_matches = all.len();
        all.truncate(MAX_DISPLAY);
        self.filtered = all;
    }

    fn rebuild_addr_index(&mut self) {
        self.a2l_addr_index.clear();
        if let Some(a2l) = &self.a2l {
            for (i, m) in a2l.measurements.iter().enumerate() {
                if let Some(addr) = m.ecu_address {
                    self.a2l_addr_index.insert(addr, i);
                }
            }
        }
    }

    /// Is this A2L measurement (by address) currently in the CSV item list?
    fn is_in_csv(&self, ecu_address: Option<u32>) -> bool {
        let Some(addr) = ecu_address else {
            return false;
        };
        if addr == 0xFFFF_FFFF {
            return false;
        }
        self.csv_items.iter().any(|item| item.address == addr)
    }
}

// ─── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Message {
    // A2L
    OpenA2lPressed,
    A2lPathSelected(Option<PathBuf>),
    A2lLoaded(Result<Arc<A2lFile>, String>),

    // Filter
    FilterChanged(String),
    SelectAllVisible,

    // Left-panel toggle (add/remove measurement from CSV list)
    ToggleMeasurement(String),

    // CSV
    OpenCsvPressed,
    CsvPathSelected(Option<PathBuf>),
    CsvLoaded(Result<Vec<CsvItem>, String>),
    SaveCsvPressed,
    SaveCsvAsPressed,
    SaveCsvPathSelected(Option<PathBuf>),
    RemoveCsvItem(usize),

    // Inline editing
    StartEdit(EditTarget),
    EditDraftChanged(String),
    CommitEdit,
    CancelEdit,

    // Keyboard navigation
    TabForward,
    TabBackward,

    // Split pane
    SplitDragStart,
    SplitDragUpdate(f32),
    SplitDragEnd,
}

// ─── Update ──────────────────────────────────────────────────────────────────

fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        // ── A2L ──────────────────────────────────────────────────────────────
        Message::OpenA2lPressed => Task::future(async {
            let handle = rfd::AsyncFileDialog::new()
                .set_title("Open A2L file")
                .add_filter("A2L files", &["a2l", "A2L"])
                .add_filter("All files", &["*"])
                .pick_file()
                .await;
            Message::A2lPathSelected(handle.map(|h| h.path().to_path_buf()))
        }),

        Message::A2lPathSelected(Some(path)) => {
            state.a2l_path = Some(path.clone());
            state.a2l = None;
            state.loading_a2l = true;
            state.a2l_error = None;
            state.filtered = Vec::new();
            state.total_matches = 0;
            state.a2l_addr_index.clear();
            Task::future(async move {
                let result = tokio::task::spawn_blocking(move || {
                    mqb_a2l::parse_file(&path)
                        .map(Arc::new)
                        .map_err(|e| e.to_string())
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
                Message::A2lLoaded(result)
            })
        }

        Message::A2lPathSelected(None) => Task::none(),

        Message::A2lLoaded(Ok(a2l)) => {
            state.loading_a2l = false;
            state.a2l = Some(a2l);
            state.filter.clear();
            state.rebuild_addr_index();
            state.rebuild_filter();
            Task::none()
        }

        Message::A2lLoaded(Err(e)) => {
            state.loading_a2l = false;
            state.a2l_error = Some(e);
            Task::none()
        }

        // ── Filter ───────────────────────────────────────────────────────────
        Message::FilterChanged(s) => {
            state.filter = s;
            state.rebuild_filter();
            Task::none()
        }

        Message::SelectAllVisible => {
            if let Some(a2l) = &state.a2l {
                for &idx in &state.filtered {
                    let m = &a2l.measurements[idx];
                    if !state.is_in_csv(m.ecu_address) {
                        state.csv_items.push(csv_item_from_a2l(m, a2l));
                    }
                }
            }
            Task::none()
        }

        // ── Toggle A2L measurement in/out of CSV list ─────────────────────
        Message::ToggleMeasurement(name) => {
            if let Some(a2l) = &state.a2l {
                if let Some(m) = a2l.measurements.iter().find(|m| m.name == name) {
                    let addr = m.ecu_address.unwrap_or(0xFFFF_FFFF);
                    let already_in = state.csv_items.iter().any(|i| i.address == addr);
                    if already_in {
                        state.csv_items.retain(|i| i.address != addr);
                    } else {
                        let item = csv_item_from_a2l(m, a2l);
                        state.csv_items.push(item);
                    }
                }
            }
            Task::none()
        }

        // ── CSV ───────────────────────────────────────────────────────────
        Message::OpenCsvPressed => Task::future(async {
            let handle = rfd::AsyncFileDialog::new()
                .set_title("Open simostools CSV")
                .add_filter("CSV files", &["csv", "CSV"])
                .add_filter("All files", &["*"])
                .pick_file()
                .await;
            Message::CsvPathSelected(handle.map(|h| h.path().to_path_buf()))
        }),

        Message::CsvPathSelected(Some(path)) => {
            state.csv_path = Some(path.clone());
            state.loading_csv = true;
            state.csv_error = None;
            Task::future(async move {
                let result = tokio::task::spawn_blocking(move || {
                    read_file_latin1_or_utf8(&path)
                        .map_err(|e| e.to_string())
                        .and_then(|s| parse_csv(&s))
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()));
                Message::CsvLoaded(result)
            })
        }

        Message::CsvPathSelected(None) => Task::none(),

        Message::CsvLoaded(Ok(items)) => {
            state.loading_csv = false;
            state.csv_items = items;
            Task::none()
        }

        Message::CsvLoaded(Err(e)) => {
            state.loading_csv = false;
            state.csv_error = Some(e);
            Task::none()
        }

        Message::SaveCsvPressed => {
            if let Some(path) = &state.csv_path {
                let content = write_csv(&state.csv_items);
                if let Err(e) = std::fs::write(path, content.as_bytes()) {
                    state.csv_error = Some(e.to_string());
                } else {
                    state.csv_error = None;
                }
            } else {
                // No path yet — trigger Save As
                return update(state, Message::SaveCsvAsPressed);
            }
            Task::none()
        }

        Message::SaveCsvAsPressed => Task::future(async {
            let handle = rfd::AsyncFileDialog::new()
                .set_title("Save simostools CSV")
                .add_filter("CSV files", &["csv"])
                .save_file()
                .await;
            Message::SaveCsvPathSelected(handle.map(|h| h.path().to_path_buf()))
        }),

        Message::SaveCsvPathSelected(Some(path)) => {
            state.csv_path = Some(path.clone());
            let content = write_csv(&state.csv_items);
            if let Err(e) = std::fs::write(&path, content.as_bytes()) {
                state.csv_error = Some(e.to_string());
            } else {
                state.csv_error = None;
            }
            Task::none()
        }

        Message::SaveCsvPathSelected(None) => Task::none(),

        Message::RemoveCsvItem(idx) => {
            if idx < state.csv_items.len() {
                state.csv_items.remove(idx);
            }
            Task::none()
        }

        // ── Inline editing ────────────────────────────────────────────────
        Message::StartEdit(target) => {
            let draft = match &target {
                EditTarget::CsvName(i) => state
                    .csv_items
                    .get(*i)
                    .map(|item| item.name.clone())
                    .unwrap_or_default(),
                EditTarget::CsvEquation(i) => state
                    .csv_items
                    .get(*i)
                    .map(|item| {
                        if item.equation.is_empty() {
                            "x".to_owned()
                        } else {
                            item.equation.clone()
                        }
                    })
                    .unwrap_or_default(),
            };
            state.editing = Some((target, draft));
            iced::widget::operation::focus(EDIT_INPUT_ID)
        }

        Message::EditDraftChanged(s) => {
            if let Some((_, draft)) = &mut state.editing {
                *draft = s;
            }
            Task::none()
        }

        Message::CommitEdit => {
            if let Some((target, draft)) = state.editing.take() {
                match target {
                    EditTarget::CsvName(i) => {
                        if let Some(item) = state.csv_items.get_mut(i) {
                            item.name = draft;
                        }
                    }
                    EditTarget::CsvEquation(i) => {
                        if let Some(item) = state.csv_items.get_mut(i) {
                            item.equation = draft;
                        }
                    }
                }
            }
            Task::none()
        }

        Message::CancelEdit => {
            state.editing = None;
            Task::none()
        }

        // ── Keyboard nav ─────────────────────────────────────────────────
        Message::TabForward => iced::widget::operation::focus_next(),
        Message::TabBackward => iced::widget::operation::focus_previous(),

        // ── Split pane ──────────────────────────────────────────────────
        Message::SplitDragStart => {
            state.dragging_split = true;
            Task::none()
        }
        Message::SplitDragUpdate(x) => {
            // Account for outer padding (14px)
            state.split_x = (x - 14.0).clamp(250.0, 900.0);
            Task::none()
        }
        Message::SplitDragEnd => {
            state.dragging_split = false;
            Task::none()
        }
    }
}

// ─── Subscription ─────────────────────────────────────────────────────────────

fn subscription(state: &State) -> Subscription<Message> {
    let keys = keyboard::listen().filter_map(|event| match event {
        keyboard::Event::KeyPressed { key, modifiers, .. } => match key {
            keyboard::Key::Named(keyboard::key::Named::Tab) => Some(if modifiers.shift() {
                Message::TabBackward
            } else {
                Message::TabForward
            }),
            keyboard::Key::Named(keyboard::key::Named::Escape) => Some(Message::CancelEdit),
            _ => None,
        },
        _ => None,
    });
    if state.dragging_split {
        let drag = event::listen_with(|event, _status, _window| match event {
            Event::Mouse(mouse::Event::CursorMoved { position }) => {
                Some(Message::SplitDragUpdate(position.x))
            }
            Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                Some(Message::SplitDragEnd)
            }
            _ => None,
        });
        Subscription::batch([keys, drag])
    } else {
        keys
    }
}

// ─── View ─────────────────────────────────────────────────────────────────────

fn view(state: &State) -> Element<'_, Message> {
    // ── Top bar ────────────────────────────────────────────────────────────
    let a2l_btn_label = if state.loading_a2l {
        "Loading…"
    } else {
        "Open A2L…"
    };
    let a2l_btn = button(a2l_btn_label)
        .on_press_maybe((!state.loading_a2l).then_some(Message::OpenA2lPressed))
        .padding([6, 14]);

    let a2l_file_label = state
        .a2l_path
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "No A2L".into());

    let a2l_status = if let Some(e) = &state.a2l_error {
        format!("Error: {e}")
    } else if state.loading_a2l {
        "Loading…".into()
    } else if let Some(a2l) = &state.a2l {
        format!("({} measurements)", a2l.measurements.len())
    } else {
        String::new()
    };

    let csv_btn = button(if state.loading_csv {
        "Loading…"
    } else {
        "Open CSV…"
    })
    .on_press_maybe((!state.loading_csv).then_some(Message::OpenCsvPressed))
    .padding([6, 14]);

    let csv_file_label = state
        .csv_path
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "No CSV".into());

    let has_csv_items = !state.csv_items.is_empty();
    let save_btn = button("Save CSV")
        .on_press_maybe(has_csv_items.then_some(Message::SaveCsvPressed))
        .padding([6, 14]);
    let save_as_btn = button("Save As…")
        .on_press_maybe(has_csv_items.then_some(Message::SaveCsvAsPressed))
        .padding([6, 14]);

    let csv_status = if let Some(e) = &state.csv_error {
        text(format!("Save error: {e}"))
            .size(12)
            .color(Color::from_rgb(0.9, 0.3, 0.3))
    } else {
        text(String::new()).size(12)
    };

    let topbar = row![
        a2l_btn,
        text(a2l_file_label),
        text(a2l_status)
            .size(12)
            .color(Color::from_rgb(0.6, 0.6, 0.6)),
        text("  |  ")
            .size(12)
            .color(Color::from_rgb(0.35, 0.35, 0.35)),
        csv_btn,
        text(csv_file_label),
        save_btn,
        save_as_btn,
        csv_status,
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    // ── Left panel: A2L browser ────────────────────────────────────────────
    let showing_str = if state.a2l.is_some() {
        if state.total_matches > MAX_DISPLAY {
            format!(
                "Showing {} of {} — refine filter",
                state.filtered.len(),
                state.total_matches
            )
        } else {
            format!("{} matches", state.total_matches)
        }
    } else {
        String::new()
    };

    let filter_row = row![
        text_input("Filter by name or description…", &state.filter)
            .id(FILTER_INPUT_ID)
            .on_input(Message::FilterChanged)
            .width(Length::Fill),
        text(showing_str).size(12),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    let list_rows: Vec<Element<'_, Message>> = match &state.a2l {
        None => vec![text(if state.loading_a2l {
            "Loading A2L file…"
        } else {
            "Open an A2L file to browse measurements."
        })
        .into()],
        Some(a2l) => state
            .filtered
            .iter()
            .map(|&idx| measurement_row(a2l, idx, state))
            .collect(),
    };

    let select_all_btn = button("Select All Visible")
        .on_press_maybe((!state.filtered.is_empty()).then_some(Message::SelectAllVisible))
        .padding([4, 10]);

    let list_header = row![
        text("Measurements").size(15).width(Length::Fill),
        select_all_btn,
    ]
    .align_y(Alignment::Center);

    let left_panel = column![
        list_header,
        horizontal_rule(1),
        filter_row,
        scrollable(column(list_rows).spacing(0).width(Length::Fill)).height(Length::Fill),
    ]
    .spacing(8)
    .width(state.split_x)
    .height(Length::Fill);

    // ── Right panel: CSV item list ─────────────────────────────────────────
    let csv_count = state.csv_items.len();

    let csv_header = row![text(format!("Log Channels  ({csv_count})"))
        .size(15)
        .width(Length::Fill),]
    .align_y(Alignment::Center);

    let csv_rows: Vec<Element<'_, Message>> = state
        .csv_items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            csv_item_row(
                item,
                idx,
                &state.a2l_addr_index,
                state.a2l.as_deref(),
                state.editing.as_ref(),
            )
        })
        .collect();

    let csv_content: Element<'_, Message> = if csv_rows.is_empty() {
        container(
            text("No channels selected.\nOpen a CSV or select measurements from the A2L.").size(13),
        )
        .padding([8, 0])
        .into()
    } else {
        scrollable(column(csv_rows).spacing(0).width(Length::Fill))
            .height(Length::Fill)
            .into()
    };

    let right_panel = column![csv_header, horizontal_rule(1), csv_content,]
        .spacing(8)
        .width(Length::Fill)
        .height(Length::Fill);

    // ── Root ──────────────────────────────────────────────────────────────
    let divider = mouse_area(
        container(vertical_rule(1))
            .width(8)
            .height(Length::Fill)
            .align_x(Alignment::Center),
    )
    .on_press(Message::SplitDragStart)
    .interaction(iced::mouse::Interaction::ResizingHorizontally);

    column![
        topbar,
        horizontal_rule(1),
        row![left_panel, divider, right_panel]
            .spacing(12)
            .height(Length::Fill),
    ]
    .spacing(10)
    .padding(14)
    .height(Length::Fill)
    .into()
}

// ─── Left panel: measurement row ─────────────────────────────────────────────

fn measurement_row<'a>(a2l: &'a A2lFile, idx: usize, state: &State) -> Element<'a, Message> {
    let m = &a2l.measurements[idx];
    let is_selected = state.is_in_csv(m.ecu_address);
    let name = m.name.clone();

    let desc: &str = if m.description.is_empty() {
        "—"
    } else {
        &m.description
    };
    let unit = a2l
        .compu_methods
        .get(&m.compu_method_ref)
        .map(|cm| cm.unit.as_str())
        .unwrap_or("");

    let label_col = column![
        row![
            text(&m.name).size(13),
            text(if unit.is_empty() || unit == "-" {
                String::new()
            } else {
                format!("  [{unit}]")
            })
            .size(11)
            .color(Color::from_rgb(0.5, 0.7, 0.5)),
        ],
        text(desc).size(11).color(Color::from_rgb(0.55, 0.55, 0.55)),
    ]
    .spacing(1)
    .width(Length::Fill);

    let row_content = row![checkbox(is_selected), label_col,]
        .spacing(8)
        .align_y(Alignment::Center)
        .padding([5, 8]);

    let bg = if is_selected {
        Color::from_rgb(0.13, 0.22, 0.13)
    } else {
        Color::TRANSPARENT
    };

    mouse_area(
        container(row_content)
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(iced::Background::Color(bg)),
                ..Default::default()
            }),
    )
    .on_press(Message::ToggleMeasurement(name))
    .into()
}

// ─── Right panel: CSV item row ────────────────────────────────────────────────

fn csv_item_row<'a>(
    item: &'a CsvItem,
    idx: usize,
    addr_index: &HashMap<u32, usize>,
    a2l: Option<&'a A2lFile>,
    editing: Option<&'a (EditTarget, String)>,
) -> Element<'a, Message> {
    // Check what (if anything) is being edited for this row
    let editing_name = editing.and_then(|(t, d)| {
        if *t == EditTarget::CsvName(idx) {
            Some(d.as_str())
        } else {
            None
        }
    });
    let editing_equation = editing.and_then(|(t, d)| {
        if *t == EditTarget::CsvEquation(idx) {
            Some(d.as_str())
        } else {
            None
        }
    });

    // Cross-correlate: find A2L measurement at this address
    let a2l_match: Option<(&str, DataType)> = if !item.is_derived() {
        addr_index.get(&item.address).and_then(|&i| {
            a2l.map(|a| (&a.measurements[i].name as &str, a.measurements[i].datatype))
        })
    } else {
        None
    };

    // Line 1: name (editable) + unit + address
    let addr_label = if item.is_derived() {
        "(derived)".to_string()
    } else {
        format!("{:#010x}", item.address)
    };
    let unit_display = if item.unit.is_empty() {
        String::new()
    } else {
        format!("  [{}]", item.unit)
    };

    let name_widget: Element<'_, Message> = if let Some(draft) = editing_name {
        text_input("", draft)
            .id(EDIT_INPUT_ID)
            .on_input(Message::EditDraftChanged)
            .on_submit(Message::CommitEdit)
            .size(13)
            .width(Length::Fill)
            .into()
    } else {
        mouse_area(text(&item.name).size(13).width(Length::Fill))
            .on_press(Message::StartEdit(EditTarget::CsvName(idx)))
            .interaction(iced::mouse::Interaction::Text)
            .into()
    };

    let line1 = row![
        name_widget,
        text(unit_display)
            .size(11)
            .color(Color::from_rgb(0.5, 0.7, 0.5)),
        text(addr_label)
            .size(11)
            .color(Color::from_rgb(0.45, 0.55, 0.75)),
    ]
    .spacing(4)
    .align_y(Alignment::Center);

    // Line 2: A2L cross-reference
    let line2_str = match a2l_match {
        Some((a2l_name, dtype)) => {
            let renamed = a2l_name != item.name.as_str();
            if renamed {
                format!("A2L: {a2l_name}  ·  {dtype:?}")
            } else {
                format!("{dtype:?}")
            }
        }
        None if item.is_derived() => String::new(),
        None => "(no A2L match)".to_string(),
    };
    let line2_color = if a2l_match
        .map(|(n, _)| n != item.name.as_str())
        .unwrap_or(false)
    {
        Color::from_rgb(0.7, 0.65, 0.4) // highlight renamed items
    } else {
        Color::from_rgb(0.5, 0.5, 0.5)
    };

    // Line 3: equation (editable)
    let eq_str: &str = if item.equation.is_empty() {
        "x"
    } else {
        &item.equation
    };
    let line3_widget: Element<'_, Message> = if let Some(draft) = editing_equation {
        text_input("", draft)
            .id(EDIT_INPUT_ID)
            .on_input(Message::EditDraftChanged)
            .on_submit(Message::CommitEdit)
            .size(10)
            .width(Length::Fill)
            .into()
    } else {
        let eq_color = if eq_str == "x" {
            Color::from_rgb(0.35, 0.35, 0.35)
        } else {
            Color::from_rgb(0.45, 0.45, 0.45)
        };
        mouse_area(text(eq_str).size(10).color(eq_color).width(Length::Fill))
            .on_press(Message::StartEdit(EditTarget::CsvEquation(idx)))
            .interaction(iced::mouse::Interaction::Text)
            .into()
    };

    let detail = column![
        line1,
        text(line2_str).size(10).color(line2_color),
        line3_widget,
    ]
    .spacing(1)
    .width(Length::Fill);

    let remove_btn = button("×")
        .on_press(Message::RemoveCsvItem(idx))
        .padding([2, 7]);

    let full_row = row![detail, remove_btn]
        .spacing(6)
        .align_y(Alignment::Center)
        .padding([5, 8]);

    let bg = if !item.enabled {
        Color::from_rgb(0.12, 0.12, 0.12)
    } else {
        Color::TRANSPARENT
    };

    container(full_row)
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(bg)),
            ..Default::default()
        })
        .into()
}

// ─── CSV parse / write ────────────────────────────────────────────────────────

fn read_file_latin1_or_utf8(path: &std::path::Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    })
}

fn parse_csv(content: &str) -> Result<Vec<CsvItem>, String> {
    let mut lines = content.lines();
    // Skip header row
    let _header = lines.next().ok_or("CSV is empty")?;

    let mut items = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let c: Vec<&str> = line.split(',').collect();
        let get = |i: usize| c.get(i).copied().unwrap_or("").trim();

        let address = {
            let s = get(4);
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).unwrap_or(0xFFFF_FFFF)
            } else {
                s.parse().unwrap_or(0xFFFF_FFFF)
            }
        };

        items.push(CsvItem {
            name: get(0).to_owned(),
            unit: get(1).to_owned(),
            equation: get(2).to_owned(),
            format: get(3).to_owned(),
            address,
            length: get(5).parse().unwrap_or(1),
            signed: get(6).eq_ignore_ascii_case("true"),
            prog_min: get(7).parse().unwrap_or(0.0),
            prog_max: get(8).parse().unwrap_or(1000.0),
            warn_min: get(9).parse().unwrap_or(-1000.0),
            warn_max: get(10).parse().unwrap_or(1000.0),
            smoothing: get(11).parse().unwrap_or(0.0),
            enabled: get(12).eq_ignore_ascii_case("true"),
            tabs: get(13).to_owned(),
            assign_to: get(14).to_owned(),
        });
    }
    Ok(items)
}

fn write_csv(items: &[CsvItem]) -> String {
    let mut out = String::with_capacity(items.len() * 80);
    out.push_str(
        "Name,Unit,Equation,Format,Address,Length,Signed,ProgMin,ProgMax,WarnMin,WarnMax,Smoothing,Enabled,Tabs,Assign To\n",
    );
    for item in items {
        let addr = if item.is_derived() {
            "0xffffffff".to_owned()
        } else {
            format!("{:#010x}", item.address)
        };
        let fields: [&str; 15] = [
            &item.name,
            &item.unit,
            &item.equation,
            &item.format,
            &addr,
            &item.length.to_string(),
            if item.signed { "TRUE" } else { "FALSE" },
            &fmt_f64(item.prog_min),
            &fmt_f64(item.prog_max),
            &fmt_f64(item.warn_min),
            &fmt_f64(item.warn_max),
            &fmt_f64(item.smoothing),
            if item.enabled { "TRUE" } else { "FALSE" },
            &item.tabs,
            &item.assign_to,
        ];
        for (i, field) in fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            if field.contains(',') || field.contains('"') || field.contains('\n') {
                out.push('"');
                out.push_str(&field.replace('"', "\"\""));
                out.push('"');
            } else {
                out.push_str(field);
            }
        }
        out.push('\n');
    }
    out
}

/// Format f64 without unnecessary trailing `.0` or scientific notation.
fn fmt_f64(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

// ─── A2L → CsvItem ───────────────────────────────────────────────────────────

fn csv_item_from_a2l(m: &mqb_a2l::Measurement, a2l: &A2lFile) -> CsvItem {
    let cm = a2l.compu_methods.get(&m.compu_method_ref);
    let unit = cm.map(|c| c.unit.clone()).unwrap_or_default();
    let equation = cm
        .map(|c| equation_from_a2l(&c.conversion))
        .unwrap_or_else(|| "x".into());

    let signed = matches!(
        m.datatype,
        DataType::SByte
            | DataType::SWord
            | DataType::SLong
            | DataType::AInt64
            | DataType::Float32Ieee
            | DataType::Float64Ieee
    );

    CsvItem {
        name: m.name.clone(),
        unit,
        equation,
        format: "%01.2f".into(),
        address: m.ecu_address.unwrap_or(0xFFFF_FFFF),
        length: m.datatype.byte_width() as u32,
        signed,
        prog_min: 0.0,
        prog_max: 1000.0,
        warn_min: -1000.0,
        warn_max: 1000.0,
        smoothing: 0.0,
        enabled: true,
        tabs: String::new(),
        assign_to: String::new(),
    }
}

/// Build a simostools-style equation string from an A2L conversion.
///
/// The result is in terms of `x` (the raw integer read from RAM) and evaluates
/// to the physical (display) value.
fn equation_from_a2l(conv: &Conversion) -> String {
    match conv {
        Conversion::Identical => "x".into(),

        Conversion::Linear { a, b } => {
            if *a == 1.0 && *b == 0.0 {
                "x".into()
            } else if *b == 0.0 {
                format!("x * {a}")
            } else if *b > 0.0 {
                format!("x * {a} + {b}")
            } else {
                format!("x * {a} - {}", -b)
            }
        }

        // Common RAT_FUNC shape: a=0, d=0, e=0
        //   internal = (b·phys + c) / f  →  phys = (f·x − c) / b
        Conversion::RatFunc { a, b, c, d, e, f }
            if *a == 0.0 && *d == 0.0 && *e == 0.0 && *b != 0.0 =>
        {
            if *f == 1.0 {
                // phys = (x − c) / b
                if *c == 0.0 {
                    format!("x / {b}")
                } else if *c > 0.0 {
                    format!("(x - {c}) / {b}")
                } else {
                    format!("(x + {}) / {b}", -c)
                }
            } else {
                // phys = x * (f/b) − c/b
                let scale = f / b;
                let offset = -c / b;
                if offset == 0.0 {
                    format!("x * {scale}")
                } else if offset > 0.0 {
                    format!("x * {scale} + {offset}")
                } else {
                    format!("x * {scale} - {}", -offset)
                }
            }
        }

        Conversion::Form { formula } => formula.clone(),

        _ => "x".into(),
    }
}
