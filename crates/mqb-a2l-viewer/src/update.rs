use std::collections::HashSet;
use std::sync::Arc;

use iced::widget::scrollable::{self, RelativeOffset};
use iced::{keyboard, Task};

use mqb_a2l::reader::{CharacteristicValues, make_resolver, read_characteristic};
use mqb_a2l::A2lFile;

use crate::data::{address_map_for, build_categories};
use crate::state::{Msg, State};

pub fn subscription(_state: &State) -> iced::Subscription<Msg> {
    keyboard::on_key_press(|key, _modifiers| {
        match key {
            keyboard::Key::Named(keyboard::key::Named::ArrowDown) => Some(Msg::SelectNext),
            keyboard::Key::Named(keyboard::key::Named::ArrowUp) => Some(Msg::SelectPrev),
            _ => None,
        }
    })
}

pub fn update(state: &mut State, msg: Msg) -> Task<Msg> {
    match msg {
        Msg::LoadA2l => {
            state.loading_a2l = true;
            state.a2l_error = None;
            return Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Open A2L file")
                        .add_filter("A2L files", &["a2l", "A2L"])
                        .pick_file()
                        .await
                        .map(|h| h.path().to_path_buf())
                },
                Msg::A2lPicked,
            );
        }
        Msg::A2lPicked(Some(path)) => {
            state.a2l_path = Some(path.clone());
            return Task::perform(
                async move {
                    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
                    let a2l = mqb_a2l::parse(&bytes).map_err(|e| e.to_string())?;
                    Ok(Arc::new(a2l))
                },
                Msg::A2lLoaded,
            );
        }
        Msg::A2lPicked(None) => {
            state.loading_a2l = false;
        }
        Msg::A2lLoaded(Ok(a2l)) => {
            let (categories, char_to_cats) = build_categories(&a2l);
            state.categories = categories;
            state.char_to_cats = char_to_cats;
            state.a2l = Some(a2l);
            state.loading_a2l = false;
            state.selected = None;
            state.cached_values = None;
            state.cached_values2 = None;
            state.selected_category = None;
            state.changed_set.clear();
            state.rebuild_filter();
        }
        Msg::A2lLoaded(Err(e)) => {
            state.a2l_error = Some(e);
            state.loading_a2l = false;
        }
        Msg::LoadBin => {
            state.loading_bin = true;
            state.bin_error = None;
            return Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Open firmware binary")
                        .add_filter("Binary files", &["bin", "BIN"])
                        .pick_file()
                        .await
                        .map(|h| h.path().to_path_buf())
                },
                Msg::BinPicked,
            );
        }
        Msg::BinPicked(Some(path)) => {
            state.bin_path = Some(path.clone());
            return Task::perform(
                async move {
                    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
                    Ok(Arc::new(data))
                },
                Msg::BinLoaded,
            );
        }
        Msg::BinPicked(None) => {
            state.loading_bin = false;
        }
        Msg::BinLoaded(Ok(data)) => {
            state.binary = Some(data);
            state.loading_bin = false;
            state.read_selected();
            // Recompute changed set if bin2 is also loaded
            return maybe_compute_changes(state);
        }
        Msg::BinLoaded(Err(e)) => {
            state.bin_error = Some(e);
            state.loading_bin = false;
        }
        Msg::LoadBin2 => {
            state.loading_bin2 = true;
            state.bin2_error = None;
            return Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .set_title("Open comparison binary")
                        .add_filter("Binary files", &["bin", "BIN"])
                        .pick_file()
                        .await
                        .map(|h| h.path().to_path_buf())
                },
                Msg::Bin2Picked,
            );
        }
        Msg::Bin2Picked(Some(path)) => {
            state.bin2_path = Some(path.clone());
            return Task::perform(
                async move {
                    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
                    Ok(Arc::new(data))
                },
                Msg::Bin2Loaded,
            );
        }
        Msg::Bin2Picked(None) => {
            state.loading_bin2 = false;
        }
        Msg::Bin2Loaded(Ok(data)) => {
            state.binary2 = Some(data);
            state.loading_bin2 = false;
            state.compare_mode = true;
            state.read_selected();
            return maybe_compute_changes(state);
        }
        Msg::Bin2Loaded(Err(e)) => {
            state.bin2_error = Some(e);
            state.loading_bin2 = false;
        }
        Msg::ModuleChanged(m) => {
            state.module = m;
            state.address_map = address_map_for(m);
            state.read_selected();
            return maybe_compute_changes(state);
        }
        Msg::CategoryChanged(cat) => {
            state.selected_category = Some(cat);
            state.rebuild_filter();
        }
        Msg::ClearCategory => {
            state.selected_category = None;
            state.rebuild_filter();
        }
        Msg::FilterChanged(f) => {
            state.filter = f;
            state.rebuild_filter();
        }
        Msg::SelectChar(idx) => {
            state.selected = Some(idx);
            state.read_selected();
        }
        Msg::SelectNext => {
            state.move_selection(1);
            return scroll_to_selected(state);
        }
        Msg::SelectPrev => {
            state.move_selection(-1);
            return scroll_to_selected(state);
        }
        Msg::ToggleCompare(on) => {
            state.compare_mode = on;
            if !on {
                state.show_changed_only = false;
            }
            state.read_selected();
            state.rebuild_filter();
        }
        Msg::ToggleChangedOnly(on) => {
            state.show_changed_only = on;
            state.rebuild_filter();
        }
        Msg::ChangedSetComputed { changed, axis_changed_values_same } => {
            state.changed_set = changed;
            state.axis_changed_values_same = axis_changed_values_same;
            state.computing_changes = false;
            // Rebuild filter in case show_changed_only is active
            state.rebuild_filter();
        }
    }
    Task::none()
}

/// Scroll the characteristic list so the selected item is visible.
fn scroll_to_selected(state: &State) -> Task<Msg> {
    let Some(sel) = state.selected else { return Task::none() };
    let Some(pos) = state.filtered.iter().position(|&i| i == sel) else { return Task::none() };
    let len = state.filtered.len();
    let y = if len <= 1 { 0.0 } else { pos as f32 / (len - 1) as f32 };
    scrollable::snap_to(crate::CHAR_LIST_ID(), RelativeOffset { x: 0.0, y })
}

/// Kick off background computation of changed characteristic indices.
fn maybe_compute_changes(state: &mut State) -> Task<Msg> {
    let Some(a2l) = &state.a2l else { return Task::none() };
    let Some(bin1) = &state.binary else { return Task::none() };
    let Some(bin2) = &state.binary2 else { return Task::none() };

    state.computing_changes = true;
    state.changed_set.clear();
    state.axis_changed_values_same.clear();

    let a2l = Arc::clone(a2l);
    let bin1 = Arc::clone(bin1);
    let bin2 = Arc::clone(bin2);
    let map = state.address_map.clone();

    Task::perform(
        async move {
            compute_changed_set(&a2l, &bin1, &bin2, &map)
        },
        |(changed, axis_changed_values_same)| Msg::ChangedSetComputed {
            changed,
            axis_changed_values_same,
        },
    )
}

/// Compare all characteristics between two binaries.
/// Returns (changed_indices, axis_changed_values_same_indices).
fn compute_changed_set(
    a2l: &A2lFile,
    bin1: &[u8],
    bin2: &[u8],
    map: &mqb_a2l::reader::AddressMap,
) -> (HashSet<usize>, HashSet<usize>) {
    let resolve = make_resolver(map);
    let mut changed = HashSet::new();
    let mut axis_changed_values_same = HashSet::new();
    for (i, ch) in a2l.characteristics.iter().enumerate() {
        let v1 = read_characteristic(ch, a2l, bin1, &resolve);
        let v2 = read_characteristic(ch, a2l, bin2, &resolve);
        match (&v1, &v2) {
            (Some(a), Some(b)) if a != b => {
                changed.insert(i);
                if has_axis_change_without_rescale(a, b) {
                    axis_changed_values_same.insert(i);
                }
            }
            (None, Some(_)) | (Some(_), None) => { changed.insert(i); }
            _ => {}
        }
    }
    (changed, axis_changed_values_same)
}

/// Returns true if the axes differ but the data values are identical —
/// suggesting the values may not have been rescaled for the new axis.
fn has_axis_change_without_rescale(a: &CharacteristicValues, b: &CharacteristicValues) -> bool {
    match (a, b) {
        (
            CharacteristicValues::Curve { x: x1, y: y1 },
            CharacteristicValues::Curve { x: x2, y: y2 },
        ) => x1 != x2 && y1 == y2,
        (
            CharacteristicValues::Map { x: x1, y: y1, z: z1 },
            CharacteristicValues::Map { x: x2, y: y2, z: z2 },
        ) => (x1 != x2 || y1 != y2) && z1 == z2,
        (
            CharacteristicValues::Cuboid { x: x1, y: y1, z: z1, w: w1 },
            CharacteristicValues::Cuboid { x: x2, y: y2, z: z2, w: w2 },
        ) => (x1 != x2 || y1 != y2 || z1 != z2) && w1 == w2,
        _ => false,
    }
}
