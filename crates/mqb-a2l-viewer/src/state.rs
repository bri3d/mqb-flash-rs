use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use mqb_a2l::reader::{AddressMap, CharacteristicValues, make_resolver, read_characteristic};
use mqb_a2l::A2lFile;

use crate::data::{Category, ModulePreset, address_map_for};
use crate::MAX_DISPLAY;

pub struct State {
    // A2L
    pub a2l_path: Option<PathBuf>,
    pub a2l: Option<Arc<A2lFile>>,
    pub loading_a2l: bool,
    pub a2l_error: Option<String>,

    // Firmware binary 1 (base)
    pub bin_path: Option<PathBuf>,
    pub binary: Option<Arc<Vec<u8>>>,
    pub loading_bin: bool,
    pub bin_error: Option<String>,

    // Firmware binary 2 (compare)
    pub bin2_path: Option<PathBuf>,
    pub binary2: Option<Arc<Vec<u8>>>,
    pub loading_bin2: bool,
    pub bin2_error: Option<String>,

    // Module
    pub module: ModulePreset,
    pub address_map: AddressMap,

    // Categories
    pub categories: Vec<Category>,
    pub char_to_cats: HashMap<usize, Vec<String>>,
    pub selected_category: Option<Category>,

    // Filter
    pub filter: String,
    pub filtered: Vec<usize>,
    pub total_matches: usize,

    // Selection
    pub selected: Option<usize>,
    pub cached_values: Option<CharacteristicValues>,
    pub cached_values2: Option<CharacteristicValues>,

    // Compare mode
    pub compare_mode: bool,
    pub show_changed_only: bool,
    pub changed_set: HashSet<usize>,
    pub computing_changes: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            a2l_path: None,
            a2l: None,
            loading_a2l: false,
            a2l_error: None,
            bin_path: None,
            binary: None,
            loading_bin: false,
            bin_error: None,
            bin2_path: None,
            binary2: None,
            loading_bin2: false,
            bin2_error: None,
            module: ModulePreset::Simos18,
            address_map: address_map_for(ModulePreset::Simos18),
            categories: Vec::new(),
            char_to_cats: HashMap::new(),
            selected_category: None,
            filter: String::new(),
            filtered: Vec::new(),
            total_matches: 0,
            selected: None,
            cached_values: None,
            cached_values2: None,
            compare_mode: false,
            show_changed_only: false,
            changed_set: HashSet::new(),
            computing_changes: false,
        }
    }
}

impl State {
    pub fn rebuild_filter(&mut self) {
        let Some(a2l) = &self.a2l else {
            self.filtered.clear();
            self.total_matches = 0;
            return;
        };
        let filt = self.filter.to_lowercase();
        let cat_filter: Option<&str> = self.selected_category.as_ref().map(|c| c.name.as_str());

        let mut all: Vec<usize> = a2l
            .characteristics
            .iter()
            .enumerate()
            .filter(|(i, c)| {
                // Category filter
                if let Some(cat_name) = cat_filter {
                    let in_cat = self.char_to_cats.get(i)
                        .map(|cats| cats.iter().any(|cn| cn == cat_name))
                        .unwrap_or(false);
                    if !in_cat { return false; }
                }
                // Changed-only filter
                if self.show_changed_only && !self.changed_set.is_empty()
                    && !self.changed_set.contains(i) { return false; }
                // Text filter
                filt.is_empty()
                    || c.name.to_lowercase().contains(&filt)
                    || c.description.to_lowercase().contains(&filt)
            })
            .map(|(i, _)| i)
            .collect();
        self.total_matches = all.len();
        all.truncate(MAX_DISPLAY);
        self.filtered = all;
    }

    pub fn read_selected(&mut self) {
        self.cached_values = None;
        self.cached_values2 = None;
        let Some(idx) = self.selected else { return };
        let Some(a2l) = &self.a2l else { return };
        let ch = &a2l.characteristics[idx];
        let resolve = make_resolver(&self.address_map);
        if let Some(binary) = &self.binary {
            self.cached_values = read_characteristic(ch, a2l, binary, &resolve);
        }
        if let Some(binary2) = &self.binary2 {
            self.cached_values2 = read_characteristic(ch, a2l, binary2, &resolve);
        }
    }

    /// Move selection to next/prev item in filtered list.
    pub fn move_selection(&mut self, delta: isize) {
        if self.filtered.is_empty() { return; }
        let current_pos = self.selected
            .and_then(|sel| self.filtered.iter().position(|&i| i == sel));
        let new_pos = match current_pos {
            Some(pos) => (pos as isize + delta).clamp(0, self.filtered.len() as isize - 1) as usize,
            None => if delta > 0 { 0 } else { self.filtered.len() - 1 },
        };
        self.selected = Some(self.filtered[new_pos]);
        self.read_selected();
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    LoadA2l,
    A2lPicked(Option<PathBuf>),
    A2lLoaded(Result<Arc<A2lFile>, String>),
    LoadBin,
    BinPicked(Option<PathBuf>),
    BinLoaded(Result<Arc<Vec<u8>>, String>),
    LoadBin2,
    Bin2Picked(Option<PathBuf>),
    Bin2Loaded(Result<Arc<Vec<u8>>, String>),
    ModuleChanged(ModulePreset),
    CategoryChanged(Category),
    ClearCategory,
    FilterChanged(String),
    SelectChar(usize),
    SelectNext,
    SelectPrev,
    ToggleCompare(bool),
    ToggleChangedOnly(bool),
    ChangedSetComputed(HashSet<usize>),
}
