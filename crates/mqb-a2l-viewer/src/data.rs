use std::collections::{HashMap, HashSet};

use mqb_a2l::reader::AddressMap;
use mqb_a2l::A2lFile;

/// Known Simos18 address map: (base_addr, file_offset, block_length).
const SIMOS18_MAP: &[(u32, usize, usize)] = &[
    (0x80000000, 0x000000, 0x01C000),  // SBOOT
    (0x8001C000, 0x01C000, 0x023E00),  // CBOOT
    (0x80040000, 0x040000, 0x0FFC00),  // ASW1
    (0x80140000, 0x140000, 0x0BFC00),  // ASW2
    (0x80880000, 0x280000, 0x07FC00),  // ASW3
    (0xA0800000, 0x200000, 0x07FC00),  // CAL
];

/// Simos18.10 address map — different base addresses and file layout.
const SIMOS1810_MAP: &[(u32, usize, usize)] = &[
    (0x80800000, 0x200000, 0x01FE00),  // CBOOT
    (0x80020000, 0x020000, 0x0DFC00),  // ASW1
    (0x80100000, 0x100000, 0x0FFC00),  // ASW2
    (0x808C0000, 0x2C0000, 0x13FC00),  // ASW3
    (0xA0820000, 0x220000, 0x09FC00),  // CAL
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModulePreset {
    Simos18,
    Simos1810,
}

impl std::fmt::Display for ModulePreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModulePreset::Simos18 => write!(f, "Simos18 (SC8)"),
            ModulePreset::Simos1810 => write!(f, "Simos18.10 (SCG)"),
        }
    }
}

pub const MODULE_PRESETS: &[ModulePreset] = &[ModulePreset::Simos18, ModulePreset::Simos1810];

pub fn address_map_for(preset: ModulePreset) -> AddressMap {
    match preset {
        ModulePreset::Simos18 => SIMOS18_MAP.to_vec(),
        ModulePreset::Simos1810 => SIMOS1810_MAP.to_vec(),
    }
}

/// A display-friendly category entry for the dropdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    /// Display label: "AIRM — Air motion"
    pub label: String,
    /// The parent function name (used as key).
    pub name: String,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

/// Build categories from parsed FUNCTION blocks.
///
/// Returns: (sorted category list, char_index → set of category names)
pub fn build_categories(a2l: &A2lFile) -> (Vec<Category>, HashMap<usize, Vec<String>>) {
    // 1. Collect sub-function children for each parent
    let mut parent_children: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut is_child: HashSet<&str> = HashSet::new();
    let func_map: HashMap<&str, &mqb_a2l::Function> = a2l.functions.iter()
        .map(|f| (f.name.as_str(), f))
        .collect();

    for func in &a2l.functions {
        if !func.sub_functions.is_empty() {
            for child_name in &func.sub_functions {
                is_child.insert(child_name.as_str());
                parent_children.entry(&func.name)
                    .or_default()
                    .push(child_name.as_str());
            }
        }
    }

    // 2. Build char_name → index lookup
    let char_idx: HashMap<&str, usize> = a2l.characteristics.iter()
        .enumerate()
        .map(|(i, c)| (c.name.as_str(), i))
        .collect();

    // 3. For each parent function, collect all characteristic indices
    //    from its sub-functions' DEF_CHARACTERISTIC + REF_CHARACTERISTIC
    let mut cat_chars: HashMap<String, HashSet<usize>> = HashMap::new();

    // Helper: collect chars from a function into a set
    let collect_func_chars = |func_name: &str, set: &mut HashSet<usize>| {
        if let Some(func) = func_map.get(func_name) {
            for cname in func.def_characteristics.iter().chain(func.ref_characteristics.iter()) {
                if let Some(&idx) = char_idx.get(cname.as_str()) {
                    set.insert(idx);
                }
            }
        }
    };

    for func in &a2l.functions {
        if !func.sub_functions.is_empty() {
            let set = cat_chars.entry(func.name.clone()).or_default();
            // Include the parent's own chars too
            collect_func_chars(&func.name, set);
            // Include all sub-function chars
            for child_name in &func.sub_functions {
                collect_func_chars(child_name, set);
            }
        }
    }

    // Also include leaf functions that aren't children of any parent as their own category
    for func in &a2l.functions {
        if func.sub_functions.is_empty() && !is_child.contains(func.name.as_str()) {
            let has_chars = !func.def_characteristics.is_empty() || !func.ref_characteristics.is_empty();
            if has_chars {
                let set = cat_chars.entry(func.name.clone()).or_default();
                collect_func_chars(&func.name, set);
            }
        }
    }

    // 4. Build sorted category list (only categories with chars)
    let mut categories: Vec<Category> = cat_chars.keys()
        .filter(|name| {
            cat_chars.get(*name).map(|s| !s.is_empty()).unwrap_or(false)
        })
        .map(|name| {
            let desc = func_map.get(name.as_str())
                .map(|f| f.description.as_str())
                .unwrap_or("");
            let label = if desc.is_empty() {
                name.clone()
            } else {
                format!("{name} — {desc}")
            };
            Category { label, name: name.clone() }
        })
        .collect();
    categories.sort_by(|a, b| a.name.cmp(&b.name));

    // 5. Build reverse map: char_idx → list of category names
    let mut char_to_cats: HashMap<usize, Vec<String>> = HashMap::new();
    for (cat_name, indices) in &cat_chars {
        for &idx in indices {
            char_to_cats.entry(idx).or_default().push(cat_name.clone());
        }
    }

    (categories, char_to_cats)
}
