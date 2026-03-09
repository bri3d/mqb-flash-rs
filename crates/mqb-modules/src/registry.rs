//! Module registry — maps module names to FlashInfo configs.
//!
//! This is the canonical source of truth shared by the CLI and GUI.

use crate::FlashInfo;
use crate::modules::{
    simos18::S18_FLASH_INFO,
    simos122::S122_FLASH_INFO,
    simos1810::S1810_FLASH_INFO,
    simos184::S184_FLASH_INFO,
    simos16::S16_FLASH_INFO,
    simos10::S10_FLASH_INFO,
    simos8::S8_FLASH_INFO,
    simos12::S12_FLASH_INFO,
    dq250mqb::DQ250_FLASH_INFO,
    dq381::DQ381_FLASH_INFO,
    haldex4motion::HALDEX_FLASH_INFO,
};

/// All supported module names (including aliases) and their configs.
///
/// Aliases share the same `&FlashInfo`.  `module_names()` returns only the
/// canonical (first) name for each unique config.
pub static MODULES: &[(&str, &FlashInfo)] = &[
    ("simos18",       &S18_FLASH_INFO),
    ("simos122",      &S122_FLASH_INFO),
    ("simos1810",     &S1810_FLASH_INFO),
    ("simos184",      &S184_FLASH_INFO),
    ("simos16",       &S16_FLASH_INFO),
    ("simos10",       &S10_FLASH_INFO),
    ("simos8",        &S8_FLASH_INFO),
    ("simos12",       &S12_FLASH_INFO),
    ("dq250",         &DQ250_FLASH_INFO),
    ("dq250mqb",      &DQ250_FLASH_INFO), // alias
    ("dsg",           &DQ250_FLASH_INFO), // alias
    ("dq381",         &DQ381_FLASH_INFO),
    ("haldex",        &HALDEX_FLASH_INFO),
    ("haldex4motion", &HALDEX_FLASH_INFO), // alias
];

/// Look up a [`FlashInfo`] by its module name (including aliases).
pub fn get_flash_info(name: &str) -> Option<&'static FlashInfo> {
    MODULES.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
}

/// List canonical module names (one per unique ECU config, no aliases).
pub fn module_names() -> Vec<&'static str> {
    let mut seen: Vec<*const FlashInfo> = Vec::new();
    MODULES
        .iter()
        .filter_map(|(name, info)| {
            let ptr = *info as *const FlashInfo;
            if seen.contains(&ptr) {
                None
            } else {
                seen.push(ptr);
                Some(*name)
            }
        })
        .collect()
}
