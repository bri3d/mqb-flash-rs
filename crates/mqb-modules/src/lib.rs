//! Shared types, crypto implementations, and per-ECU flash configurations.

pub mod crypto;
pub mod modules;
pub mod registry;
pub mod types;

pub use crypto::{AesCrypto, BlockCrypto, DsgCrypto, NoCrypto, SimosXorCrypto};
pub use registry::{get_flash_info, module_names};
pub use types::*;
