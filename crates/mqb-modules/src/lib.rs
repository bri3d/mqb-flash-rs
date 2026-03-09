//! Shared types, crypto implementations, and per-ECU flash configurations.

pub mod types;
pub mod crypto;
pub mod modules;
pub mod registry;

pub use types::*;
pub use crypto::{BlockCrypto, AesCrypto, SimosXorCrypto, DsgCrypto, NoCrypto};
pub use registry::{get_flash_info, module_names};
