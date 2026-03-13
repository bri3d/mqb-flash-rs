//! UDS session management and ECU flashing.

pub mod interface;
pub mod flash;
pub mod fake_adapter;

pub use interface::Interface;
pub use flash::{FlashError, FlashOptions, ProgressUpdate, flash_blocks, read_ecu_data, prepare_block_for_flash, prepare_patch_for_flash};
pub use fake_adapter::FakeCanAdapter;
pub use mqb_sa2::Sa2Vm;
#[cfg(feature = "j2534")]
pub use automotive::j2534::{J2534CanAdapter, J2534NativeIsoTpTransport};
pub use automotive::TransportLayer;
