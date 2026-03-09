//! UDS session management and ECU flashing.

pub mod interface;
pub mod flash;
pub mod fake_adapter;
#[cfg(feature = "j2534")]
mod j2534_common;
#[cfg(feature = "j2534")]
pub mod j2534_adapter;
#[cfg(feature = "j2534")]
pub mod j2534_isotp_adapter;

pub use interface::Interface;
pub use flash::{FlashError, FlashOptions, ProgressUpdate, flash_blocks, read_ecu_data, prepare_block_for_flash, prepare_patch_for_flash};
pub use fake_adapter::FakeCanAdapter;
pub use mqb_sa2::Sa2Vm;
#[cfg(feature = "j2534")]
pub use j2534_adapter::J2534CanAdapter;
#[cfg(feature = "j2534")]
pub use j2534_isotp_adapter::J2534NativeIsoTpTransport;
pub use automotive::IsoTpTransport;
