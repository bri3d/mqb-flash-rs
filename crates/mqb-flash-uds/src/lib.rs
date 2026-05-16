//! UDS session management and ECU flashing.

pub mod flash;

pub use flash::{FlashError, FlashOptions, ProgressUpdate, flash_blocks, read_ecu_data, prepare_block_for_flash, prepare_patch_for_flash};
pub use mqb_sa2::Sa2Vm;
#[cfg(feature = "j2534")]
pub use automotive::j2534::{J2534CanAdapter, J2534NativeIsoTpTransport};
pub use automotive::TransportLayer;

// The transport layer (interface selection + fake adapter) lives in the
// `mqb-transport` crate.  Re-export the items dependents import from here so
// `mqb-flash-cli`, `mqb-flash-gui`, and the tests keep working unchanged.
pub use mqb_transport::{FakeCanAdapter, Interface};
