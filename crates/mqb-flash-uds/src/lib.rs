//! UDS session management and ECU flashing.

pub mod fixup;
pub mod flash;
pub mod identify;
pub mod immo;
pub mod prepare;
pub mod unlock;
pub mod workshop;

#[cfg(feature = "j2534")]
pub use automotive::j2534::{J2534CanAdapter, J2534NativeIsoTpTransport};
pub use automotive::TransportLayer;
pub use fixup::{checksum_and_patch_blocks, FixupError, FixupReport};
pub use flash::{
    flash_blocks, make_isotp_config, open_extended_session, probe, read_dids, read_ecu_data,
    read_ecu_with_transport, FlashError, FlashOptions, ProbeKind, ProbeOutcome, ProgressUpdate,
};
pub use identify::{
    candidates_from_dids, identify_on_channel, Candidate, ChannelIdentification, ChannelKind,
    Confidence, IDENT_CHANNELS, IDENT_DIDS,
};
pub use immo::{
    assess as assess_immo, diff_after_flash, read_immo_snapshot, ImmoFinding, ImmoReport,
    ImmoSnapshot, ImmoSupport, Severity,
};
pub use mqb_sa2::Sa2Vm;
pub use prepare::{
    compress_and_encrypt, prepare_block, prepare_block_for_flash, prepare_patch_block,
    prepare_patch_for_flash,
};
pub use unlock::{leave_bootloader, probe_unlock_state, UnlockProbe, UnlockState};
pub use workshop::WorkshopCode;

// The transport layer (interface selection + fake adapter) lives in the
// `mqb-transport` crate.  Re-export the items dependents import from here so
// `mqb-flash-cli`, `mqb-flash-gui`, and the tests keep working unchanged.
pub use mqb_transport::{FakeCanAdapter, Interface};
