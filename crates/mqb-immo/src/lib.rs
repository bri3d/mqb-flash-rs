//! The Simos18 immobilizer: its state, its authentication protocol, and its
//! diagnostic path.
//!
//! The immobilizer has two entirely separate interfaces, and this crate covers
//! both:
//!
//! * **Authentication** ([`auth`]) — a challenge/response between the ECU
//!   (slave) and the instrument cluster (master) over two 8-byte CAN frames on
//!   `0x010` / `0x011`. [`auth::ImmoMaster`] plays the cluster's side.
//! * **Diagnostics** ([`diag`]) — `ImoComDiag`, running on plain UDS DIDs with
//!   no SecurityAccess and no extended session. This is where an identity is
//!   read and written.
//!
//! On top of those sits [`state`], which decodes the unauthenticated status
//! DIDs and applies the pre-flight rules that say whether an ECU will start.
//! The flash wizard and the standalone immobilizer tool share it, so both judge
//! an ECU by the same reasoning. [`adapt`] combines the two interfaces into a
//! plan for moving an identity onto an ECU.
//!
//! Every key in here comes out of the ECU's own encrypted NVRAM (see
//! [`mqb_nvcrypt`]), which already requires the Hitag2 Device-ID keys to read.
//!
//! Nothing in this crate talks to a bus: it takes bytes and produces bytes.
//! Reading DIDs over UDS is `mqb_flash_uds::immo`; carrying authentication
//! frames is the caller's job.
//!
//! # Scope
//!
//! All of this was derived from Simos18 and only Simos18. That gate is enforced
//! by [`state::ImmoSupport`], which is required to build a
//! [`state::ImmoSnapshot`] and is only handed out for that module.

pub mod adapt;
pub mod auth;
pub mod diag;
pub mod state;

pub use adapt::{
    adapt_plan, adapt_preflight, download_flags, pclass_plan, snapshot_key_proof, vin_plan,
    DownloadPlan, PreflightExt, PreflightItem, PreflightLevel,
};
pub use auth::{
    aes128_encrypt_block, classify, crc_master, crc_slave, describe_ecu_status, ecu_status_hint,
    master_key_for_idx_lab, FixedRng, ImmoMaster, MasterEvent, MasterRng, OsRandom, Variant,
    CAN_ID_REQUEST, CAN_ID_RESPONSE, MASTER_KEY_CANDIDATES,
};
pub use diag::{
    download_plaintext, download_value, identity_checksum, imo_error_name, key_proof, wdbi_frame,
    DiagError, DownloadCommand, DID_DOWNLOAD,
};
pub use state::{
    assess, decode_2ed, decode_2ee, decode_2ef, decode_2ff, diff_after_flash, lock_status,
    resolve_state, tuning_status, ExtendedDid, ImmoFinding, ImmoReport, ImmoRule, ImmoSnapshot,
    ImmoState, ImmoSupport, LockStatus, LockoutDid, Severity, StateDid, StatusBitsDid,
    TuningStatus, IMMO_DIDS, IMMO_DIDS_FULL,
};

// Re-exported so a caller can go from a DFlash image to a live exchange without
// naming a second crate.
pub use mqb_nvcrypt::{Dump, Hitag2Keys, ImmoRecord, ImmoSecrets, StStatFct, IMMO_CHANNELS};
