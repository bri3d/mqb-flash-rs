//! Simos18 immobilizer pre-flight check — the UDS side.
//!
//! The decoding and the rules live in [`mqb_immo::state`], so the flash wizard
//! and the standalone immobilizer tool judge an ECU by exactly the same
//! reasoning. This module is the part that needs a transport: reading the
//! status DIDs off a live ECU.
//!
//! Everything the rules layer exports is re-exported here, so callers can keep
//! importing it from `mqb_flash_uds::immo`.
//!
//! All reads are `ReadDataByIdentifier` on the module's normal channel
//! (tester `0x7E0` / ECU `0x7E8`) in the *default* session, with no
//! SecurityAccess and no immobilizer login.

use automotive::TransportLayer;

pub use mqb_immo::state::*;

use crate::flash::read_dids;

/// Read every immobilizer DID in the required order.
///
/// Never fails: DIDs the ECU refuses are simply absent from the snapshot, which
/// the rules treat as [`Severity::Unknown`] (fail-open). Response-pending
/// (NRC `0x78`) is handled inside `UDSClient`.
///
/// Takes an [`ImmoSupport`] token so the module gate cannot be bypassed by
/// reading first and looking for a way to build a snapshot afterwards.
pub async fn read_immo_snapshot<T: TransportLayer>(
    transport: &T,
    support: ImmoSupport,
) -> ImmoSnapshot {
    let dids = read_dids(transport, &IMMO_DIDS).await;
    ImmoSnapshot::from_dids(support, dids)
}
