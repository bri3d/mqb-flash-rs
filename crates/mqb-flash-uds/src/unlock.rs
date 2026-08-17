//! Detecting whether a Simos ECU is already unlocked.
//!
//! "Unlocked" here means the Customer Bootloader (CBOOT) has been patched into
//! sample mode — the patch [`mqb_cboot::patch_cboot`] applies, which forces
//! `is_sample_mode()` to return true and so bypasses RSA signature validation.
//!
//! # How the detection works
//!
//! A patched CBOOT reports an **`X`-prefixed hardware version** on DID `0xF1A3`
//! (`VW ECU Hardware Version Number`) — typically `H13` becomes `X13`.
//!
//! The read is only meaningful **inside CBOOT**, because the application
//! software is not patched and always reports the stock value. So the probe has
//! to enter a programming session first; reading `0xF1A3` in the extended
//! session just asks the ASW, which answers `H13` whether or not the ECU is
//! unlocked.
//!
//! This is confirmed by a captured session (`full_flash_log/filtered.txt`): the
//! sweeps answered by the ASW return `62 f1 a3 48 31 33` (`"H13"`) *and* answer
//! `0xF197` / `0xF1AD` normally, while the sweeps answered by CBOOT return
//! `62 f1 a3 58 31 33` (`"X13"`) and reject `0xF197` / `0xF1AD` with NRC `0x31`
//! — CBOOT implements far fewer DIDs than the ASW.
//!
//! # Why not the SwitchPatch probe
//!
//! An earlier design classified the ECU by whether it accepted `3E 10 02`
//! (SwitchPatch). That is not valid for this tool: we do not apply SwitchPatch,
//! so its behaviour says nothing about whether *our* unlock is present. It is
//! also structurally unreliable — the fallback only runs when the normal
//! session request already failed, and a failure has many innocent causes.
//!
//! # Side effect — the caller must handle this
//!
//! [`probe_unlock_state`] leaves the ECU **sitting in CBOOT**. The engine will
//! not run and normal diagnostics are unavailable until the ECU is reset. A
//! caller that is not going straight on to flash must call
//! [`leave_bootloader`].

use automotive::uds::{RoutineControlType, UDSClient};
use automotive::TransportLayer;

use mqb_modules::FlashInfo;

use crate::flash::FlashError;

/// DID `0xF1A3` — VW ECU Hardware Version Number.
///
/// Read inside CBOOT, this is the unlock marker.
pub const DID_HARDWARE_VERSION: u16 = 0xF1A3;

/// The prefix a patched (sample-mode) CBOOT reports, e.g. `H13` -> `X13`.
const UNLOCKED_PREFIX: u8 = b'X';

/// Whether an ECU's CBOOT has been patched into sample mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockState {
    /// CBOOT reported an `X`-prefixed hardware version — the unlock is present.
    Unlocked,
    /// CBOOT reported a stock hardware version — the ECU still validates
    /// signatures and must be unlocked before modified software will boot.
    Locked,
    /// The probe could not reach a conclusion. Carries a human-readable reason.
    ///
    /// This is deliberately distinct from [`UnlockState::Locked`]: the wizard
    /// must not tell a user their unlocked ECU is locked because a read failed.
    Unknown(String),
}

impl UnlockState {
    /// A short phrase for the UI.
    pub fn label(&self) -> &str {
        match self {
            UnlockState::Unlocked => "Unlocked",
            UnlockState::Locked => "Locked",
            UnlockState::Unknown(_) => "Could not be determined",
        }
    }
}

/// The full result of an unlock probe, including the raw evidence.
#[derive(Debug, Clone)]
pub struct UnlockProbe {
    pub state: UnlockState,
    /// The raw `0xF1A3` payload, if it was read at all.
    pub hardware_version_raw: Option<Vec<u8>>,
    /// The `0xF1A3` payload rendered as text, if it was readable.
    pub hardware_version: Option<String>,
}

/// Classify a raw `0xF1A3` payload **as read inside CBOOT**.
///
/// Pure, so the classification is testable without a bus. Passing a value read
/// outside CBOOT will produce a confidently wrong `Locked`.
pub fn classify_hardware_version(raw: &[u8]) -> UnlockState {
    let text: String = String::from_utf8_lossy(raw).trim().to_owned();

    match raw.first() {
        None => UnlockState::Unknown("ECU returned an empty hardware version".into()),
        Some(&UNLOCKED_PREFIX) => UnlockState::Unlocked,
        // Any other *plausible* revision string means a stock bootloader. We
        // do not require it to be exactly "H13": revisions vary across hardware
        // and only the X prefix is the patch marker.
        Some(&c) if c.is_ascii_alphanumeric() => UnlockState::Locked,
        Some(&c) => UnlockState::Unknown(format!(
            "hardware version starts with a non-printable byte 0x{c:02X} \
             (read: {text:?})"
        )),
    }
}

/// Whether an unlock even applies to this module.
///
/// Only the Simos variants carry an unlock patch; the transmission and AWD
/// modules have `patch_info: None` and must never be shown an unlock step.
pub fn supports_unlock(flash_info: &FlashInfo) -> bool {
    flash_info.patch_info.is_some()
}

/// Enter CBOOT and read the hardware version to determine the unlock state.
///
/// Leaves the ECU in the programming session (i.e. in CBOOT) — see the module
/// docs. Returns `Unknown` rather than an error for anything that merely means
/// "could not tell", and reserves `Err` for a transport-level failure.
pub async fn probe_unlock_state<T: TransportLayer>(
    transport: &T,
    flash_info: &FlashInfo,
) -> Result<UnlockProbe, FlashError> {
    if !supports_unlock(flash_info) {
        return Ok(UnlockProbe {
            state: UnlockState::Unknown(
                "this control module has no unlock patch, so the concept does not apply".into(),
            ),
            hardware_version_raw: None,
            hardware_version: None,
        });
    }

    let uds = UDSClient::new(transport);

    // 1. Extended session.
    uds.diagnostic_session_control(0x03).await?;

    // 2. Programming precondition. The ECU refuses the programming session if
    //    this has not run — same order the captured tester session uses.
    if let Err(e) = uds
        .routine_control(RoutineControlType::Start, 0x0203, None)
        .await
    {
        return Ok(unknown(format!(
            "the ECU refused the programming precondition check ({e}); \
             it will not enter the bootloader (engine running, or voltage out of range?)"
        )));
    }

    uds.tester_present().await?;

    // 3. Programming session — this is what puts the ECU into CBOOT, and it is
    //    the whole reason the probe has a side effect.
    if let Err(e) = uds.diagnostic_session_control(0x02).await {
        return Ok(unknown(format!(
            "the ECU would not enter the bootloader ({e}), so its unlock state \
             cannot be read"
        )));
    }

    // 4. CBOOT is answering now — read the marker.
    match uds.read_data_by_identifier(DID_HARDWARE_VERSION).await {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes).trim().to_owned();
            let state = classify_hardware_version(&bytes);
            tracing::info!(
                hardware_version = %text,
                state = state.label(),
                "Unlock probe complete"
            );
            Ok(UnlockProbe {
                state,
                hardware_version: Some(text),
                hardware_version_raw: Some(bytes),
            })
        }
        Err(e) => Ok(unknown(format!(
            "the bootloader did not answer the hardware-version request ({e})"
        ))),
    }
}

fn unknown(reason: String) -> UnlockProbe {
    tracing::warn!("Unlock probe inconclusive: {reason}");
    UnlockProbe {
        state: UnlockState::Unknown(reason),
        hardware_version_raw: None,
        hardware_version: None,
    }
}

/// Reset the ECU so it leaves CBOOT and boots the application again.
///
/// Call this after [`probe_unlock_state`] whenever the caller is **not** going
/// on to flash. The ECU hard-resets and normally does not answer, so a timeout
/// is the expected outcome and is not an error.
pub async fn leave_bootloader<T: TransportLayer>(transport: &T) -> Result<(), FlashError> {
    let uds = UDSClient::new(transport);
    match uds.ecu_reset(0x01).await {
        Ok(_) => Ok(()),
        Err(automotive::Error::Timeout) => {
            tracing::debug!("ECUReset: no response (expected — the ECU is rebooting)");
            Ok(())
        }
        Err(e) => Err(FlashError::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mqb_modules::modules::{
        dq250mqb::DQ250_FLASH_INFO, haldex4motion::HALDEX_FLASH_INFO, simos18::S18_FLASH_INFO,
    };

    /// The exact bytes captured from hardware, both states.
    /// `full_flash_log/filtered.txt`: `62 f1 a3 48 31 33` and `62 f1 a3 58 31 33`.
    #[test]
    fn classifies_the_real_captured_values() {
        assert_eq!(classify_hardware_version(b"H13"), UnlockState::Locked);
        assert_eq!(classify_hardware_version(b"X13"), UnlockState::Unlocked);
        // As they arrive on the wire, from the capture.
        assert_eq!(
            classify_hardware_version(&[0x48, 0x31, 0x33]),
            UnlockState::Locked
        );
        assert_eq!(
            classify_hardware_version(&[0x58, 0x31, 0x33]),
            UnlockState::Unlocked
        );
    }

    /// Only the X prefix is the marker — other revisions are stock, not unknown.
    #[test]
    fn other_revisions_read_as_locked() {
        for v in [&b"H13"[..], b"J13", b"H01", b"K22"] {
            assert_eq!(classify_hardware_version(v), UnlockState::Locked, "{v:?}");
        }
    }

    /// An unreadable answer must never be reported as Locked — telling a user
    /// their unlocked ECU is locked would send them to re-flash the unlock.
    #[test]
    fn unreadable_answers_are_unknown_not_locked() {
        assert!(matches!(
            classify_hardware_version(b""),
            UnlockState::Unknown(_)
        ));
        assert!(matches!(
            classify_hardware_version(&[0x00]),
            UnlockState::Unknown(_)
        ));
    }

    /// The prefix check must be anchored at the start, not a substring search.
    #[test]
    fn x_elsewhere_in_the_string_is_not_an_unlock() {
        assert_eq!(classify_hardware_version(b"H1X"), UnlockState::Locked);
        assert_eq!(classify_hardware_version(b"HX3"), UnlockState::Locked);
    }

    #[test]
    fn unlock_only_applies_to_modules_with_a_patch() {
        assert!(supports_unlock(&S18_FLASH_INFO));
        assert!(!supports_unlock(&DQ250_FLASH_INFO));
        assert!(!supports_unlock(&HALDEX_FLASH_INFO));
    }
}
