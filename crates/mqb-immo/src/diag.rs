//! The immobilizer diagnostic path (`ImoComDiag`).
//!
//! Entirely separate from the CAN authentication in [`crate::auth`] — different
//! transport, message layout and derivation — but keyed with the **same**
//! `noKeySecu`. It runs on ordinary `ReadDataByIdentifier` /
//! `WriteDataByIdentifier` on the powertrain channel (`0x7E0` / `0x7E8`).
//!
//! **The two write DIDs are dispatched before any session or security check.**
//! Immobilizer download needs no SecurityAccess and no extended session; the
//! only thing protecting it is knowledge of `noKeySecu`.
//!
//! Because the Imo state machine runs at 10 ms and its AES is sliced across
//! cycles, a request is answered over several of them: the ECU replies NRC
//! `0x78` (responsePending) until it has an answer. `UDSClient` handles that.
//!
//! This module builds and decodes messages. It does not send them.

use crate::auth::aes128_encrypt_block;

// ── DIDs ──────────────────────────────────────────────────────────────────────

/// Imo service 1 — get a 4-byte challenge.
pub const DID_CHALLENGE: u16 = 0x02E0;
/// Imo service 2 — login (write).
pub const DID_LOGIN: u16 = 0x02E1;
/// Imo service 6 — download / adaptation (write).
pub const DID_DOWNLOAD: u16 = 0x02E2;
/// Imo service 3 — adaptation status.
pub const DID_ADAPT_STATUS: u16 = 0x02ED;
/// Imo service 4 — live immobilizer state.
pub const DID_LIVE_STATE: u16 = 0x02EE;
/// Imo service 5 — lockout timers.
pub const DID_LOCKOUTS: u16 = 0x02EF;
/// Imo service 7 — signed identity checksum.
pub const DID_IDENTITY_CKS: u16 = 0x02F9;
/// Imo service 8 — fault/environment snapshot.
pub const DID_SNAPSHOT: u16 = 0x02FF;
/// Imo service 9 — VIN.
pub const DID_VIN: u16 = 0xF190;
/// Imo service 11 — the FAZIT production string.
pub const DID_FAZIT: u16 = 0xF17C;

/// Expected length of the FAZIT string.
pub const FAZIT_LEN: usize = 23;
/// Expected length of a VIN.
pub const VIN_LEN: usize = 17;
/// Length of the download service's decrypted record.
pub const DOWNLOAD_PLAINTEXT_LEN: usize = 0x30;
/// Length of the DID `0x2E2` value: three AES blocks plus the plaintext CRC32.
pub const DOWNLOAD_VALUE_LEN: usize = DOWNLOAD_PLAINTEXT_LEN + 4;

/// The 12-byte tail appended to the CRC32 before the identity checksum's AES.
const CKS_TAIL: [u8; 12] = [
    0x0c, 0xc3, 0x48, 0x95, 0x0d, 0x30, 0x89, 0xa2, 0x3f, 0x47, 0xe6, 0x58,
];

// ── Download record (service 6, DID 0x2E2) ────────────────────────────────────

/// `plaintext[0x22]` bit 7 — leaves the ECU in `stStatFct` 4 (adaptation mode).
///
/// `node_fcn24` refuses the record without it, so it is not optional.
pub const DOWNLOAD_FLAG_ADAPTATION: u8 = 0x80;
/// `plaintext[0x22]` bit 6 — `bAuthMute`.
pub const DOWNLOAD_FLAG_AUTH_MUTE: u8 = 0x40;
/// `plaintext[0x22]` bit 5 — `bVldChkDi`.
pub const DOWNLOAD_FLAG_VLD_CHK_DI: u8 = 0x20;
/// `plaintext[0x22]` bit 4 — `bTrigFctDi`.
pub const DOWNLOAD_FLAG_TRIG_FCT_DI: u8 = 0x10;
/// `plaintext[0x22]` bit 3 — `bLimModEna`.
pub const DOWNLOAD_FLAG_LIM_MOD_ENA: u8 = 0x08;

/// What the download service should do with the record it just decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadCommand {
    /// 1 — clear `noKeySecu` and reset the immobilizer data set.
    ClearKeyAndReset,
    /// 2 — take `noKeySecu` from the record and reset the data set.
    SetKeyAndReset,
    /// 3 — set the key and adopt the whole record. The normal case.
    SetKeyAndAdopt,
}

impl DownloadCommand {
    pub fn raw(self) -> u8 {
        match self {
            DownloadCommand::ClearKeyAndReset => 1,
            DownloadCommand::SetKeyAndReset => 2,
            DownloadCommand::SetKeyAndAdopt => 3,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DownloadCommand::ClearKeyAndReset => "clear key + data reset",
            DownloadCommand::SetKeyAndReset => "set key + data reset",
            DownloadCommand::SetKeyAndAdopt => "set key + adopt record",
        }
    }
}

/// Why a download record could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiagError {
    #[error("a VIN must be exactly {VIN_LEN} bytes, got {got}")]
    BadVinLength { got: usize },
    #[error("the FAZIT string must be exactly {FAZIT_LEN} bytes, got {got}")]
    BadFazitLength { got: usize },
    #[error("a challenge must be exactly 4 bytes, got {got}")]
    BadChallengeLength { got: usize },
    #[error("DID 0x2ED must be at least 3 bytes to sign, got {got}")]
    ShortAdaptStatus { got: usize },
    #[error("DID 0x2EE must be at least 2 bytes to sign, got {got}")]
    ShortLiveState { got: usize },
}

/// Build the 48-byte record the download service decrypts.
///
/// The ECU also recognises a "virgin" form — VIN all `0xFF`, `[0x21] == 0`,
/// `[0x22] == 0xFF`, `[0x23] == 0xFF` — which *resets* the immobilizer data set
/// instead of adopting the record. It is reachable through this function, so an
/// adaptation must pass a real VIN and set [`DOWNLOAD_FLAG_ADAPTATION`].
pub fn download_plaintext(
    vin: &str,
    new_key: &[u8; 16],
    idx_tun: u8,
    flags: u8,
    ct_dat_bas_fazit: u8,
    command: DownloadCommand,
) -> Result<[u8; DOWNLOAD_PLAINTEXT_LEN], DiagError> {
    let vin = vin.as_bytes();
    if vin.len() != VIN_LEN {
        return Err(DiagError::BadVinLength { got: vin.len() });
    }
    let mut out = [0u8; DOWNLOAD_PLAINTEXT_LEN];
    out[0x00..0x11].copy_from_slice(vin);
    out[0x11..0x21].copy_from_slice(new_key);
    out[0x21] = idx_tun;
    out[0x22] = flags;
    out[0x23] = ct_dat_bas_fazit;
    out[0x24] = command.raw();
    // [0x25..0x30] stay zero: the ECU requires it unless the command is 3.
    Ok(out)
}

/// Encrypt a download record into the 52-byte DID `0x2E2` value.
///
/// Three **independent** ECB blocks — no chaining, no IV — under the ECU's
/// *current* key, then the plaintext's CRC32 appended big-endian in the clear.
///
/// `no_key_secu` is the key the ECU holds **now**, not the one being written.
/// Getting that backwards is the one mistake the ECU cannot tell you about: the
/// record fails its CRC and the attempt walks the lockout ladder.
pub fn download_value(
    no_key_secu: &[u8; 16],
    plaintext: &[u8; DOWNLOAD_PLAINTEXT_LEN],
) -> [u8; DOWNLOAD_VALUE_LEN] {
    let mut out = [0u8; DOWNLOAD_VALUE_LEN];
    for (i, offset) in [0usize, 16, 32].iter().enumerate() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&plaintext[*offset..*offset + 16]);
        out[i * 16..i * 16 + 16].copy_from_slice(&aes128_encrypt_block(no_key_secu, &block));
    }
    out[DOWNLOAD_PLAINTEXT_LEN..].copy_from_slice(&crc32fast::hash(plaintext).to_be_bytes());
    out
}

/// The `WriteDataByIdentifier` bytes for a DID value, for display.
pub fn wdbi_frame(did: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + value.len());
    out.push(0x2E);
    out.extend_from_slice(&did.to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// Human-readable names for the download flag bits.
pub fn download_flag_names(flags: u8) -> Vec<&'static str> {
    [
        (DOWNLOAD_FLAG_ADAPTATION, "adaptation → stStatFct 4"),
        (DOWNLOAD_FLAG_AUTH_MUTE, "bAuthMute"),
        (DOWNLOAD_FLAG_VLD_CHK_DI, "bVldChkDi"),
        (DOWNLOAD_FLAG_TRIG_FCT_DI, "bTrigFctDi"),
        (DOWNLOAD_FLAG_LIM_MOD_ENA, "bLimModEna"),
    ]
    .into_iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, name)| name)
    .collect()
}

// ── Identity checksum (service 7, DID 0x2F9) ──────────────────────────────────

/// Recompute the 5-byte DID `0x2F9` payload.
///
/// The only *read* with cryptographic value: the ECU signs the identity data it
/// just reported, together with the live challenge, under its current
/// `noKeySecu`. Recomputing it locally proves both that a dump's key is right
/// and that the dump belongs to the ECU on the bus — and it writes nothing, so
/// unlike a trial login it cannot arm the wrong-attempt lockout ladder.
///
/// The ECU refuses this DID (error `0x20`) unless services 1, 3, 4 and 9 have
/// run in the session, which is why the read order matters.
///
/// `fazit` is DID `0xF17C`, `vin` `0xF190`, `adapt_status` `0x2ED`,
/// `live_state` `0x2EE`, `challenge` `0x2E0`.
pub fn identity_checksum(
    no_key_secu: &[u8; 16],
    fazit: &[u8],
    vin: &[u8],
    adapt_status: &[u8],
    live_state: &[u8],
    challenge: &[u8],
) -> Result<[u8; 5], DiagError> {
    if fazit.len() != FAZIT_LEN {
        return Err(DiagError::BadFazitLength { got: fazit.len() });
    }
    if vin.len() != VIN_LEN {
        return Err(DiagError::BadVinLength { got: vin.len() });
    }
    if challenge.len() != 4 {
        return Err(DiagError::BadChallengeLength {
            got: challenge.len(),
        });
    }
    if adapt_status.len() < 3 {
        return Err(DiagError::ShortAdaptStatus {
            got: adapt_status.len(),
        });
    }
    if live_state.len() < 2 {
        return Err(DiagError::ShortLiveState {
            got: live_state.len(),
        });
    }

    let mut buf = [0u8; 0x40];
    buf[0x00..0x17].copy_from_slice(fazit);
    buf[0x17..0x28].copy_from_slice(vin);
    buf[0x28] = adapt_status[0]; // stStatFct
    buf[0x29] = adapt_status[1]; // ctDatBasFazit
    buf[0x2A] = adapt_status[2]; // idxLab
    buf[0x32] = live_state[0];
    buf[0x33] = live_state[1];
    buf[0x3C..0x40].copy_from_slice(challenge);

    let mut block = [0u8; 16];
    block[0..4].copy_from_slice(&crc32fast::hash(&buf).to_le_bytes());
    block[4..16].copy_from_slice(&CKS_TAIL);
    let ct = aes128_encrypt_block(no_key_secu, &block);

    // The four AES bytes travel byte-reversed after a leading tag.
    Ok([0x82, ct[3], ct[2], ct[1], ct[0]])
}

/// Whether the ECU's DID `0x2F9` answer matches what `no_key_secu` would
/// produce for the identity data it reported.
///
/// Only the four AES bytes are compared. Payload `[0]` is `0x82` or `0x84`
/// depending on whether the Imo component or the platform ran the cipher, which
/// says nothing about the key.
pub fn key_proof(
    reported: &[u8],
    no_key_secu: &[u8; 16],
    fazit: &[u8],
    vin: &[u8],
    adapt_status: &[u8],
    live_state: &[u8],
    challenge: &[u8],
) -> bool {
    if reported.len() < 5 {
        return false;
    }
    match identity_checksum(no_key_secu, fazit, vin, adapt_status, live_state, challenge) {
        Ok(expected) => expected[1..5] == reported[1..5],
        Err(_) => false,
    }
}

// ── Error codes (DID 0x2FF byte 18) ───────────────────────────────────────────

/// Decode the immobilizer's last recorded error code.
pub fn imo_error_name(code: u8) -> &'static str {
    match code {
        0x00 => "none",
        0x01 => "svc 1, hardware-sample lock",
        0x02 => "svc 1, ignition off",
        0x03 => "svc 1, no random",
        0x04 => "login, ignition off",
        0x05 => "login, stStatFct == 10",
        0x06 => "login, hardware-sample lock",
        0x07 => "login, stStatFct == 0x63",
        0x08 => "login, bad length",
        0x09 => "login, no challenge issued",
        0x0A => "login, stStatFct not adaptable",
        0x0B => "login lockout active",
        0x0C => "login, vehicle moving",
        0x0D => "login, engine running",
        0x0E => "login, bad subFunc/param",
        0x0F => "login failed (wrong PIN)",
        0x10 => "login timeout",
        0x11 => "svc 3, hardware-sample lock",
        0x12 => "svc 4, hardware-sample lock",
        0x13 => "svc 5, hardware-sample lock",
        0x14 => "download, ignition off",
        0x15 => "download, stStatFct == 10",
        0x16 => "download, hardware-sample lock",
        0x17 => "download, stStatFct == 0x63",
        0x18 => "download, bad length",
        0x19 => "download lockout active",
        0x1A => "download, vehicle moving",
        0x1B => "download, engine running",
        0x1C => "download rejected",
        0x1D => "download failed (CRC)",
        0x1E => "download timeout",
        0x1F => "svc 7, hardware-sample lock",
        0x20 => "svc 7, prerequisites missing",
        0x21 => "svc 7 timeout",
        0x22 => "svc 8, hardware-sample lock",
        0x23 => "svc 10 unsupported",
        0x2C..=0x31 => "SHE download",
        0x32 => "SHE download timeout",
        0x34..=0x36 => "svc 0xAA",
        0x37 => "occurrence-counter timeout",
        0x38 => "login param rejected (bTrigFct)",
        0x3B => "login param rejected (bLock)",
        0x3D => "login param rejected (bLimModEna)",
        0xFF => "unknown service",
        _ => "unrecognised",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x59, 0x67, 0xF8, 0xFB, 0xF7, 0xAF, 0x63, 0x4F, 0x17, 0xCF, 0x78, 0x65, 0xF1, 0x83, 0x24,
        0xC3,
    ];
    const VIN: &str = "1VWAT7A31FC022915";
    const CHALLENGE: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

    fn plan() -> [u8; DOWNLOAD_PLAINTEXT_LEN] {
        download_plaintext(
            VIN,
            &KEY,
            0x6A,
            DOWNLOAD_FLAG_ADAPTATION,
            0x01,
            DownloadCommand::SetKeyAndAdopt,
        )
        .unwrap()
    }

    #[test]
    fn download_plaintext_layout() {
        let p = plan();
        assert_eq!(&p[0x00..0x11], VIN.as_bytes());
        assert_eq!(&p[0x11..0x21], &KEY);
        assert_eq!(p[0x21], 0x6A);
        assert_eq!(p[0x22], DOWNLOAD_FLAG_ADAPTATION);
        assert_eq!(p[0x23], 0x01);
        assert_eq!(p[0x24], 3);
        assert_eq!(&p[0x25..], &[0u8; 11], "the tail must be zero");
    }

    /// The ECU compares the four trailing CRC bytes against its own
    /// little-endian CRC32 buffer *in reverse*, which is what makes them
    /// big-endian on the wire. Mirrored here rather than trusting our own order.
    #[test]
    fn download_value_shape_and_crc_order() {
        let p = plan();
        let value = download_value(&KEY, &p);
        assert_eq!(value.len(), 52);
        assert_eq!(wdbi_frame(DID_DOWNLOAD, &value).len(), 55);

        let crc_le = crc32fast::hash(&p).to_le_bytes();
        let sent = &value[DOWNLOAD_PLAINTEXT_LEN..];
        for i in 0..4 {
            assert_eq!(sent[i], crc_le[3 - i]);
        }
    }

    /// Three independent ECB blocks, not CBC: block 2 of identical plaintext
    /// must encrypt identically regardless of what precedes it.
    #[test]
    fn download_uses_three_independent_ecb_blocks() {
        let p = plan();
        let value = download_value(&KEY, &p);
        for (i, offset) in [0usize, 16, 32].iter().enumerate() {
            let mut block = [0u8; 16];
            block.copy_from_slice(&p[*offset..*offset + 16]);
            assert_eq!(
                &value[i * 16..i * 16 + 16],
                &aes128_encrypt_block(&KEY, &block),
                "block {i} must be a plain ECB encryption"
            );
        }
    }

    /// Encrypting under the wrong key produces different ciphertext — the
    /// mistake that costs a lockout, so it must not be able to look the same.
    #[test]
    fn the_encrypting_key_matters() {
        let p = plan();
        let other = [0u8; 16];
        assert_ne!(download_value(&KEY, &p), download_value(&other, &p));
    }

    #[test]
    fn rejects_a_malformed_vin() {
        assert_eq!(
            download_plaintext(
                "SHORT",
                &KEY,
                0,
                DOWNLOAD_FLAG_ADAPTATION,
                0,
                DownloadCommand::SetKeyAndAdopt
            ),
            Err(DiagError::BadVinLength { got: 5 })
        );
    }

    /// The "virgin" reset form the ECU tests for.
    #[test]
    fn virgin_reset_record() {
        let vin: String = std::iter::repeat_n('\u{FF}', 17).collect();
        // A VIN of 0xFF bytes is not ASCII, so build it directly.
        let mut p = [0u8; DOWNLOAD_PLAINTEXT_LEN];
        p[0x00..0x11].fill(0xFF);
        p[0x21] = 0x00;
        p[0x22] = 0xFF;
        p[0x23] = 0xFF;
        p[0x24] = DownloadCommand::SetKeyAndReset.raw();
        assert_eq!(&p[0x00..0x11], &[0xFFu8; 17]);
        assert_eq!(p[0x24], 2);
        assert_eq!(&p[0x25..], &[0u8; 11]);
        // ... and the same VIN through the builder is refused, because a
        // 17-char UTF-8 string of U+00FF is 34 bytes, not 17.
        assert!(
            download_plaintext(&vin, &KEY, 0, 0xFF, 0xFF, DownloadCommand::SetKeyAndReset).is_err()
        );
    }

    #[test]
    fn identity_checksum_shape() {
        let fazit = [b'F'; FAZIT_LEN];
        let adapt = [0x02, 0x01, 0x0D, 0, 0, 0, 0, 0, 0, 0];
        let live = [0x04, 0xC4, 0, 0, 0, 0, 0, 0, 0, 0];
        let cks =
            identity_checksum(&KEY, &fazit, VIN.as_bytes(), &adapt, &live, &CHALLENGE).unwrap();
        assert_eq!(cks.len(), 5);
        assert_eq!(cks[0], 0x82);
    }

    /// The key proof must accept the right key, reject a wrong one, and ignore
    /// the leading tag byte, which says nothing about the key.
    #[test]
    fn key_proof_accepts_only_the_right_key() {
        let fazit = [b'F'; FAZIT_LEN];
        let adapt = [0x02, 0x01, 0x0D, 0, 0, 0, 0, 0, 0, 0];
        let live = [0x04, 0xC4, 0, 0, 0, 0, 0, 0, 0, 0];
        let reported =
            identity_checksum(&KEY, &fazit, VIN.as_bytes(), &adapt, &live, &CHALLENGE).unwrap();

        let check = |key: &[u8; 16], payload: &[u8]| {
            key_proof(
                payload,
                key,
                &fazit,
                VIN.as_bytes(),
                &adapt,
                &live,
                &CHALLENGE,
            )
        };

        assert!(check(&KEY, &reported));
        assert!(!check(&[0u8; 16], &reported));

        let mut platform_tag = reported;
        platform_tag[0] = 0x84;
        assert!(
            check(&KEY, &platform_tag),
            "the tag byte must not affect the verdict"
        );

        // A changed challenge must not still verify: the signature is bound to
        // the live exchange, which is what makes it proof about *this* ECU.
        let other = identity_checksum(
            &KEY,
            &fazit,
            VIN.as_bytes(),
            &adapt,
            &live,
            &[0xAA, 0xBB, 0xCC, 0xDD],
        )
        .unwrap();
        assert!(!check(&KEY, &other));

        // Short or absent payloads are a "no", never a "yes".
        assert!(!check(&KEY, &[]));
        assert!(!check(&KEY, &reported[..3]));
    }

    #[test]
    fn error_names_cover_the_documented_table() {
        assert_eq!(imo_error_name(0x00), "none");
        assert_eq!(imo_error_name(0x0F), "login failed (wrong PIN)");
        assert_eq!(imo_error_name(0x1D), "download failed (CRC)");
        assert_eq!(imo_error_name(0x20), "svc 7, prerequisites missing");
        assert_eq!(imo_error_name(0x2E), "SHE download");
        assert_eq!(imo_error_name(0x35), "svc 0xAA");
        assert_eq!(imo_error_name(0xFF), "unknown service");
        assert_eq!(imo_error_name(0x99), "unrecognised");
    }

    #[test]
    fn flag_names() {
        assert_eq!(
            download_flag_names(DOWNLOAD_FLAG_ADAPTATION | DOWNLOAD_FLAG_LIM_MOD_ENA),
            vec!["adaptation → stStatFct 4", "bLimModEna"]
        );
        assert!(download_flag_names(0).is_empty());
    }
}
