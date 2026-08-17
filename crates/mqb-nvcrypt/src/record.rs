//! The immobilizer record carried by NVRAM channels 6, 7 and 8.
//!
//! All three channels hold an identical copy for redundancy; the firmware votes
//! between them. Each is a 104-byte FEE slot laid out as:
//!
//! ```text
//! [0..13]    datStat     write counter + last authentication random
//! [13..66]   datDat      the identity: noKeySecu, VIN, idxTun, noKeyMst, flags
//! [66..83]   reserved    zero
//! [83..100]  VIN copy    plaintext, read by CBOOT
//! [100..104] padding     FEE slot fill
//! ```
//!
//! Both sub-records end in a **CRC-16/CCITT-FALSE** over everything before it,
//! stored little-endian.
//!
//! # Why this keeps the raw bytes
//!
//! [`ImmoRecord`] stores `datStat` and `datDat` verbatim and edits them in
//! place rather than decoding to fields and re-encoding. Two bytes make that
//! necessary: `datDat[0x2C]` packs `bLock` and `bLimModEna` into nibbles whose
//! cleared encoding is not consistent across the firmware's own writers (a real
//! ECU reads `0x05`, not the `0x50` the builder suggests), and `datDat[0x2E]` is
//! unused with no documented value. Round-tripping the raw bytes means an edit
//! to the VIN cannot silently rewrite a flag as a side effect.

use crate::crc::crc16_ccitt_false;

/// Offset of `datDat` within the record.
const DAT_DAT: usize = 13;
/// Length of the `datStat` sub-record.
pub const DAT_STAT_LEN: usize = 13;
/// Length of the `datDat` sub-record.
pub const DAT_DAT_LEN: usize = 53;
/// The two sub-records together — the shortest usable record.
pub const MIN_RECORD_LEN: usize = DAT_STAT_LEN + DAT_DAT_LEN;
/// A full channel payload, including the VIN copy and FEE padding.
pub const CHANNEL_RECORD_LEN: usize = 104;
/// Where the plaintext VIN copy CBOOT reads lives in a full channel payload.
const VIN_COPY: usize = 83;
/// Length of a VIN.
pub const VIN_LEN: usize = 17;

// datStat field offsets.
const DS_AUTH_PRE_VLD: usize = 0x00;
const DS_RND_OLD: usize = 0x01;
const DS_CT: usize = 0x07;
const DS_CRC: usize = 0x0B;

// datDat field offsets.
const DD_KEY_SECU: usize = 0x01;
const DD_VIN: usize = 0x11;
const DD_CT_FAZIT: usize = 0x22;
const DD_IDX_TUN: usize = 0x23;
const DD_ST_STAT_FCT: usize = 0x24;
const DD_KEY_MST: usize = 0x25;
const DD_TI_DLY_DOWN: usize = 0x27;
const DD_CNT_DOWN_WRG: usize = 0x28;
const DD_TI_DLY_ACC: usize = 0x29;
const DD_CNT_ACC_WRG: usize = 0x2A;
const DD_INH_ACS_MEM: usize = 0x2B;
const DD_LOCK_LIM: usize = 0x2C;
const DD_FLAGS: usize = 0x2D;
const DD_CT: usize = 0x2F;
const DD_CRC: usize = 0x33;

/// `datDat[0x2D]` flag bits.
const FLAG_AUTH_MUTE: u8 = 0x40;
const FLAG_VLD_CHK_DI: u8 = 0x20;
const FLAG_TRIG_FCT_DI: u8 = 0x10;

/// `stStatFct` as stored in `datDat[0x24]`.
///
/// The stored encoding is not the numeric state the rest of the ECU sees: the
/// firmware maps these four values to 1/2/3/4, with `0xA5` reading as 3 only on
/// a hardware-sample ECU and as 2 otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StStatFct {
    /// `0x55` → 1: neutral, never adapted.
    NotAdapted,
    /// `0xAA` → 2: adapted. The normal in-service value.
    Adapted,
    /// `0xA5` → 3 on a hardware sample, otherwise 2.
    AdaptedHwSample,
    /// `0x5A` → 4: adaptation mode; the ECU learns `noKeyMst` from the master.
    Adaptation,
    /// Anything else. Decoded as 2, matching the firmware's fallback.
    Unrecognised(u8),
}

impl StStatFct {
    /// Decode the stored byte.
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0x55 => StStatFct::NotAdapted,
            0xAA => StStatFct::Adapted,
            0xA5 => StStatFct::AdaptedHwSample,
            0x5A => StStatFct::Adaptation,
            other => StStatFct::Unrecognised(other),
        }
    }

    /// The byte as stored in `datDat[0x24]`.
    pub fn raw(self) -> u8 {
        match self {
            StStatFct::NotAdapted => 0x55,
            StStatFct::Adapted => 0xAA,
            StStatFct::AdaptedHwSample => 0xA5,
            StStatFct::Adaptation => 0x5A,
            StStatFct::Unrecognised(v) => v,
        }
    }

    /// The numeric `ImoDat_stStatFct_VW` the rest of the ECU sees.
    pub fn numeric(self) -> u8 {
        match self {
            StStatFct::NotAdapted => 1,
            StStatFct::Adapted => 2,
            StStatFct::AdaptedHwSample => 3,
            StStatFct::Adaptation => 4,
            StStatFct::Unrecognised(_) => 2,
        }
    }

    /// One-line description for the UI.
    pub fn label(self) -> &'static str {
        match self {
            StStatFct::NotAdapted => "neutral / not adapted",
            StStatFct::Adapted => "adapted",
            StStatFct::AdaptedHwSample => "adapted (hardware sample)",
            StStatFct::Adaptation => "adaptation — learns noKeyMst from the master",
            StStatFct::Unrecognised(_) => "adapted (unrecognised encoding)",
        }
    }

    /// The four values the firmware writes, for a picker.
    pub fn all() -> [StStatFct; 4] {
        [
            StStatFct::NotAdapted,
            StStatFct::Adapted,
            StStatFct::AdaptedHwSample,
            StStatFct::Adaptation,
        ]
    }
}

/// Why a record could not be decoded or edited.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error(
        "immobilizer record is {got} bytes; it needs at least {MIN_RECORD_LEN} \
         (13 datStat + 53 datDat)"
    )]
    TooShort { got: usize },

    #[error("a VIN must be exactly {VIN_LEN} bytes, got {got}")]
    BadVinLength { got: usize },

    #[error("a VIN must be printable ASCII")]
    NonAsciiVin,
}

/// The identity fields the immobilizer protocol needs, lifted out of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmoSecrets {
    /// The 16-byte AES-128 key everything in the immobilizer is keyed with.
    pub no_key_secu: [u8; 16],
    /// The master (cluster) PIN.
    pub no_key_mst: u16,
    /// Tuning index / PClass — byte 4 of every authentication block.
    pub idx_tun: u8,
    /// 17-character VIN.
    pub vin: String,
    pub ct_dat_bas_fazit: u8,
    pub st_stat_fct: StStatFct,
    pub b_auth_mute: bool,
    pub b_vld_chk_di: bool,
    pub b_trig_fct_di: bool,
    pub b_lim_mod_ena: bool,
    pub b_lock: bool,
    pub b_inh_acs_mem: bool,
    /// Which NVRAM channel this came from, when it came from a dump at all.
    pub channel: Option<u8>,
}

/// One immobilizer record, editable in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmoRecord {
    dat_stat: [u8; DAT_STAT_LEN],
    dat_dat: [u8; DAT_DAT_LEN],
    /// Everything past the two sub-records: the reserved zeroes, the VIN copy
    /// and the FEE padding. Empty for a bare 66-byte record.
    tail: Vec<u8>,
    /// Which channel this was read from.
    channel: Option<u8>,
}

impl ImmoRecord {
    /// Decode a plaintext record. Anything past the two sub-records is kept
    /// verbatim so it survives a re-encode.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() < MIN_RECORD_LEN {
            return Err(RecordError::TooShort { got: bytes.len() });
        }
        let mut dat_stat = [0u8; DAT_STAT_LEN];
        dat_stat.copy_from_slice(&bytes[..DAT_STAT_LEN]);
        let mut dat_dat = [0u8; DAT_DAT_LEN];
        dat_dat.copy_from_slice(&bytes[DAT_DAT..MIN_RECORD_LEN]);
        Ok(Self {
            dat_stat,
            dat_dat,
            tail: bytes[MIN_RECORD_LEN..].to_vec(),
            channel: None,
        })
    }

    /// Note which NVRAM channel this record came from.
    pub fn with_channel(mut self, channel: u8) -> Self {
        self.channel = Some(channel);
        self
    }

    /// The NVRAM channel this came from, if any.
    pub fn channel(&self) -> Option<u8> {
        self.channel
    }

    /// The `datStat` sub-record as stored, CRC included.
    pub fn dat_stat_bytes(&self) -> &[u8; DAT_STAT_LEN] {
        &self.dat_stat
    }

    /// The `datDat` sub-record as stored, CRC included.
    ///
    /// This is the identity itself, and the right thing to compare when
    /// checking whether channels 6/7/8 hold the same record: the FEE padding
    /// after it legitimately differs between the three copies.
    pub fn dat_dat_bytes(&self) -> &[u8; DAT_DAT_LEN] {
        &self.dat_dat
    }

    /// Re-encode the record, refreshing both CCITT CRCs.
    ///
    /// The result is byte-identical to the input when nothing was changed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIN_RECORD_LEN + self.tail.len());
        let mut dat_stat = self.dat_stat;
        let crc = crc16_ccitt_false(&dat_stat[..DS_CRC]);
        dat_stat[DS_CRC..DS_CRC + 2].copy_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&dat_stat);

        let mut dat_dat = self.dat_dat;
        let crc = crc16_ccitt_false(&dat_dat[..DD_CRC]);
        dat_dat[DD_CRC..DD_CRC + 2].copy_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&dat_dat);

        out.extend_from_slice(&self.tail);
        out
    }

    // ── datStat ───────────────────────────────────────────────────────────

    /// `bAuthPreVld` as stored: `0xAA` set, `0x55` clear.
    pub fn b_auth_pre_vld_raw(&self) -> u8 {
        self.dat_stat[DS_AUTH_PRE_VLD]
    }

    /// Whether `bAuthPreVld` is set.
    pub fn b_auth_pre_vld(&self) -> bool {
        self.dat_stat[DS_AUTH_PRE_VLD] == 0xAA
    }

    /// The last authentication random the ECU saw.
    pub fn no_rnd_old(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out.copy_from_slice(&self.dat_stat[DS_RND_OLD..DS_RND_OLD + 4]);
        out
    }

    /// `datStat`'s write counter.
    pub fn ct_dat_stat(&self) -> u32 {
        u32::from_le_bytes(self.dat_stat[DS_CT..DS_CT + 4].try_into().unwrap())
    }

    /// The stored `datStat` CRC.
    pub fn dat_stat_crc(&self) -> u16 {
        u16::from_le_bytes([self.dat_stat[DS_CRC], self.dat_stat[DS_CRC + 1]])
    }

    /// Whether the stored `datStat` CRC matches its contents.
    pub fn dat_stat_crc_ok(&self) -> bool {
        crc16_ccitt_false(&self.dat_stat[..DS_CRC]) == self.dat_stat_crc()
    }

    // ── datDat ────────────────────────────────────────────────────────────

    /// The 16-byte AES key the whole immobilizer is keyed with.
    pub fn no_key_secu(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.dat_dat[DD_KEY_SECU..DD_KEY_SECU + 16]);
        out
    }

    /// Replace `noKeySecu`.
    pub fn set_no_key_secu(&mut self, key: [u8; 16]) {
        self.dat_dat[DD_KEY_SECU..DD_KEY_SECU + 16].copy_from_slice(&key);
    }

    /// The VIN, as stored (latin-1, so any byte decodes).
    pub fn vin(&self) -> String {
        self.dat_dat[DD_VIN..DD_VIN + VIN_LEN]
            .iter()
            .map(|&b| b as char)
            .collect()
    }

    /// Replace the VIN, updating the plaintext copy CBOOT reads as well.
    pub fn set_vin(&mut self, vin: &str) -> Result<(), RecordError> {
        let bytes = vin.as_bytes();
        if bytes.len() != VIN_LEN {
            return Err(RecordError::BadVinLength { got: bytes.len() });
        }
        if !bytes.iter().all(|b| (0x20..0x7F).contains(b)) {
            return Err(RecordError::NonAsciiVin);
        }
        self.dat_dat[DD_VIN..DD_VIN + VIN_LEN].copy_from_slice(bytes);
        // The copy at [83..100] is what CBOOT reads; leaving it stale would
        // make the boot loader and the application disagree about the car.
        let copy_at = VIN_COPY - MIN_RECORD_LEN;
        if self.tail.len() >= copy_at + VIN_LEN {
            self.tail[copy_at..copy_at + VIN_LEN].copy_from_slice(bytes);
        }
        Ok(())
    }

    /// The plaintext VIN copy CBOOT reads, when the record is long enough to
    /// carry one.
    pub fn vin_copy(&self) -> Option<String> {
        let copy_at = VIN_COPY - MIN_RECORD_LEN;
        (self.tail.len() >= copy_at + VIN_LEN).then(|| {
            self.tail[copy_at..copy_at + VIN_LEN]
                .iter()
                .map(|&b| b as char)
                .collect()
        })
    }

    /// Whether the VIN copy still agrees with the VIN itself.
    pub fn vin_copy_ok(&self) -> Option<bool> {
        self.vin_copy().map(|copy| copy == self.vin())
    }

    /// `ctDatBasFazit`.
    pub fn ct_dat_bas_fazit(&self) -> u8 {
        self.dat_dat[DD_CT_FAZIT]
    }

    /// Replace `ctDatBasFazit`.
    pub fn set_ct_dat_bas_fazit(&mut self, value: u8) {
        self.dat_dat[DD_CT_FAZIT] = value;
    }

    /// `idxTun` / PClass — byte 4 of every authentication block.
    pub fn idx_tun(&self) -> u8 {
        self.dat_dat[DD_IDX_TUN]
    }

    /// Replace `idxTun`.
    pub fn set_idx_tun(&mut self, value: u8) {
        self.dat_dat[DD_IDX_TUN] = value;
    }

    /// `stStatFct` as stored.
    pub fn st_stat_fct(&self) -> StStatFct {
        StStatFct::from_raw(self.dat_dat[DD_ST_STAT_FCT])
    }

    /// Replace `stStatFct`.
    pub fn set_st_stat_fct(&mut self, value: StStatFct) {
        self.dat_dat[DD_ST_STAT_FCT] = value.raw();
    }

    /// The master (cluster) PIN, stored big-endian.
    pub fn no_key_mst(&self) -> u16 {
        u16::from_be_bytes([self.dat_dat[DD_KEY_MST], self.dat_dat[DD_KEY_MST + 1]])
    }

    /// Replace `noKeyMst`.
    pub fn set_no_key_mst(&mut self, value: u16) {
        self.dat_dat[DD_KEY_MST..DD_KEY_MST + 2].copy_from_slice(&value.to_be_bytes());
    }

    /// Download-lockout delay in minutes.
    pub fn ti_dly_down(&self) -> u8 {
        self.dat_dat[DD_TI_DLY_DOWN]
    }

    /// Wrong-download attempt counter.
    pub fn no_cnt_down_wrg(&self) -> u8 {
        self.dat_dat[DD_CNT_DOWN_WRG]
    }

    /// Login-lockout delay in minutes.
    pub fn ti_dly_acc(&self) -> u8 {
        self.dat_dat[DD_TI_DLY_ACC]
    }

    /// Wrong-login attempt counter.
    pub fn no_cnt_acc_wrg(&self) -> u8 {
        self.dat_dat[DD_CNT_ACC_WRG]
    }

    /// `bInhAcsMem` — the interlock on UDS `0x23` and CCP.
    ///
    /// Decoded **fail-closed**, matching the firmware: only the explicit
    /// `0x5A` reads as false, so an unexpected byte is reported as inhibited
    /// rather than silently as open.
    pub fn b_inh_acs_mem(&self) -> bool {
        self.dat_dat[DD_INH_ACS_MEM] != 0x5A
    }

    /// `bLock` — the low nibble of `datDat[0x2C]`.
    pub fn b_lock(&self) -> bool {
        self.dat_dat[DD_LOCK_LIM] & 0x0F == 0x0A
    }

    /// `bLimModEna` — the high nibble of `datDat[0x2C]`.
    pub fn b_lim_mod_ena(&self) -> bool {
        self.dat_dat[DD_LOCK_LIM] & 0xF0 == 0xA0
    }

    /// Set `bLimModEna`, leaving the `bLock` nibble beside it alone.
    pub fn set_b_lim_mod_ena(&mut self, on: bool) {
        let low = self.dat_dat[DD_LOCK_LIM] & 0x0F;
        self.dat_dat[DD_LOCK_LIM] = if on { 0xA0 } else { 0x00 } | low;
    }

    pub fn b_auth_mute(&self) -> bool {
        self.dat_dat[DD_FLAGS] & FLAG_AUTH_MUTE != 0
    }

    pub fn b_vld_chk_di(&self) -> bool {
        self.dat_dat[DD_FLAGS] & FLAG_VLD_CHK_DI != 0
    }

    pub fn b_trig_fct_di(&self) -> bool {
        self.dat_dat[DD_FLAGS] & FLAG_TRIG_FCT_DI != 0
    }

    /// `datDat`'s write counter.
    pub fn ct_dat_dat(&self) -> u32 {
        u32::from_le_bytes(self.dat_dat[DD_CT..DD_CT + 4].try_into().unwrap())
    }

    /// The stored `datDat` CRC.
    pub fn dat_dat_crc(&self) -> u16 {
        u16::from_le_bytes([self.dat_dat[DD_CRC], self.dat_dat[DD_CRC + 1]])
    }

    /// Whether the stored `datDat` CRC matches its contents.
    ///
    /// This is the definitive test that a channel decrypted correctly: it
    /// covers every identity field, so a wrong Device ID cannot pass it.
    pub fn dat_dat_crc_ok(&self) -> bool {
        crc16_ccitt_false(&self.dat_dat[..DD_CRC]) == self.dat_dat_crc()
    }

    /// The identity fields the protocol layer needs.
    pub fn secrets(&self) -> ImmoSecrets {
        ImmoSecrets {
            no_key_secu: self.no_key_secu(),
            no_key_mst: self.no_key_mst(),
            idx_tun: self.idx_tun(),
            vin: self.vin(),
            ct_dat_bas_fazit: self.ct_dat_bas_fazit(),
            st_stat_fct: self.st_stat_fct(),
            b_auth_mute: self.b_auth_mute(),
            b_vld_chk_di: self.b_vld_chk_di(),
            b_trig_fct_di: self.b_trig_fct_di(),
            b_lim_mod_ena: self.b_lim_mod_ena(),
            b_lock: self.b_lock(),
            b_inh_acs_mem: self.b_inh_acs_mem(),
            channel: self.channel,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference record from NVCRYPT.md, whose fields and both CRCs are
    /// published alongside it.
    fn reference() -> Vec<u8> {
        let mut hex = String::from(
            "AAC985528F0000D43A0000F88B005967F8FBF7AF634F17CF7865F18324C3\
             3156574154374133314643303232393135\
             016AAA2735000000\
             00A5050000\
             03000000BF80",
        );
        hex.push_str(&"00".repeat(17));
        hex.push_str("3156574154374133314643303232393135");
        hex.push_str("9738D4B9");
        decode_hex(&hex)
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decodes_the_reference_record() {
        let rec = ImmoRecord::decode(&reference()).unwrap();
        assert!(rec.dat_stat_crc_ok());
        assert!(rec.dat_dat_crc_ok());
        assert_eq!(rec.vin(), "1VWAT7A31FC022915");
        assert_eq!(rec.idx_tun(), 0x6A);
        assert_eq!(rec.no_key_mst(), 0x2735);
        assert_eq!(rec.st_stat_fct(), StStatFct::Adapted);
        assert_eq!(rec.st_stat_fct().numeric(), 2);
        assert_eq!(rec.vin_copy().as_deref(), Some("1VWAT7A31FC022915"));
        assert_eq!(rec.vin_copy_ok(), Some(true));
    }

    /// Re-encoding an untouched record must be byte-identical. This is what
    /// makes a dump editor safe: fields nobody edited cannot drift.
    #[test]
    fn encode_round_trips_byte_for_byte() {
        let original = reference();
        let rec = ImmoRecord::decode(&original).unwrap();
        assert_eq!(rec.encode(), original);
    }

    /// Changing the VIN updates the CBOOT copy too, and refreshes only the
    /// datDat CRC — datStat is untouched, so its CRC must not move.
    #[test]
    fn setting_the_vin_updates_the_copy_and_the_crc() {
        let mut rec = ImmoRecord::decode(&reference()).unwrap();
        let stat_crc_before = rec.dat_stat_crc();

        rec.set_vin("WVWZZZ1KZAW000001").unwrap();
        let encoded = rec.encode();
        let reread = ImmoRecord::decode(&encoded).unwrap();

        assert_eq!(reread.vin(), "WVWZZZ1KZAW000001");
        assert_eq!(reread.vin_copy().as_deref(), Some("WVWZZZ1KZAW000001"));
        assert_eq!(reread.vin_copy_ok(), Some(true));
        assert!(reread.dat_dat_crc_ok(), "datDat CRC must be refreshed");
        assert!(reread.dat_stat_crc_ok());
        assert_eq!(
            reread.dat_stat_crc(),
            stat_crc_before,
            "editing datDat must not touch datStat"
        );

        // The identity really changed, so the datDat CRC must have moved too.
        let original = ImmoRecord::decode(&reference()).unwrap();
        assert_ne!(reread.dat_dat_crc(), original.dat_dat_crc());
    }

    /// A VIN of the wrong length or with non-printable bytes is refused rather
    /// than truncated into the record.
    #[test]
    fn rejects_a_malformed_vin() {
        let mut rec = ImmoRecord::decode(&reference()).unwrap();
        assert_eq!(
            rec.set_vin("TOOSHORT"),
            Err(RecordError::BadVinLength { got: 8 })
        );
        assert_eq!(
            rec.set_vin("WVWZZZ1KZAW00\u{0}001"),
            Err(RecordError::NonAsciiVin)
        );
        assert_eq!(rec.vin(), "1VWAT7A31FC022915", "the record is unchanged");
    }

    /// Editing one flag must not disturb the other nibble of the same byte.
    #[test]
    fn lim_mod_ena_leaves_the_lock_nibble_alone() {
        let mut rec = ImmoRecord::decode(&reference()).unwrap();
        assert!(!rec.b_lock());
        assert!(!rec.b_lim_mod_ena());

        rec.set_b_lim_mod_ena(true);
        assert!(rec.b_lim_mod_ena());
        assert!(!rec.b_lock(), "bLock must not be disturbed");

        rec.set_b_lim_mod_ena(false);
        assert!(!rec.b_lim_mod_ena());
        assert!(!rec.b_lock());
    }

    /// `bInhAcsMem` reads fail-closed: only the explicit `0x5A` is "not
    /// inhibited", so an unexpected byte never reads as open access.
    #[test]
    fn inh_acs_mem_is_fail_closed() {
        let mut bytes = reference();
        bytes[DAT_DAT + DD_INH_ACS_MEM] = 0x5A;
        assert!(!ImmoRecord::decode(&bytes).unwrap().b_inh_acs_mem());

        bytes[DAT_DAT + DD_INH_ACS_MEM] = 0xA5;
        assert!(ImmoRecord::decode(&bytes).unwrap().b_inh_acs_mem());

        bytes[DAT_DAT + DD_INH_ACS_MEM] = 0x00;
        assert!(
            ImmoRecord::decode(&bytes).unwrap().b_inh_acs_mem(),
            "an unrecognised byte must read as inhibited, not as open"
        );
    }

    /// A bare 66-byte record has no VIN copy, and must not pretend otherwise.
    #[test]
    fn bare_record_has_no_vin_copy() {
        let rec = ImmoRecord::decode(&reference()[..MIN_RECORD_LEN]).unwrap();
        assert!(rec.dat_dat_crc_ok());
        assert_eq!(rec.vin_copy(), None);
        assert_eq!(rec.vin_copy_ok(), None);
        assert_eq!(rec.encode().len(), MIN_RECORD_LEN);
    }

    #[test]
    fn refuses_a_short_record() {
        assert_eq!(
            ImmoRecord::decode(&[0u8; 40]),
            Err(RecordError::TooShort { got: 40 })
        );
    }

    /// A wrong Device ID produces garbage, and the datDat CRC is what catches
    /// it — the reason it is the decryption test rather than a heuristic.
    #[test]
    fn crc_rejects_a_corrupted_record() {
        let mut bytes = reference();
        bytes[DAT_DAT + DD_IDX_TUN] ^= 0xFF;
        let rec = ImmoRecord::decode(&bytes).unwrap();
        assert!(!rec.dat_dat_crc_ok());
    }
}
