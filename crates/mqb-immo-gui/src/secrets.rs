//! Where an ECU's immobilizer secrets come from.
//!
//! Every write in this tool is keyed with `noKeySecu`, and there are three
//! places it can be found. All of them are offered because a bench often has
//! only one:
//!
//! * a **DFlash dump** plus that ECU's 12-byte Device ID — the normal case. The
//!   Device ID can be typed, or read out of a program-flash dump of the same
//!   ECU, which is easier to come by than a JTAG session.
//! * a **plaintext record** in hex (`datStat` + `datDat`, 66 bytes or more),
//!   already decrypted, so no Device ID is involved.
//! * **manual entry** of the individual fields, for a record reconstructed by
//!   hand.
//!
//! Whichever is used, the result is an [`ImmoSecrets`] — plus the
//! [`ImmoRecord`] and [`Dump`] behind it where the source carries them, so the
//! DFlash editor can work on the same data.

use std::path::PathBuf;

use mqb_nvcrypt::{
    extract_device_id, Dump, Hitag2Keys, ImmoChannelSurvey, ImmoRecord, ImmoSecrets, StStatFct,
    DEVICE_ID_ADDR, DEVICE_ID_LEN, FLASH_BASE,
};

/// Which of the three ways of supplying secrets is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A DFlash image, decrypted with the ECU's Device ID.
    Dump,
    /// A plaintext `datStat` + `datDat` record as hex.
    Record,
    /// The individual fields, typed in.
    Manual,
}

impl SourceKind {
    pub const ALL: [SourceKind; 3] = [SourceKind::Dump, SourceKind::Record, SourceKind::Manual];

    pub fn label(self) -> &'static str {
        match self {
            SourceKind::Dump => "DFlash dump",
            SourceKind::Record => "Record hex",
            SourceKind::Manual => "Manual entry",
        }
    }
}

/// The fields of a hand-entered record.
#[derive(Debug, Clone, Default)]
pub struct ManualFields {
    pub no_key_secu: String,
    pub no_key_mst: String,
    pub idx_tun: String,
    pub vin: String,
    pub ct_dat_bas_fazit: String,
}

/// One ECU's secrets, and everything needed to work out what they are.
#[derive(Debug, Clone, Default)]
pub struct KeySource {
    pub kind_index: usize,
    pub dump_path: Option<PathBuf>,
    pub pflash_path: Option<PathBuf>,
    pub device_id_hex: String,
    pub record_hex: String,
    pub manual: ManualFields,

    /// The parsed DFlash image, when one is loaded.
    pub dump: Option<Dump>,
    /// The Hitag2 keys derived from the Device ID.
    pub keys: Option<Hitag2Keys>,
    /// The immobilizer record, when the source carries a whole one.
    pub record: Option<ImmoRecord>,
    /// The identity fields, once they resolve.
    pub secrets: Option<ImmoSecrets>,
    /// Which of channels 6/7/8 held a readable record, and whether they agree.
    pub survey: Option<ImmoChannelSurvey>,
    /// Why the source does not resolve, if it does not.
    pub error: Option<String>,
    /// A one-line note about what was loaded.
    pub note: Option<String>,
}

impl KeySource {
    pub fn kind(&self) -> SourceKind {
        SourceKind::ALL[self.kind_index.min(SourceKind::ALL.len() - 1)]
    }

    pub fn set_kind(&mut self, kind: SourceKind) {
        self.kind_index = SourceKind::ALL.iter().position(|k| *k == kind).unwrap_or(0);
        self.resolve();
    }

    /// Whether usable secrets are available.
    pub fn is_ready(&self) -> bool {
        self.secrets.is_some()
    }

    /// Load the Device ID out of a program-flash dump.
    ///
    /// A full flash read is enough to decrypt that ECU's DFlash — the ID sits
    /// in the OTP area, and the extractor anchors on the SHA-256 constant table
    /// beside it so a wrong dump is refused rather than yielding a wrong key.
    pub fn load_device_id_from_pflash(&mut self, path: PathBuf) {
        match std::fs::read(&path) {
            Ok(bytes) => match extract_device_id(&bytes, FLASH_BASE, DEVICE_ID_ADDR) {
                Ok(id) => {
                    self.device_id_hex = hex(&id);
                    self.pflash_path = Some(path);
                    self.note = Some(format!("Device ID {} read from program flash", hex(&id)));
                    self.error = None;
                }
                Err(e) => {
                    self.pflash_path = Some(path);
                    self.error = Some(e.to_string());
                }
            },
            Err(e) => self.error = Some(format!("could not read the program-flash dump: {e}")),
        }
        self.resolve();
    }

    /// Load and parse a DFlash image. Decryption happens in [`Self::resolve`],
    /// because it also needs the Device ID.
    pub fn load_dump(&mut self, path: PathBuf) {
        match std::fs::read(&path) {
            Ok(bytes) => {
                let dump = Dump::parse(bytes);
                self.note = Some(format!(
                    "{} records across {} live channels{}",
                    dump.records().len(),
                    dump.channels().len(),
                    match dump.generation() {
                        Some(g) if g.is_disputed() => ", generation counter disputed".to_string(),
                        Some(g) => format!(", generation counter 0x{:04X}", g.value),
                        None => ", generation counter unknown".to_string(),
                    }
                ));
                self.dump = Some(dump);
                self.dump_path = Some(path);
                self.error = None;
            }
            Err(e) => {
                self.dump = None;
                self.error = Some(format!("could not read the DFlash dump: {e}"));
            }
        }
        self.resolve();
    }

    /// Work out the secrets from whichever source is selected.
    ///
    /// Clears the previous result first, so a source that stops resolving never
    /// leaves stale keys behind for a write to pick up.
    pub fn resolve(&mut self) {
        self.secrets = None;
        self.record = None;
        self.survey = None;
        self.keys = None;

        match self.kind() {
            SourceKind::Dump => self.resolve_dump(),
            SourceKind::Record => self.resolve_record(),
            SourceKind::Manual => self.resolve_manual(),
        }
    }

    fn resolve_dump(&mut self) {
        let Some(dump) = self.dump.as_ref() else {
            self.error = Some("choose a DFlash dump".into());
            return;
        };
        let device_id = match parse_hex(&self.device_id_hex) {
            Ok(bytes) if bytes.len() == DEVICE_ID_LEN => bytes,
            Ok(bytes) => {
                self.error = Some(format!(
                    "a Device ID is {DEVICE_ID_LEN} bytes; {} given",
                    bytes.len()
                ));
                return;
            }
            Err(e) => {
                self.error = Some(format!("Device ID: {e}"));
                return;
            }
        };

        let keys = Hitag2Keys::from_device_id(&device_id);
        let survey = ImmoChannelSurvey::read(dump, &keys);
        let valid = survey.valid_channels();

        if valid.is_empty() {
            // The datDat CRC covers every identity field, so failing it means
            // the decryption is wrong — almost always the wrong Device ID.
            self.error = Some(
                "no immobilizer channel decrypted: none of channels 6, 7 or 8 produced a record \
                 whose datDat CRC holds. That normally means the Device ID does not belong to \
                 this dump."
                    .into(),
            );
            self.keys = Some(keys);
            self.survey = Some(survey);
            return;
        }

        let record = survey.first_valid().cloned();
        let mut note = format!(
            "channels {} decrypted",
            valid
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !survey.copies_agree() {
            note.push_str(" — but the copies disagree, so the firmware would have to vote");
        }
        self.note = Some(note);
        self.error = None;
        self.secrets = record.as_ref().map(|r| r.secrets());
        self.record = record;
        self.keys = Some(keys);
        self.survey = Some(survey);
    }

    fn resolve_record(&mut self) {
        let bytes = match parse_hex(&self.record_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.error = Some(format!("record hex: {e}"));
                return;
            }
        };
        match ImmoRecord::decode(&bytes) {
            Ok(record) => {
                if !record.dat_dat_crc_ok() {
                    self.error = Some(
                        "the record's datDat CRC-16 does not hold — it is not a valid \
                         plaintext immobilizer record."
                            .into(),
                    );
                    return;
                }
                let mut note = format!("record for VIN {}", record.vin());
                if !record.dat_stat_crc_ok() {
                    // Not fatal: nothing here reads datStat. On a hand-entered
                    // record it usually means a typo datDat's CRC did not cover.
                    note.push_str(" (datStat CRC-16 failed; datDat is intact)");
                }
                self.note = Some(note);
                self.error = None;
                self.secrets = Some(record.secrets());
                self.record = Some(record);
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    fn resolve_manual(&mut self) {
        let key = match parse_hex(&self.manual.no_key_secu) {
            Ok(bytes) if bytes.len() == 16 => bytes,
            Ok(bytes) => {
                self.error = Some(format!("noKeySecu is 16 bytes; {} given", bytes.len()));
                return;
            }
            Err(e) => {
                self.error = Some(format!("noKeySecu: {e}"));
                return;
            }
        };
        let no_key_mst = match parse_u16(&self.manual.no_key_mst) {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(format!("noKeyMst: {e}"));
                return;
            }
        };
        let idx_tun = match parse_u8(&self.manual.idx_tun) {
            Ok(v) => v,
            Err(e) => {
                self.error = Some(format!("idxTun: {e}"));
                return;
            }
        };
        let vin = self.manual.vin.trim().to_string();
        if vin.len() != 17 {
            self.error = Some(format!("a VIN is 17 characters; {} given", vin.len()));
            return;
        }
        let ct_dat_bas_fazit = if self.manual.ct_dat_bas_fazit.trim().is_empty() {
            1
        } else {
            match parse_u8(&self.manual.ct_dat_bas_fazit) {
                Ok(v) => v,
                Err(e) => {
                    self.error = Some(format!("ctDatBasFazit: {e}"));
                    return;
                }
            }
        };

        let mut no_key_secu = [0u8; 16];
        no_key_secu.copy_from_slice(&key);
        self.error = None;
        self.note = Some("entered by hand".into());
        // Hand-entered fields carry no flags: a record is not being
        // reconstructed here, only the identity a download needs.
        self.secrets = Some(ImmoSecrets {
            no_key_secu,
            no_key_mst,
            idx_tun,
            vin,
            ct_dat_bas_fazit,
            st_stat_fct: StStatFct::Adapted,
            b_auth_mute: false,
            b_vld_chk_di: false,
            b_trig_fct_di: false,
            b_lim_mod_ena: false,
            b_lock: false,
            b_inh_acs_mem: false,
            channel: None,
        });
    }
}

// ── Small parsers ─────────────────────────────────────────────────────────────

/// Parse hex, ignoring whitespace and any `0x` prefix.
pub fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '_')
        .collect();
    if cleaned.is_empty() {
        return Err("nothing entered".into());
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err("an odd number of hex digits".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("'{}' is not hex", &cleaned[i..i + 2]))
        })
        .collect()
}

/// Parse a byte written as hex, with or without an `0x` prefix.
pub fn parse_u8(input: &str) -> Result<u8, String> {
    let bytes = parse_hex(input)?;
    match bytes[..] {
        [value] => Ok(value),
        _ => Err(format!("expected one byte, got {}", bytes.len())),
    }
}

/// Parse a 16-bit value written as hex.
pub fn parse_u16(input: &str) -> Result<u16, String> {
    let bytes = parse_hex(input)?;
    match bytes[..] {
        [hi, lo] => Ok(u16::from_be_bytes([hi, lo])),
        [lo] => Ok(lo as u16),
        _ => Err(format!("expected two bytes, got {}", bytes.len())),
    }
}

/// Lower-case hex with no separators.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Upper-case hex, space separated — for reading a value off the screen.
pub fn hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parsing_is_forgiving_about_formatting() {
        assert_eq!(parse_hex("0x0A1b").unwrap(), vec![0x0A, 0x1B]);
        assert_eq!(parse_hex(" 0a 1b\t2c ").unwrap(), vec![0x0A, 0x1B, 0x2C]);
        assert_eq!(parse_hex("0a:1b_2c").unwrap(), vec![0x0A, 0x1B, 0x2C]);
        assert!(parse_hex("abc").is_err(), "odd digit count");
        assert!(parse_hex("").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn scalar_parsing() {
        assert_eq!(parse_u8("6a").unwrap(), 0x6A);
        assert_eq!(parse_u8("0x6A").unwrap(), 0x6A);
        assert!(parse_u8("6a6a").is_err());
        assert_eq!(parse_u16("afbb").unwrap(), 0xAFBB);
        assert_eq!(parse_u16("bb").unwrap(), 0x00BB);
    }

    /// A source that stops resolving must not leave the previous ECU's keys
    /// behind — a stale `noKeySecu` would be encrypted into the next download.
    #[test]
    fn resolving_clears_a_previous_result() {
        let mut source = KeySource {
            kind_index: 2, // Manual
            manual: ManualFields {
                no_key_secu: "000102030405060708090a0b0c0d0e0f".into(),
                no_key_mst: "afbb".into(),
                idx_tun: "6a".into(),
                vin: "1VWAT7A31FC022915".into(),
                ct_dat_bas_fazit: "01".into(),
            },
            ..Default::default()
        };
        source.resolve();
        assert!(source.is_ready());
        assert_eq!(source.secrets.as_ref().unwrap().idx_tun, 0x6A);

        source.manual.no_key_secu = "00".into(); // now too short
        source.resolve();
        assert!(!source.is_ready(), "stale secrets must not survive");
        assert!(source.error.as_ref().unwrap().contains("16 bytes"));
    }

    #[test]
    fn a_manual_vin_must_be_seventeen_characters() {
        let mut source = KeySource {
            kind_index: 2,
            manual: ManualFields {
                no_key_secu: "000102030405060708090a0b0c0d0e0f".into(),
                no_key_mst: "afbb".into(),
                idx_tun: "6a".into(),
                vin: "TOOSHORT".into(),
                ct_dat_bas_fazit: String::new(),
            },
            ..Default::default()
        };
        source.resolve();
        assert!(!source.is_ready());
        assert!(source.error.as_ref().unwrap().contains("17 characters"));
    }

    /// A plaintext record needs no Device ID, and a bad one is refused on its
    /// own CRC rather than being accepted as an identity.
    #[test]
    fn a_record_source_validates_its_own_crc() {
        let good = "AAC985528F0000D43A0000F88B005967F8FBF7AF634F17CF7865F18324C3\
                    3156574154374133314643303232393135016AAA2735000000\
                    00A5050000030000 00BF80";
        let mut source = KeySource {
            kind_index: 1, // Record
            record_hex: good.into(),
            ..Default::default()
        };
        source.resolve();
        assert!(source.is_ready(), "{:?}", source.error);
        assert_eq!(source.secrets.as_ref().unwrap().vin, "1VWAT7A31FC022915");
        assert_eq!(source.secrets.as_ref().unwrap().no_key_mst, 0x2735);

        // Flip a byte the datDat CRC covers.
        source.record_hex = good.replacen("6A", "6B", 1);
        source.resolve();
        assert!(!source.is_ready());
        assert!(source.error.as_ref().unwrap().contains("datDat CRC-16"));
    }
}
