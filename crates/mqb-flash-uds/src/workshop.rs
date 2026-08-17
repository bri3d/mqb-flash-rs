//! VW workshop code ("fingerprint") written to DID `0xF15A` during flashing.
//!
//! Port of `VW_Flash/lib/workshop_code.py` plus the two call sites that build
//! one: `simos_flash_utils.flash_bin` and `dq381_flash_utils.flash_bin`.
//!
//! The nine bytes are laid out as:
//!
//! ```text
//! YY MM DD  AA  UU UU UU UU  CC
//! ├──────┤  ├┤  ├──────────┤ ├┤
//! │         │   │            └── CRC8 over the preceding 8 bytes
//! │         │   └── 4 user bytes: on Simos, CAL[0x7A..0x7E]; on DQ381, "NONE"
//! │         └── CRC8 over the concatenated ASW blocks that were flashed
//! └── BCD flash date (two-digit year, month, day)
//! ```
//!
//! The point of the format is that a tool with nothing but ReadDataByIdentifier
//! access can tell what was last flashed — no ASW patch or ReadMemory needed.
//!
//! A real code captured from hardware (`tests/simos18_full_flash.can`, the
//! `2e f1 5a …` request) is `26 03 11 1e 20 20 20 20 76`:
//!
//! ```text
//! 26  BCD year  -> 2026
//! 03  BCD month -> March
//! 11  BCD day   -> 11th          (capture date 2026-03-11)
//! 1e  CRC8 of ASW1+ASW2+ASW3 as flashed
//! 20  ┐
//! 20  │ CAL[0x7A..0x7E] = "    " — this calibration carries four ASCII
//! 20  │ spaces in the VW_Flash fingerprint field
//! 20  ┘
//! 76  CRC8 of the eight bytes above
//! ```
//!
//! The date is a parameter rather than "now": this crate has no clock
//! dependency, and fixture-driven tests must reproduce a captured byte string
//! exactly.

/// The historical hardcoded placeholder that both front ends used before the
/// real computation existed.
///
/// It is Python's `FALLBACK` default, and Python's own validity check rejects
/// it: its trailing byte is `0x3D` while the CRC8 of the first eight bytes is
/// `0x58`. Because `bytes[3] == 0x42 && bytes[4] == 0x04` it is additionally
/// classified as "old" — written by a legacy VW_Flash/SimosTools build.
pub const FALLBACK_WORKSHOP_CODE: [u8; 9] = [0x20, 0x04, 0x20, 0x42, 0x04, 0x20, 0x42, 0xB1, 0x3D];

/// Placeholder CAL ID used when no calibration block is available (DQ381
/// always, Simos when the CAL is too short to carry a fingerprint).
pub const CAL_ID_NONE: [u8; 4] = *b"NONE";

/// CAL ID reported for a code whose CRC does not check out.
pub const CAL_ID_UNKNOWN: [u8; 4] = *b"UNKN";

/// Byte range within the Simos CAL block holding the four fingerprint bytes
/// (`simosshared.vw_flash_fingerprint_simos`).
const SIMOS_FINGERPRINT_RANGE: core::ops::Range<usize> = 0x7A..0x7E;

/// CRC8 used throughout the workshop code (CRC-8/SMBUS: polynomial `0x07`,
/// initial value `0`, no reflection, no final XOR).
///
/// Python ships this as a 256-entry lookup table applied as
/// `sum = table[sum ^ byte]`; that table is exactly the byte-wise expansion of
/// the bit loop below, so the two agree for every input. Computing it keeps the
/// table out of the source, and the ASW blocks are only a couple of megabytes.
pub fn crc8_hash(data: &[u8]) -> u8 {
    crc8_continue(0, data)
}

/// Returns `true` when the trailing CRC byte matches the first eight bytes.
///
/// Mirrors Python's `workshop_code_is_valid`.
pub fn is_valid(bytes: &[u8; 9]) -> bool {
    bytes[8] == crc8_hash(&bytes[0..8])
}

/// Returns `true` for the signature of a workshop code written by an older
/// VW_Flash / SimosTools build (`bytes[3] == 0x42 && bytes[4] == 0x04`).
///
/// Python only consults this once the CRC check has already failed, so callers
/// that want Python's `is_old` semantics must gate it on `!is_valid(bytes)`.
/// [`WorkshopCode::from_bytes`] does exactly that.
pub fn is_placeholder_signature(bytes: &[u8; 9]) -> bool {
    bytes[3] == 0x42 && bytes[4] == 0x04
}

/// Encodes a value in `0..=99` as a single packed BCD byte.
fn to_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

/// Decodes a packed BCD byte, or `None` if either nibble is not a decimal digit.
fn from_bcd(value: u8) -> Option<u8> {
    let high = value >> 4;
    let low = value & 0x0F;
    if high > 9 || low > 9 {
        return None;
    }
    Some(high * 10 + low)
}

/// The calendar date stamped into the first three bytes of a workshop code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashDate {
    /// Full year, e.g. `2026`. Only the last two digits survive the encoding.
    pub year: u16,
    /// Month, 1-12.
    pub month: u8,
    /// Day of month, 1-31.
    pub day: u8,
}

impl FlashDate {
    /// Builds a date from its calendar fields.
    pub const fn new(year: u16, month: u8, day: u8) -> Self {
        Self { year, month, day }
    }

    /// Encodes the date as the three leading BCD bytes of a workshop code.
    pub fn to_bcd_bytes(self) -> [u8; 3] {
        [
            to_bcd((self.year % 100) as u8),
            to_bcd(self.month),
            to_bcd(self.day),
        ]
    }

    /// Decodes the three leading BCD bytes, or `None` if they are not a
    /// plausible date.
    ///
    /// Two-digit years are widened to 20xx. (Python's `convert_from_bcd` feeds
    /// the raw two-digit value straight into `datetime.date`, yielding year 26
    /// rather than 2026; that only affects its human-readable string, and the
    /// re-encoded bytes are identical either way.)
    ///
    /// Unlike Python — which relies on `datetime.date` raising — this does not
    /// reject a day that is out of range for its particular month, only one
    /// outside 1-31.
    pub fn from_bcd_bytes(bytes: [u8; 3]) -> Option<Self> {
        let year = from_bcd(bytes[0])?;
        let month = from_bcd(bytes[1])?;
        let day = from_bcd(bytes[2])?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        Some(Self::new(2000 + year as u16, month, day))
    }
}

/// A decoded or freshly built VW workshop code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkshopCode {
    /// Flash date. `None` only when decoding bytes whose date field is not
    /// valid BCD — Python substitutes `date.today()` there, which this crate
    /// deliberately cannot do (no clock dependency).
    pub flash_date: Option<FlashDate>,
    /// CRC8 over the concatenated ASW blocks that were flashed.
    pub asw_checksum: u8,
    /// Four user bytes; on Simos these come from the CAL, elsewhere `NONE`.
    pub cal_id: [u8; 4],
    /// Whether the trailing CRC checked out (always `true` for a code this
    /// crate built).
    pub is_valid: bool,
    /// Whether the bytes carry the legacy VW_Flash / SimosTools placeholder
    /// signature. Only ever `true` for an invalid code.
    pub is_old: bool,
}

impl WorkshopCode {
    /// Builds a code from an already-computed ASW checksum and CAL ID.
    pub fn new(flash_date: FlashDate, asw_checksum: u8, cal_id: [u8; 4]) -> Self {
        Self {
            flash_date: Some(flash_date),
            asw_checksum,
            cal_id,
            is_valid: true,
            is_old: false,
        }
    }

    /// Builds the Simos flavour: CRC8 over the ASW blocks in flash order, and a
    /// CAL ID lifted from `CAL[0x7A..0x7E]`.
    ///
    /// `asw_blocks` must be given in the same order Python appends them (the
    /// caller's block iteration order — ASW1, ASW2, ASW3), because the CRC is
    /// over the concatenation. A CAL too short to contain the fingerprint field
    /// falls back to [`CAL_ID_NONE`], matching Python's initial value for the
    /// case where no CAL is being flashed at all.
    pub fn for_simos(asw_blocks: &[&[u8]], cal: &[u8], flash_date: FlashDate) -> Self {
        let mut crc: u8 = 0;
        for block in asw_blocks {
            // Chain the running CRC across blocks: identical to hashing the
            // concatenation, without materialising it.
            crc = crc8_continue(crc, block);
        }

        let cal_id = cal
            .get(SIMOS_FINGERPRINT_RANGE)
            .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
            .unwrap_or(CAL_ID_NONE);

        Self::new(flash_date, crc, cal_id)
    }

    /// Builds the DQ381 flavour: CRC8 over the ASW data, CAL ID fixed to
    /// `NONE` (the DQ381 path never reads a fingerprint out of the CAL).
    pub fn for_dq381(asw: &[u8], flash_date: FlashDate) -> Self {
        Self::new(flash_date, crc8_hash(asw), CAL_ID_NONE)
    }

    /// Decodes nine bytes read back from an ECU.
    ///
    /// Mirrors Python: when the CRC fails, the checksum and CAL ID fields are
    /// not trusted and are replaced with `0` and `UNKN`.
    pub fn from_bytes(bytes: &[u8; 9]) -> Self {
        let flash_date = FlashDate::from_bcd_bytes([bytes[0], bytes[1], bytes[2]]);
        let valid = is_valid(bytes);
        if valid {
            Self {
                flash_date,
                asw_checksum: bytes[3],
                cal_id: [bytes[4], bytes[5], bytes[6], bytes[7]],
                is_valid: true,
                is_old: false,
            }
        } else {
            Self {
                flash_date,
                asw_checksum: 0,
                cal_id: CAL_ID_UNKNOWN,
                is_valid: false,
                is_old: is_placeholder_signature(bytes),
            }
        }
    }

    /// Serialises to the nine bytes written to DID `0xF15A`.
    ///
    /// A `None` date encodes as `00 00 00`; that can only arise from
    /// [`WorkshopCode::from_bytes`] on a code whose date field was not BCD, as
    /// every constructor here sets a date.
    pub fn as_bytes(&self) -> [u8; 9] {
        let date = self
            .flash_date
            .map(FlashDate::to_bcd_bytes)
            .unwrap_or([0, 0, 0]);
        let mut out = [0u8; 9];
        out[0..3].copy_from_slice(&date);
        out[3] = self.asw_checksum;
        out[4..8].copy_from_slice(&self.cal_id);
        out[8] = crc8_hash(&out[0..8]);
        out
    }

    /// Human-readable summary, in the spirit of Python's `human_readable`.
    pub fn human_readable(&self) -> String {
        let date = match self.flash_date {
            Some(d) => format!("{:04}-{:02}-{:02}", d.year, d.month, d.day),
            None => "an unreadable date".to_string(),
        };
        if self.is_valid {
            format!(
                "Block fingerprint dated {} is valid and was written by SimosTools or VW_Flash. \
                 It was written with ASW Checksum {} and CAL ID: {}",
                date,
                self.asw_checksum,
                String::from_utf8_lossy(&self.cal_id)
            )
        } else if self.is_old {
            format!(
                "Block fingerprint dated {} was written by an older version of \
                 SimosTools or VW_Flash.",
                date
            )
        } else {
            format!(
                "Block fingerprint dated {} does not appear to be from SimosTools or VW_Flash.",
                date
            )
        }
    }
}

/// Continues a CRC8 over another chunk, so multiple blocks can be hashed as
/// though they were concatenated.
fn crc8_continue(mut crc: u8, data: &[u8]) -> u8 {
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            // Shifting the MSB out is what selects the polynomial feedback.
            crc = if crc & 0x80 != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nine bytes captured from a real Simos18 flash session
    /// (`tests/simos18_full_flash.can`, request `2e f1 5a …`).
    const CAPTURED: [u8; 9] = [0x26, 0x03, 0x11, 0x1E, 0x20, 0x20, 0x20, 0x20, 0x76];

    #[test]
    fn crc8_matches_smbus_check_value() {
        // Standard CRC-8/SMBUS check value for the ASCII string "123456789".
        assert_eq!(crc8_hash(b"123456789"), 0xF4);
        assert_eq!(crc8_hash(b""), 0x00);
        assert_eq!(crc8_hash(&[0x01, 0x02, 0x03, 0x04, 0x05]), 0xBC);
    }

    #[test]
    fn crc8_matches_captured_workshop_code() {
        assert_eq!(crc8_hash(&CAPTURED[0..8]), 0x76);
    }

    #[test]
    fn captured_code_decodes() {
        let code = WorkshopCode::from_bytes(&CAPTURED);
        assert!(code.is_valid);
        assert!(!code.is_old);
        assert_eq!(code.flash_date, Some(FlashDate::new(2026, 3, 11)));
        assert_eq!(code.asw_checksum, 0x1E);
        assert_eq!(&code.cal_id, b"    ");
        assert_eq!(code.as_bytes(), CAPTURED);
    }

    #[test]
    fn hardcoded_placeholder_is_rejected() {
        assert!(!is_valid(&FALLBACK_WORKSHOP_CODE));
        // Its real CRC is 0x58, not the 0x3D it carries.
        assert_eq!(crc8_hash(&FALLBACK_WORKSHOP_CODE[0..8]), 0x58);

        let code = WorkshopCode::from_bytes(&FALLBACK_WORKSHOP_CODE);
        assert!(!code.is_valid);
        assert!(code.is_old);
        assert_eq!(code.cal_id, CAL_ID_UNKNOWN);
        assert_eq!(code.asw_checksum, 0);
    }

    #[test]
    fn real_code_passes_placeholder_detection() {
        let code = WorkshopCode::new(FlashDate::new(2026, 3, 11), 0x1E, *b"ABCD");
        let bytes = code.as_bytes();
        assert!(is_valid(&bytes));
        assert!(!is_placeholder_signature(&bytes));
        assert!(!WorkshopCode::from_bytes(&bytes).is_old);
        assert_eq!(
            bytes,
            [0x26, 0x03, 0x11, 0x1E, b'A', b'B', b'C', b'D', 0xD7]
        );
    }

    #[test]
    fn simos_constructor_concatenates_asw_and_reads_cal_fingerprint() {
        let mut cal = vec![0u8; 0x100];
        cal[SIMOS_FINGERPRINT_RANGE].copy_from_slice(b"ABCD");

        let code = WorkshopCode::for_simos(
            &[&[0x01, 0x02, 0x03], &[0x04, 0x05]],
            &cal,
            FlashDate::new(2026, 3, 11),
        );
        // CRC8 of the concatenation 01 02 03 04 05.
        assert_eq!(code.asw_checksum, 0xBC);
        assert_eq!(&code.cal_id, b"ABCD");
        assert!(is_valid(&code.as_bytes()));
    }

    #[test]
    fn simos_constructor_falls_back_when_cal_is_short() {
        let code = WorkshopCode::for_simos(&[&[0xAA]], &[0u8; 4], FlashDate::new(2026, 3, 11));
        assert_eq!(code.cal_id, CAL_ID_NONE);
    }

    #[test]
    fn dq381_constructor_uses_none_cal_id() {
        let date = FlashDate::new(2026, 3, 11);
        let code = WorkshopCode::for_dq381(&[0x01, 0x02, 0x03, 0x04, 0x05], date);
        assert_eq!(code.asw_checksum, 0xBC);
        assert_eq!(&code.cal_id, b"NONE");
        assert_eq!(code.as_bytes()[0..3], [0x26, 0x03, 0x11]);
    }

    #[test]
    fn bcd_round_trips() {
        assert_eq!(
            FlashDate::new(2026, 3, 11).to_bcd_bytes(),
            [0x26, 0x03, 0x11]
        );
        assert_eq!(
            FlashDate::new(1999, 12, 31).to_bcd_bytes(),
            [0x99, 0x12, 0x31]
        );
        assert_eq!(
            FlashDate::from_bcd_bytes([0x24, 0x10, 0x09]),
            Some(FlashDate::new(2024, 10, 9))
        );
        // 0x1A has a non-decimal nibble; month 0x13 and day 0x32 are out of range.
        assert_eq!(FlashDate::from_bcd_bytes([0x1A, 0x01, 0x01]), None);
        assert_eq!(FlashDate::from_bcd_bytes([0x26, 0x13, 0x01]), None);
        assert_eq!(FlashDate::from_bcd_bytes([0x26, 0x01, 0x32]), None);
    }

    #[test]
    fn undecodable_date_still_serialises() {
        // Placeholder's date field 0x20 0x04 0x20 -> day 20 is fine, month 04 is
        // fine, year 20 is fine, so use a genuinely bad one.
        let code = WorkshopCode::from_bytes(&[0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0]);
        assert!(code.flash_date.is_none());
        assert_eq!(code.as_bytes()[0..3], [0x00, 0x00, 0x00]);
    }
}
