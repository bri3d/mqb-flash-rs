//! The two CRC-16 flavours the Simos18 NVRAM uses.
//!
//! * [`crc16_8005`] — poly `0x8005`, **reflected** (so the table is built from
//!   `0xA001`), used by both DFlash record layers. Seeded [`INIT_INNER`] for the
//!   inner content prefix and [`INIT_OUTER`] for the outer record trailer.
//! * [`crc16_ccitt_false`] — poly `0x1021`, init `0xFFFF`, MSB-first, no
//!   reflection and no final XOR. This is the one the *immobilizer* uses inside
//!   its `datStat` / `datDat` sub-records, and the one the diagnostic login PIN
//!   is derived with.
//!
//! The two are unrelated despite both being "CRC-16"; mixing them up produces
//! plausible-looking garbage, so they live in one file to keep the contrast
//! visible.

/// Seed for the inner content CRC, stored as a 2-byte little-endian prefix on
/// channels whose `record_way` is 1.
pub const INIT_INNER: u16 = 0xABCD;

/// Seed for the outer record CRC, stored big-endian after the record marker.
pub const INIT_OUTER: u16 = 0xA55A;

/// Reflected table for poly `0x8005` (i.e. `0xA001` in reflected form).
const TABLE: [u16; 256] = build_table();

const fn build_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u16;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xA001
            } else {
                c >> 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

/// CRC-16 poly `0x8005` (reflected) over `data`, starting from `init`.
///
/// Both DFlash record layers use this; only the seed differs.
pub fn crc16_8005(init: u16, data: &[u8]) -> u16 {
    let mut crc = init;
    for &byte in data {
        crc = TABLE[((crc ^ byte as u16) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// CRC-16/CCITT-FALSE: poly `0x1021`, init `0xFFFF`, MSB-first, no reflection,
/// no final XOR.
///
/// Used for `datStat` / `datDat` inside the immobilizer record and for the
/// diagnostic login PIN.
pub fn crc16_ccitt_false(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
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

    /// The reflected-0x8005 table pinned against the first entries of the table
    /// the Python tool embeds verbatim.
    #[test]
    fn table_matches_embedded_reference() {
        assert_eq!(TABLE[0], 0x0000);
        assert_eq!(TABLE[1], 0xC0C1);
        assert_eq!(TABLE[2], 0xC181);
        assert_eq!(TABLE[3], 0x0140);
        assert_eq!(TABLE[255], 0x4040);
    }

    /// The outer [T] record CRC worked through by hand in NVCRYPT.md: channel
    /// 0x2A's 8-byte record plus its trailer CRCs to 0x50AE.
    #[test]
    fn outer_crc_matches_documented_record() {
        let data = hex("600c00555500007e0500000100462a");
        assert_eq!(crc16_8005(INIT_OUTER, &data), 0x50AE);
    }

    /// The inner [P] content CRC from the same document: channel 1's content,
    /// without the 2-byte prefix, CRCs to the prefix value 0x2042.
    #[test]
    fn inner_crc_matches_documented_record() {
        let data = hex("3131315343384630483830300000");
        assert_eq!(crc16_8005(INIT_INNER, &data), 0x2042);
    }

    /// CCITT-FALSE against the canonical "123456789" check value.
    #[test]
    fn ccitt_false_check_value() {
        assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
