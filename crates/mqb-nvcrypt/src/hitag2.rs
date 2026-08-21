//! The Hitag2-like stream cipher that protects the encrypted NVRAM channels.
//!
//! This is the Mifare Hitag2 construction with **altered `f4a` / `f4b` / `f5c`
//! filter tables** — the published constants do not decrypt Simos18 NVRAM, so
//! the three tables below were recovered from the firmware.
//!
//! The 6-byte key and 4-byte IV are both derived from the 12-byte Tricore
//! Device ID ([`derive_key`] / [`derive_iv`]), which is what stops a DFlash
//! image from being cloned onto a different ECU.
//!
//! The cipher produces a 2-byte keystream word per *serial* value, and the
//! serial starts at the NVRAM channel number and advances by 2 per word — so
//! every channel gets its own keystream. Because the payload is simply XORed
//! with that keystream, [`crypt`] both encrypts and decrypts.

/// Filter table `f5c` — 32 entries, one bit each.
const F5C: [u8; 32] = [
    0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01,
    0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00,
];

/// Filter table `f4b` — 16 entries, one bit each.
const F4B: [u8; 16] = [
    0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
];

/// Filter table `f4a` — 16 entries, one bit each.
const F4A: [u8; 16] = [
    0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
];

/// The cipher's 48-bit shift register.
type State = [u8; 6];

/// Derive the 6-byte cipher key from the 12-byte Tricore Device ID.
pub fn derive_key(device_id: &[u8]) -> [u8; 6] {
    assert!(
        device_id.len() >= 8,
        "device id must be at least 8 bytes to derive a key and IV"
    );
    [
        device_id[0] ^ device_id[1] ^ device_id[4],
        device_id[2] ^ device_id[1] ^ device_id[3],
        device_id[0] ^ device_id[2] ^ device_id[5],
        device_id[0] ^ device_id[3] ^ device_id[4],
        device_id[3] ^ device_id[1] ^ device_id[6],
        device_id[4] ^ device_id[1] ^ device_id[5],
    ]
}

/// Derive the 4-byte cipher IV from the 12-byte Tricore Device ID.
pub fn derive_iv(device_id: &[u8]) -> [u8; 4] {
    assert!(
        device_id.len() >= 8,
        "device id must be at least 8 bytes to derive a key and IV"
    );
    [
        device_id[5] ^ device_id[4] ^ device_id[6],
        device_id[5] ^ device_id[2] ^ device_id[7],
        device_id[6] ^ device_id[4] ^ device_id[7],
        device_id[0] ^ device_id[6] ^ device_id[7],
    ]
}

/// The non-linear filter over the shift register: five 4-bit taps feeding
/// `f4a`/`f4b`, combined and used to index `f5c`.
fn filter(s: &State) -> u8 {
    let a = F4A[(((s[0] >> 2) & 0x0C) | ((s[0] >> 1) & 0x03)) as usize];
    let b = F4B[(((s[1] >> 1) & 0x04) | ((s[1] >> 4) & 0x08) | (s[1] & 0x03)) as usize];
    let c = F4B[(((s[2] >> 3) & 0x08)
        | (s[2] & 0x04)
        | (s[2].wrapping_mul(2) & 0x02)
        | ((s[3] >> 5) & 0x01)) as usize];
    let d = F4B[((s[3] & 0x0C) | (s[3].wrapping_mul(2) & 0x02) | ((s[4] >> 6) & 0x01)) as usize];
    let e = F4A[(((s[5] >> 2) & 0x06) | ((s[4] >> 2) & 0x08) | ((s[5] >> 1) & 0x01)) as usize];

    let mut x = b | a.wrapping_mul(2);
    x = c | x.wrapping_mul(2);
    x = d | x.wrapping_mul(2);
    x = x.wrapping_mul(2) | e;
    F5C[x as usize]
}

/// Shift the 48-bit register left by one and insert `new_bit` at the bottom.
fn shift_in(s: &State, new_bit: u8) -> State {
    [
        (s[0] << 1) | (s[1] >> 7),
        (s[1] << 1) | (s[2] >> 7),
        (s[2] << 1) | (s[3] >> 7),
        (s[3] << 1) | (s[4] >> 7),
        (s[4] << 1) | (s[5] >> 7),
        (s[5] << 1) | (new_bit & 1),
    ]
}

/// The LFSR feedback term. Note `s[4]` is deliberately untapped.
fn feedback(s: &State) -> u8 {
    let v = (s[0].wrapping_mul(4))
        ^ s[0]
        ^ (s[0].wrapping_mul(8))
        ^ (s[0].wrapping_mul(0x40))
        ^ (s[0].wrapping_mul(0x80))
        ^ s[1]
        ^ s[2]
        ^ (s[2].wrapping_mul(0x40))
        ^ (s[2].wrapping_mul(0x80))
        ^ (s[3].wrapping_mul(4))
        ^ (s[3].wrapping_mul(0x40))
        ^ (s[5].wrapping_mul(2))
        ^ (s[5].wrapping_mul(4))
        ^ (s[5].wrapping_mul(8))
        ^ (s[5].wrapping_mul(0x40))
        ^ (s[5].wrapping_mul(0x80));
    (v & 0x80) >> 7
}

/// Initialise the register from the serial, then mix in the 32 key/IV bits.
fn init_state(key: &[u8; 6], iv: &[u8; 4], serial: u16) -> State {
    let hi = (serial >> 8) as u8;
    let lo = serial as u8;
    let mut s: State = [hi, lo, hi, lo, key[0], key[1]];

    let mixed = [
        iv[0] ^ key[2],
        iv[1] ^ key[3],
        iv[2] ^ key[4],
        iv[3] ^ key[5],
    ];
    for byte in mixed {
        for bit in (0..8).rev() {
            let f = filter(&s);
            s = shift_in(&s, f ^ ((byte >> bit) & 1));
        }
    }
    s
}

/// One 2-byte keystream word for `serial`.
pub fn keystream_word(key: &[u8; 6], iv: &[u8; 4], serial: u16) -> [u8; 2] {
    let mut s = init_state(key, iv, serial);
    let mut out = [0u8; 2];
    for byte in out.iter_mut() {
        let mut acc = 0u8;
        for bit in (0..8).rev() {
            let fb = feedback(&s);
            s = shift_in(&s, fb);
            acc |= filter(&s) << bit;
        }
        *byte = acc;
    }
    out
}

/// XOR `data` with the keystream for `serial`, advancing the serial by 2 per
/// 2-byte word.
///
/// The cipher is a pure XOR stream, so this is both the encryptor and the
/// decryptor.
/// The keystream comes a word at a time, so an odd-length payload has a
/// leftover byte. It is **copied through unchanged** rather than dropped (as
/// the reference Python does), so `crypt(crypt(x)) == x` holds for every length
/// — the property a dump rewriter depends on. In practice that byte only ever
/// lands in FEE padding.
pub fn crypt(data: &[u8], key: &[u8; 6], iv: &[u8; 4], serial: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut s = serial;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let ks = keystream_word(key, iv, s);
        out.push(chunk[0] ^ ks[0]);
        out.push(chunk[1] ^ ks[1]);
        s = s.wrapping_add(2);
    }
    out.extend_from_slice(chunks.remainder());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE_ID: [u8; 12] = [
        0x44, 0x80, 0x05, 0x11, 0x18, 0xa0, 0x48, 0x29, 0x02, 0x0c, 0x00, 0x20,
    ];

    /// The key and IV the reference implementation derives for the bench ECU
    /// whose Device ID is `4480051118a04829020c0020`.
    #[test]
    fn key_and_iv_derivation() {
        assert_eq!(derive_key(&DEVICE_ID), [0xdc, 0x94, 0xe1, 0x4d, 0xd9, 0x38]);
        assert_eq!(derive_iv(&DEVICE_ID), [0xf0, 0x8c, 0x79, 0x25]);
    }

    /// Known-answer test for the cipher itself, pinning the recovered
    /// `f4a`/`f4b`/`f5c` tables and the whole state machine — a transcription
    /// slip shows up here rather than as a dump that decrypts to noise.
    #[test]
    fn keystream_known_answers() {
        let key = derive_key(&DEVICE_ID);
        let iv = derive_iv(&DEVICE_ID);
        for (serial, expected) in [
            (0u16, [0xfc, 0x42]),
            (1, [0xc6, 0x9f]),
            (2, [0xa7, 0x95]),
            (6, [0x9d, 0xf1]),
            (7, [0x1f, 0xe3]),
            (8, [0x7c, 0x87]),
        ] {
            assert_eq!(
                keystream_word(&key, &iv, serial),
                expected,
                "keystream word for serial {serial}"
            );
        }
    }

    /// XOR stream: encrypting twice is the identity, whatever the serial.
    #[test]
    fn crypt_is_an_involution() {
        let key = derive_key(&DEVICE_ID);
        let iv = derive_iv(&DEVICE_ID);
        let plain: Vec<u8> = (0..104u8).collect();
        let cipher = crypt(&plain, &key, &iv, 6);
        assert_ne!(cipher, plain, "the keystream must not be all zeroes");
        assert_eq!(crypt(&cipher, &key, &iv, 6), plain);
    }

    /// Each channel gets its own keystream, because the serial seeds the state.
    #[test]
    fn keystream_differs_per_channel() {
        let key = derive_key(&DEVICE_ID);
        let iv = derive_iv(&DEVICE_ID);
        let a = keystream_word(&key, &iv, 6);
        let b = keystream_word(&key, &iv, 7);
        assert_ne!(a, b);
    }

    /// A trailing odd byte passes through rather than being dropped.
    #[test]
    fn odd_length_keeps_the_last_byte() {
        let key = derive_key(&DEVICE_ID);
        let iv = derive_iv(&DEVICE_ID);
        let out = crypt(&[1, 2, 3], &key, &iv, 6);
        assert_eq!(out.len(), 3);
        assert_eq!(out[2], 3);
    }
}
