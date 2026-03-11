//! LZSS encoder/decoder matching the C `lzss.c` (Storer-Szymanski modified LZ77).
//!
//! Format: byte-oriented flag bytes, each governing 8 items.
//! - Flag bit 0 (MSB first): literal byte (1 data byte follows)
//! - Flag bit 1 (MSB first): back-reference (2 data bytes follow)
//!
//! Back-reference encoding (2 bytes):
//!   byte1 = (length << 2) | (dist_hi & 0x03)
//!   byte2 = dist_lo
//!   dist = WINDOW_SIZE - offset   (10-bit distance)
//!   length = raw match length     (6-bit, range 3..63)
//!
//! Constants: WINDOW_SIZE=1023, MAX_UNCODED=2, MAX_CODED=64.

const WINDOW_SIZE: usize = 1023;
const MAX_UNCODED: usize = 2;
const MAX_CODED: usize = 64;

/// Padding mode for the encoder output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    /// No padding.
    None,
    /// Pad output to next 16-byte (AES block) boundary with 0x00.
    AesBlock,
    /// Pad output to match exact decompressed length (uses LZSS no-op references).
    Exact,
}

// ── Encoder ─────────────────────────────────────────────────────────────────

struct Match {
    offset: usize,
    length: usize,
}

fn find_match(
    window: &[u8; WINDOW_SIZE],
    window_head: usize,
    lookahead: &[u8; MAX_CODED],
    lookahead_head: usize,
    lookahead_len: usize,
) -> Match {
    let mut best = Match { offset: 0, length: 0 };

    for i in 0..WINDOW_SIZE {
        let mut k = 0;
        for j in 0..MAX_CODED {
            if j == lookahead_len {
                break;
            }
            if (i + j) == WINDOW_SIZE {
                break;
            }
            if window[(window_head + i + j) % WINDOW_SIZE]
                != lookahead[(lookahead_head + j) % MAX_CODED]
            {
                break;
            }
            k = j + 1;
            if k >= best.length {
                best.length = k;
                best.offset = i;
            }
        }
        let _ = k; // suppress unused warning
    }

    best
}

pub fn encode(input: &[u8], padding: Padding) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut window = [0x11u8; WINDOW_SIZE];
    let mut lookahead = [0u8; MAX_CODED];

    let mut window_head: usize = 0;
    let mut lookahead_head: usize = 0;
    let mut read_pos: usize = 0;

    // Fill initial lookahead buffer
    let mut len: usize = 0;
    while len < MAX_CODED && read_pos < input.len() {
        lookahead[len] = input[read_pos];
        read_pos += 1;
        len += 1;
    }

    if len == 0 {
        return output;
    }

    let mut flags: u8 = 0;
    let mut flag_pos: u8 = 0x80;
    let mut encoded_data: Vec<u8> = Vec::new();
    let mut compressed_size: usize = 0;

    let mut match_data = find_match(&window, window_head, &lookahead, lookahead_head, len);

    while len > 0 {
        if match_data.length > 0x3F {
            match_data.length = 0x3F;
        }

        if match_data.length <= MAX_UNCODED {
            // Literal
            match_data.length = 1;
            encoded_data.push(lookahead[lookahead_head]);
        } else {
            // Back-reference
            let dist = WINDOW_SIZE - match_data.offset;
            encoded_data.push(((dist >> 8) as u8) | ((match_data.length as u8) << 2));
            encoded_data.push((dist & 0xFF) as u8);
            flags |= flag_pos;
        }

        if flag_pos == 0x01 {
            // 8 items accumulated — flush
            output.push(flags);
            compressed_size += 1;
            for &b in &encoded_data {
                output.push(b);
                compressed_size += 1;
            }
            flags = 0;
            flag_pos = 0x80;
            encoded_data.clear();
        } else {
            flag_pos >>= 1;
        }

        // Advance sliding window and refill lookahead
        let mut i = 0;
        while i < match_data.length && read_pos < input.len() {
            window[window_head] = lookahead[lookahead_head];
            lookahead[lookahead_head] = input[read_pos];
            window_head = (window_head + 1) % WINDOW_SIZE;
            lookahead_head = (lookahead_head + 1) % MAX_CODED;
            read_pos += 1;
            i += 1;
        }

        // Handle case where input is exhausted before match_data.length
        while i < match_data.length {
            window[window_head] = lookahead[lookahead_head];
            window_head = (window_head + 1) % WINDOW_SIZE;
            lookahead_head = (lookahead_head + 1) % MAX_CODED;
            len -= 1;
            i += 1;
        }

        match_data = find_match(&window, window_head, &lookahead, lookahead_head, len);
    }

    // Flush remaining encoded data
    if !encoded_data.is_empty() {
        if padding == Padding::Exact {
            let total_size = compressed_size + encoded_data.len() + 1;
            if total_size % 16 != 0 {
                while (compressed_size + encoded_data.len() + 1) % 16 != 0 {
                    if flag_pos == 0x00 {
                        break;
                    }
                    encoded_data.push(0);
                    encoded_data.push(0);
                    flags |= flag_pos;
                    flag_pos >>= 1;
                }
            }
        }

        output.push(flags);
        compressed_size += 1;
        for &b in &encoded_data {
            output.push(b);
            compressed_size += 1;
        }
    }

    // Final padding
    match padding {
        Padding::Exact => {
            let remainder = 16 - (compressed_size % 16);
            let padding_lengths: [usize; 17] = [
                0x0, 0x1, 0x12, 0x3, 0x14, 0x5, 0x16, 0x7,
                0x18, 0x9, 0x1A, 0xB, 0x1C, 0xD, 0x1E, 0xF, 0x0,
            ];
            let padding_block: [u8; 17] = [
                0xFF, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ];
            let r = padding_lengths[remainder];
            for i in 0..r {
                output.push(padding_block[i % 0x11]);
            }
        }
        Padding::AesBlock | Padding::None => {
            if padding == Padding::AesBlock {
                while compressed_size % 16 != 0 {
                    output.push(0x00);
                    compressed_size += 1;
                }
            }
        }
    }

    output
}

// ── Decoder ──────────────────────────────────────────────────────────────────

pub fn decode(input: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut window = [b' '; WINDOW_SIZE]; // 0x20 — matches C decoder
    let mut next_char: usize = 0;
    let mut pos: usize = 0;

    let mut flags: u8 = 0;
    let mut flags_used: u8 = 7;

    loop {
        flags <<= 1;
        flags_used += 1;

        if flags_used == 8 {
            if pos >= input.len() {
                break;
            }
            flags = input[pos];
            pos += 1;
            flags_used = 0;
        }

        if (flags & 0x80) == 0 {
            // Literal
            if pos >= input.len() {
                break;
            }
            let c = input[pos];
            pos += 1;
            output.push(c);
            window[next_char] = c;
            next_char = (next_char + 1) % WINDOW_SIZE;
        } else {
            // Back-reference: 2 bytes
            if pos + 1 >= input.len() {
                break;
            }
            let byte1 = input[pos] as usize;
            let byte2 = input[pos + 1] as usize;
            pos += 2;

            let dist = byte2 + ((byte1 & 0x03) << 8);
            let offset = WINDOW_SIZE - dist;
            let length = byte1 >> 2;

            for i in 0..length {
                let b = window[(next_char + offset + i) % WINDOW_SIZE];
                output.push(b);
                window[(next_char + i) % WINDOW_SIZE] = b;
            }
            next_char = (next_char + length) % WINDOW_SIZE;
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_short() {
        let data = b"Hello, world! Hello, world!";
        let compressed = encode(data, Padding::None);
        let decompressed = decode(&compressed);
        assert_eq!(decompressed, data);
    }

    #[test]
    fn round_trip_zeros() {
        let data = vec![0u8; 1024];
        let compressed = encode(&data, Padding::None);
        let decompressed = decode(&compressed);
        assert_eq!(decompressed, data);
    }

    #[test]
    fn round_trip_spaces() {
        let data = vec![0x20u8; 512];
        let compressed = encode(&data, Padding::None);
        let decompressed = decode(&compressed);
        assert_eq!(decompressed, data);
    }

    #[test]
    fn aes_padding_alignment() {
        let data = b"test";
        let compressed = encode(data, Padding::AesBlock);
        assert_eq!(compressed.len() % 16, 0);
    }

    #[test]
    fn round_trip_repeating_pattern() {
        // Pattern that will generate back-references
        let mut data = Vec::new();
        for _ in 0..10 {
            data.extend_from_slice(b"ABCDEFGH");
        }
        let compressed = encode(&data, Padding::None);
        let decompressed = decode(&compressed);
        assert_eq!(decompressed, data, "repeating pattern round-trip failed");
    }

    #[test]
    fn round_trip_large_binary() {
        // Simulate a flash block: 64 KiB of pseudo-random-ish data
        let data: Vec<u8> = (0..65536u32)
            .map(|i| (i.wrapping_mul(1664525).wrapping_add(1013904223) >> 24) as u8)
            .collect();
        let compressed = encode(&data, Padding::AesBlock);
        assert_eq!(compressed.len() % 16, 0);
        let decompressed = decode(&compressed);
        // Decoder may produce a few extra bytes from padding (no end-of-stream marker),
        // so just verify the first data.len() bytes match exactly.
        assert!(
            decompressed.len() >= data.len(),
            "decompressed too short: {} < {}",
            decompressed.len(),
            data.len()
        );
        assert_eq!(
            &decompressed[..data.len()],
            &data[..],
            "large binary round-trip content mismatch"
        );
    }

    #[test]
    fn round_trip_larger_than_window() {
        let data: Vec<u8> = (0..4096).map(|i: u32| (i % 251) as u8).collect();
        let compressed = encode(&data, Padding::None);
        let decompressed = decode(&compressed);
        assert_eq!(decompressed, data);
    }
}
