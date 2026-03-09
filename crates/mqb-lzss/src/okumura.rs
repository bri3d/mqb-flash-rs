//! Okumura LZSS encoder/decoder.
//!
//! Parameters: EI=10, EJ=6, P=2, N=1024, F=65, init_chr=0x20.
//! This is a bit-stream codec — each "code word" is either:
//!   - `1` + 8 literal bits (a raw byte), or
//!   - `0` + EI position bits + EJ length bits (a back-reference).

const EI: u32 = 10;
const EJ: u32 = 6;
const P: usize = 2;
const N: usize = 1 << EI as usize; // 1024
const F: usize = (1 << EJ as usize) + 1; // 65
const INIT_CHR: u8 = 0x20;

/// Padding mode for the encoder output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    /// No padding (default behaviour, identical to original C binary).
    None,
    /// Pad output to next 16-byte (AES block) boundary.
    AesBlock,
    /// Pad output to match exact input length.
    Exact,
}

// ── Encoder ─────────────────────────────────────────────────────────────────

struct Encoder<'a> {
    input: &'a [u8],
    output: Vec<u8>,
    buffer: [u8; N * 2],
    bit_buf: u8,
    bit_mask: u8,
}

impl<'a> Encoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        let mut buffer = [0u8; N * 2];
        buffer[..N - F].fill(INIT_CHR);
        Self {
            input,
            output: Vec::new(),
            buffer,
            bit_buf: 0,
            bit_mask: 128,
        }
    }

    fn putbit(&mut self, one: bool) {
        if one {
            self.bit_buf |= self.bit_mask;
        }
        self.bit_mask >>= 1;
        if self.bit_mask == 0 {
            self.output.push(self.bit_buf);
            self.bit_buf = 0;
            self.bit_mask = 128;
        }
    }

    fn flush(&mut self) {
        if self.bit_mask != 128 {
            self.output.push(self.bit_buf);
        }
    }

    /// Emit a literal byte (1 + 8 bits).
    fn output1(&mut self, c: u8) {
        self.putbit(true);
        for bit in (0..8).rev() {
            self.putbit((c >> bit) & 1 != 0);
        }
    }

    /// Emit a back-reference (0 + EI position bits + EJ length bits).
    fn output2(&mut self, x: usize, y: usize) {
        self.putbit(false);
        let mut mask = N >> 1;
        while mask != 0 {
            self.putbit(x & mask != 0);
            mask >>= 1;
        }
        let mut mask = 1 << (EJ - 1);
        while mask != 0 {
            self.putbit(y & mask as usize != 0);
            mask >>= 1;
        }
    }

    fn encode(mut self) -> Vec<u8> {
        let input = self.input;
        let len = input.len();

        // Fill the look-ahead region: load up to N+F bytes from input into the
        // upper half of the double-buffer (positions N-F .. N*2).
        let initial_load = len.min(N + F);
        self.buffer[N - F..N - F + initial_load].copy_from_slice(&input[..initial_load]);
        let mut bufferend = N - F + initial_load;
        let mut read_pos = initial_load;

        let mut r = N - F; // current position in ring buffer
        let mut s = 0usize; // start of valid history

        while r < bufferend {
            let f1 = F.min(bufferend - r);
            let c = self.buffer[r];
            let mut x = 0usize;
            let mut y = 1usize;

            // Search for longest match
            let search_start = if r > s { r - 1 } else { s };
            let mut i = search_start as isize;
            while i >= s as isize {
                let i_usize = i as usize;
                if self.buffer[i_usize] == c {
                    let mut j = 1;
                    while j < f1 {
                        if self.buffer[i_usize + j] != self.buffer[r + j] {
                            break;
                        }
                        j += 1;
                    }
                    if j > y {
                        x = i_usize;
                        y = j;
                    }
                }
                if i == s as isize {
                    break;
                }
                i -= 1;
            }

            if y <= P {
                y = 1;
                self.output1(c);
            } else {
                self.output2(x & (N - 1), y - 2);
            }

            r += y;
            s += y;

            // Refill buffer when near the end
            if r >= N * 2 - F {
                for i in 0..N {
                    self.buffer[i] = self.buffer[i + N];
                }
                bufferend -= N;
                r -= N;
                s -= N;

                while bufferend < N * 2 && read_pos < len {
                    self.buffer[bufferend] = input[read_pos];
                    bufferend += 1;
                    read_pos += 1;
                }
            }
        }

        self.flush();
        self.output
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    output: Vec<u8>,
    buffer: [u8; N],
    bit_buf: u8,
    bit_mask: u8,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        let mut buffer = [0u8; N];
        buffer[..N - F].fill(INIT_CHR);
        Self {
            input,
            pos: 0,
            output: Vec::new(),
            buffer,
            bit_buf: 0,
            bit_mask: 0,
        }
    }

    fn getbit(&mut self, n: u32) -> Option<usize> {
        let mut x = 0usize;
        for _ in 0..n {
            if self.bit_mask == 0 {
                if self.pos >= self.input.len() {
                    return None;
                }
                self.bit_buf = self.input[self.pos];
                self.pos += 1;
                self.bit_mask = 128;
            }
            x <<= 1;
            if self.bit_buf & self.bit_mask != 0 {
                x += 1;
            }
            self.bit_mask >>= 1;
        }
        Some(x)
    }

    fn decode(mut self) -> Vec<u8> {
        let mut r = N - F;

        loop {
            let c = match self.getbit(1) {
                None => break,
                Some(v) => v,
            };

            if c != 0 {
                // Literal
                let c = match self.getbit(8) {
                    None => break,
                    Some(v) => v as u8,
                };
                self.output.push(c);
                self.buffer[r] = c;
                r = (r + 1) & (N - 1);
            } else {
                // Back-reference
                let i = match self.getbit(EI) {
                    None => break,
                    Some(v) => v,
                };
                let j = match self.getbit(EJ) {
                    None => break,
                    Some(v) => v,
                };
                for k in 0..=j + 1 {
                    let c = self.buffer[(i + k) & (N - 1)];
                    self.output.push(c);
                    self.buffer[r] = c;
                    r = (r + 1) & (N - 1);
                }
            }
        }

        self.output
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Compress `input` using Okumura LZSS (EI=10, EJ=6, P=2, init_chr=0x20).
pub fn encode(input: &[u8], padding: Padding) -> Vec<u8> {
    let mut out = Encoder::new(input).encode();

    match padding {
        Padding::None => {}
        Padding::AesBlock => {
            let rem = out.len() % 16;
            if rem != 0 {
                out.resize(out.len() + (16 - rem), 0u8);
            }
        }
        Padding::Exact => {
            if out.len() < input.len() {
                out.resize(input.len(), 0u8);
            }
        }
    }

    out
}

/// Decompress an Okumura LZSS stream.
pub fn decode(input: &[u8]) -> Vec<u8> {
    Decoder::new(input).decode()
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
    fn round_trip_large_binary() {
        // Simulate a flash block: 64 KiB of pseudo-random-ish data
        let data: Vec<u8> = (0..65536u32).map(|i| (i.wrapping_mul(1664525).wrapping_add(1013904223) >> 24) as u8).collect();
        let compressed = encode(&data, Padding::AesBlock);
        assert_eq!(compressed.len() % 16, 0);
        let decompressed = decode(&compressed);
        assert_eq!(decompressed, data);
    }

    #[test]
    fn round_trip_larger_than_initial_buffer() {
        // Input larger than N+F=1089 bytes, exercises the ring-buffer refill path
        let data: Vec<u8> = (0..4096).map(|i: u32| (i % 251) as u8).collect();
        let compressed = encode(&data, Padding::None);
        let decompressed = decode(&compressed);
        assert_eq!(decompressed, data);
    }
}
