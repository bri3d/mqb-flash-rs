//! LZSS10 decompressor used for ODX flash data.
//!
//! Format: one flag byte followed by 8 items.
//! - flag bit = 0 → copy next byte literally
//! - flag bit = 1 → read big-endian u16: upper 6 bits = count, lower 10 bits = back-displacement

/// Decompress LZSS10-compressed bytes.
///
/// `decompressed_size` must be the exact expected output length (from the ODX XML).
pub fn decompress_lzss10(input: &[u8], decompressed_size: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(decompressed_size);
    let mut it = input.iter().copied();

    'outer: while output.len() < decompressed_size {
        let flag_byte = match it.next() {
            Some(b) => b,
            None => break,
        };

        for bit in (0..8).rev() {
            if output.len() >= decompressed_size {
                break 'outer;
            }
            let flag = (flag_byte >> bit) & 1;
            if flag == 0 {
                // Literal
                match it.next() {
                    Some(b) => output.push(b),
                    None => break 'outer,
                }
            } else {
                // Back-reference
                let hi = match it.next() {
                    Some(b) => b,
                    None => break 'outer,
                };
                let lo = match it.next() {
                    Some(b) => b,
                    None => break 'outer,
                };
                let sh = ((hi as u16) << 8) | lo as u16;
                let count = (sh >> 10) as usize;
                let disp = (sh & 0x3FF) as usize;

                for _ in 0..count {
                    if output.len() >= decompressed_size {
                        break;
                    }
                    // disp is 1-based from end of output
                    let idx = output.len() - disp;
                    let b = output[idx];
                    output.push(b);
                }
            }
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_literals() {
        // 8 literal bytes: flag=0x00 (all flag bits 0) then 8 bytes
        let input: Vec<u8> = {
            let mut v = vec![0x00u8]; // flag byte: all 0s → 8 literals
            v.extend_from_slice(b"ABCDEFGH");
            v
        };
        let out = decompress_lzss10(&input, 8);
        assert_eq!(out, b"ABCDEFGH");
    }
}
