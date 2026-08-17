//! LegacySimos LZSS decompressor for Simos8 ECUs.
//!
//! Header layout (bytes 0-10):
//! - `[0]`    signifier byte
//! - `[1]`    offset_size (in bits)
//! - `[2]`    dict_size mask bits (fill_bits)
//! - `[3..7]` block_size (big-endian u32)
//! - `[7..11]` count (big-endian u16, unused during decompression)
//!
//! After the header (cursor starts at 11):
//! - If current byte == signifier:
//!   advance, read big-endian u16, extract offset and length from it,
//!   copy `length` bytes from `output[output_cursor - offset]`,
//!   then copy the next literal byte.
//! - Otherwise: copy literal byte.

fn fill_bits(count: u8) -> u16 {
    if count >= 16 {
        !0
    } else {
        (1u16 << count) - 1
    }
}

/// Decompress a LegacySimos-compressed block.
pub fn decompress_legacy(input: &[u8]) -> Vec<u8> {
    assert!(input.len() >= 11, "LegacySimos input too short");

    let signifier = input[0];
    let offset_size = input[1] as u32;
    let dict_size = fill_bits(input[2]);
    // block_size at bytes 3..7 big-endian
    let block_size = mqb_bytes::read_u32_be(input, 3) as usize;

    let mut output = vec![0u8; block_size];
    let mut output_cursor = 0usize;
    let mut cursor = 11usize;

    while cursor < input.len() {
        if output_cursor >= block_size {
            break;
        }

        if input[cursor] == signifier {
            cursor += 1;
            if cursor + 1 >= input.len() {
                break;
            }
            let offset_and_len = mqb_bytes::read_u16_be(input, cursor);
            cursor += 2;

            let offset = (offset_and_len >> (16 - offset_size)) as usize;
            let length = (offset_and_len & dict_size) as usize;

            let block_offset = output_cursor;
            for i in 0..length {
                if output_cursor >= block_size {
                    break;
                }
                output[output_cursor] = output[block_offset - offset + i];
                output_cursor += 1;
            }

            // Copy the following literal byte
            if cursor < input.len() && output_cursor < block_size {
                output[output_cursor] = input[cursor];
                cursor += 1;
                output_cursor += 1;
            }
        } else {
            output[output_cursor] = input[cursor];
            cursor += 1;
            output_cursor += 1;
        }
    }

    output
}
