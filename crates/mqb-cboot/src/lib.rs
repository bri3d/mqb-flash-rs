//! CBOOT sample-mode patch for VW/Audi Simos ECUs.
//!
//! Locates the `is_sample_mode()` function in a CBOOT binary by searching for
//! a recognisable Tricore instruction sequence, then overwrites it so the
//! function always returns 1 (sample/development ECU).  This bypasses RSA
//! signature validation while leaving CRC validation intact.
//!
//! The needle appears in exactly two locations in every supported CBOOT:
//! once in PMEM (the library copy) and once in the copy that executes from RAM.
//!
//! # Tricore disassembly
//!
//! Needle (original):
//! ```text
//! DA 00    mov  d15, #0x0
//! 3C 02    j    +2
//! DA 01    mov  d15, #0x1
//! 02 F2    mov  d2,  d15
//! ```
//!
//! Patch (forces d15 = 1, i.e. "sample mode"):
//! ```text
//! 00 00    nop
//! 00 00    nop
//! DA 01    mov  d15, #0x1
//! 02 F2    mov  d2,  d15
//! ```

use thiserror::Error;

/// The Tricore instruction sequence that identifies `is_sample_mode()`.
const NEEDLE: [u8; 8] = [0xDA, 0x00, 0x3C, 0x02, 0xDA, 0x01, 0x02, 0xF2];

/// Replacement bytes that force the function to always return 1.
const PATCH: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0xDA, 0x01, 0x02, 0xF2];

#[derive(Debug, Error, PartialEq)]
pub enum PatchError {
    #[error("CBOOT patch needle found {0} time(s); expected exactly 2 — wrong CBOOT version or already patched?")]
    WrongMatchCount(usize),
}

/// Apply the sample-mode patch to a raw CBOOT block.
///
/// Returns the patched bytes.  Fails if the needle is not found exactly twice.
pub fn patch_cboot(data: &[u8]) -> Result<Vec<u8>, PatchError> {
    let positions: Vec<usize> = data
        .windows(NEEDLE.len())
        .enumerate()
        .filter_map(|(i, w)| (w == NEEDLE).then_some(i))
        .collect();

    if positions.len() != 2 {
        return Err(PatchError::WrongMatchCount(positions.len()));
    }

    let mut out = data.to_vec();
    for pos in positions {
        out[pos..pos + NEEDLE.len()].copy_from_slice(&PATCH);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buf_with_needles(count: usize) -> Vec<u8> {
        // Each needle is separated by a distinct filler byte so they don't overlap.
        let mut v = vec![0xFFu8; 16];
        for _ in 0..count {
            v.extend_from_slice(&NEEDLE);
            v.extend_from_slice(&[0xFF; 16]);
        }
        v
    }

    #[test]
    fn patches_exactly_two_occurrences() {
        let input = buf_with_needles(2);
        let output = patch_cboot(&input).unwrap();

        // Needle should be gone
        assert!(output.windows(NEEDLE.len()).all(|w| w != NEEDLE));
        // Patch bytes should appear twice
        let patch_count = output.windows(PATCH.len()).filter(|w| *w == PATCH).count();
        assert_eq!(patch_count, 2);
        // Length unchanged
        assert_eq!(output.len(), input.len());
    }

    #[test]
    fn errors_on_zero_matches() {
        let input = vec![0u8; 64];
        assert_eq!(patch_cboot(&input), Err(PatchError::WrongMatchCount(0)));
    }

    #[test]
    fn errors_on_one_match() {
        let input = buf_with_needles(1);
        assert_eq!(patch_cboot(&input), Err(PatchError::WrongMatchCount(1)));
    }

    #[test]
    fn errors_on_three_matches() {
        let input = buf_with_needles(3);
        assert_eq!(patch_cboot(&input), Err(PatchError::WrongMatchCount(3)));
    }
}
