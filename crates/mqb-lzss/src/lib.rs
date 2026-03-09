//! LZSS compression/decompression for VW ECU firmware.
//!
//! Three distinct algorithms:
//! - **Okumura LZSS** (`encode`/`decode`): bit-stream encoder/decoder, EI=10 EJ=6 P=2.
//!   Used to compress blocks before flashing.
//! - **LZSS10** (`decompress_lzss10`): simple 8-flag-bits-per-byte format.
//!   Used to decompress ODX flash data.
//! - **LegacySimos** (`decompress_legacy`): signifier-byte based LZSS.
//!   Used for Simos8 (very old ECUs).

mod okumura;
mod lzss10;
mod legacy;

pub use okumura::{encode, decode, Padding};
pub use lzss10::decompress_lzss10;
pub use legacy::decompress_legacy;
