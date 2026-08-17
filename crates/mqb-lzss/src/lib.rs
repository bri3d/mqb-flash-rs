//! LZSS compression/decompression for VW ECU firmware.
//!
//! Three distinct algorithms:
//! - **Storer-Szymanski LZSS** (`encode`/`decode`): byte-oriented flag-byte format,
//!   window=1023, max match=63. Used to compress blocks before flashing.
//! - **LZSS10** (`decompress_lzss10`): simple 8-flag-bits-per-byte format.
//!   Used to decompress ODX flash data.
//! - **LegacySimos** (`decompress_legacy`): signifier-byte based LZSS.
//!   Used for Simos8 (very old ECUs).

mod legacy;
mod lzss10;
mod storer_szymanski;

pub use legacy::decompress_legacy;
pub use lzss10::decompress_lzss10;
pub use storer_szymanski::{decode, encode, Padding};
