//! Checksum validation and fixing for VW ECU flash blocks.
//!
//! Four families:
//! - **Simos CRC32**: non-reflected MSB-first CRC32 (poly 0x04C11DB7, init 0)
//! - **ECM3**: 64-bit pure sum of u32 LE words
//! - **DQ381**: standard zlib CRC32 (reflected), stored big-endian
//! - **DSG JAMCRC**: `0xFFFFFFFF - crc32(data[..-4])`, stored little-endian
//! - **Haldex 16-bit**: NOT of u16 LE word sum, stored at fixed offset

mod dq381;
mod dsg;
mod ecm3;
mod haldex;
mod simos_crc;

pub use dq381::validate_dq381;
pub use dsg::validate_dsg;
pub use ecm3::{load_ecm3_location, locate_ecm3_with_asw1, validate_ecm3};
pub use haldex::validate_haldex;
pub use simos_crc::{crc32_simos, validate_simos, validate_simos_block};
