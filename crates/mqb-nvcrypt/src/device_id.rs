//! Recovering the 12-byte Tricore Device ID from a program-flash dump.
//!
//! The Device ID keys every encrypted NVRAM channel ([`crate::hitag2`]). It is
//! readable over JTAG, but a bank-0 PMEM dump of the same ECU already contains
//! a copy at `0x80014200`, in the OTP area between SBOOT and CBOOT — so a full
//! flash read is enough to decrypt that ECU's DFlash, with no live ECU or GDB
//! session involved.
//!
//! The word order is the order the boot code stages it to `0xD0000000`, which
//! is the order [`crate::hitag2::derive_key`] and [`crate::hitag2::derive_iv`]
//! consume.

use mqb_bytes::read_u32_le;

/// Default base address of a bank-0 program-flash image.
pub const FLASH_BASE: u32 = 0x8000_0000;

/// Where the Device ID copy lives in the OTP area.
pub const DEVICE_ID_ADDR: u32 = 0x8001_4200;

/// Length of the Device ID.
pub const DEVICE_ID_LEN: usize = 12;

/// The SHA-256 round-constant table, also in the OTP area. Used as an anchor:
/// if these two words are where they should be, the image really is a bank-0
/// dump at the assumed base.
const OTP_SHA256_K_ADDR: u32 = 0x8001_4308;

/// Why a Device ID could not be read out of a flash image.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceIdError {
    /// The SHA-256 constant table is not at the expected address, so this is
    /// not a bank-0 image at the assumed base.
    #[error(
        "no OTP signature at base 0x{base:08X}: this is not a bank-0 program-flash dump, \
         or the base address is wrong (a DFlash or bank-1 dump will fail this way)"
    )]
    NoOtpSignature { base: u32 },

    /// The image is too short to contain the Device ID at the given address.
    #[error("flash image is too short to hold a Device ID at 0x{addr:08X}")]
    TooShort { addr: u32 },

    /// The slot is all `0x00` or all `0xFF` — it was never programmed.
    #[error("the Device ID slot at 0x{addr:08X} is blank; it was never programmed")]
    Blank { addr: u32 },
}

/// Pull the 12-byte Device ID out of a program-flash dump.
///
/// `base` is the address the image starts at and `addr` the Device ID address;
/// both default to [`FLASH_BASE`] / [`DEVICE_ID_ADDR`] for a normal bank-0 read.
pub fn extract_device_id(
    flash: &[u8],
    base: u32,
    addr: u32,
) -> Result<[u8; DEVICE_ID_LEN], DeviceIdError> {
    let word = |a: u32| -> Option<u32> {
        let off = a.checked_sub(base)? as usize;
        (off + 4 <= flash.len()).then(|| read_u32_le(flash, off))
    };

    // Anchor on the SHA-256 round constants before trusting anything else here.
    if word(OTP_SHA256_K_ADDR) != Some(0x428A_2F98)
        || word(OTP_SHA256_K_ADDR + 4) != Some(0x7137_4491)
    {
        return Err(DeviceIdError::NoOtpSignature { base });
    }

    let off = addr
        .checked_sub(base)
        .ok_or(DeviceIdError::TooShort { addr })? as usize;
    if off + DEVICE_ID_LEN > flash.len() {
        return Err(DeviceIdError::TooShort { addr });
    }

    let mut id = [0u8; DEVICE_ID_LEN];
    id.copy_from_slice(&flash[off..off + DEVICE_ID_LEN]);
    if id.iter().all(|&b| b == id[0]) {
        return Err(DeviceIdError::Blank { addr });
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic image with the OTP anchor and a Device ID in place.
    fn image(id: [u8; DEVICE_ID_LEN]) -> Vec<u8> {
        let mut flash = vec![0u8; 0x20000];
        let k = (OTP_SHA256_K_ADDR - FLASH_BASE) as usize;
        flash[k..k + 4].copy_from_slice(&0x428A_2F98u32.to_le_bytes());
        flash[k + 4..k + 8].copy_from_slice(&0x7137_4491u32.to_le_bytes());
        let d = (DEVICE_ID_ADDR - FLASH_BASE) as usize;
        flash[d..d + DEVICE_ID_LEN].copy_from_slice(&id);
        flash
    }

    #[test]
    fn reads_the_id_when_the_anchor_is_present() {
        let id = [
            0x44, 0x80, 0x05, 0x11, 0x18, 0xa0, 0x48, 0x29, 0x02, 0x0c, 0x00, 0x20,
        ];
        assert_eq!(
            extract_device_id(&image(id), FLASH_BASE, DEVICE_ID_ADDR),
            Ok(id)
        );
    }

    /// A DFlash dump, or the wrong base, must be refused rather than producing
    /// a confident wrong key.
    #[test]
    fn refuses_an_image_without_the_otp_anchor() {
        let flash = vec![0u8; 0x20000];
        assert_eq!(
            extract_device_id(&flash, FLASH_BASE, DEVICE_ID_ADDR),
            Err(DeviceIdError::NoOtpSignature { base: FLASH_BASE })
        );
    }

    #[test]
    fn refuses_a_blank_slot() {
        let flash = image([0xFF; DEVICE_ID_LEN]);
        assert_eq!(
            extract_device_id(&flash, FLASH_BASE, DEVICE_ID_ADDR),
            Err(DeviceIdError::Blank {
                addr: DEVICE_ID_ADDR
            })
        );
    }

    #[test]
    fn refuses_a_truncated_image() {
        let mut flash = image([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        flash.truncate((DEVICE_ID_ADDR - FLASH_BASE) as usize + 4);
        // The anchor sits past the truncation point, so this reports as a
        // missing signature rather than a short read — either way, refused.
        assert!(extract_device_id(&flash, FLASH_BASE, DEVICE_ID_ADDR).is_err());
    }
}
