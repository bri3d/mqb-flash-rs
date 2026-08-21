//! Simos18 NVRAM: the DFlash-backed EEPROM emulation and its crypto.
//!
//! Simos18 gives the application software an "NVRAM" of 127 channels emulated
//! in the Tricore's DFlash. Some channels are encrypted with a Hitag2 variant
//! keyed by the ECU's 12-byte Tricore Device ID — which is what stops a DFlash
//! image from being cloned onto a different ECU. Channels 6, 7 and 8 hold three
//! identical copies of the **immobilizer record**.
//!
//! Everything here works from an image on disk; nothing in this crate talks to
//! an ECU.
//!
//! ```no_run
//! use mqb_nvcrypt::{Dump, Hitag2Keys, ImmoRecord, IMMO_CHANNELS};
//!
//! let dump = Dump::parse(std::fs::read("PMU0_DFlash.bin")?);
//! let keys = Hitag2Keys::from_device_id(&[0x44, 0x80, 0x05, 0x11, 0x18, 0xa0,
//!                                         0x48, 0x29, 0x02, 0x0c, 0x00, 0x20]);
//! for channel in IMMO_CHANNELS {
//!     let Some(analysis) = dump.analyze_channel(channel, Some(&keys)) else { continue };
//!     if let Ok(record) = ImmoRecord::decode(&analysis.content) {
//!         if record.dat_dat_crc_ok() {
//!             println!("channel {channel}: VIN {}", record.vin());
//!         }
//!     }
//! }
//! # Ok::<(), std::io::Error>(())
//! ```

pub mod crc;
pub mod device_id;
pub mod dflash;
pub mod hitag2;
pub mod record;

pub use crc::{crc16_8005, crc16_ccitt_false, INIT_INNER, INIT_OUTER};
pub use device_id::{extract_device_id, DeviceIdError, DEVICE_ID_ADDR, DEVICE_ID_LEN, FLASH_BASE};
pub use dflash::{
    analyze, Alignment, Dump, Generation, GenerationSource, Hitag2Keys, PageHeader, Record,
    RecordAnalysis, WriteError,
};
pub use hitag2::{crypt, derive_iv, derive_key};
pub use record::{
    ImmoRecord, ImmoSecrets, RecordError, StStatFct, CHANNEL_RECORD_LEN, MIN_RECORD_LEN, VIN_LEN,
};

/// The NVRAM channels that carry the immobilizer record. All three hold an
/// identical copy; the firmware votes between them.
pub const IMMO_CHANNELS: [u8; 3] = [6, 7, 8];

/// Find the immobilizer record in a dump, trying each of channels 6/7/8 in turn.
///
/// A channel counts only when its `datDat` CRC checks out, which is the
/// definitive proof that the Device ID was right — the CRC covers every
/// identity field, so a wrong key cannot pass it.
pub fn immo_record_from_dump(dump: &Dump, keys: &Hitag2Keys) -> Option<ImmoRecord> {
    IMMO_CHANNELS.iter().find_map(|&channel| {
        let analysis = dump.analyze_channel(channel, Some(keys))?;
        let record = ImmoRecord::decode(&analysis.content)
            .ok()?
            .with_channel(channel);
        record.dat_dat_crc_ok().then_some(record)
    })
}

/// Which of channels 6/7/8 carry a readable immobilizer record, and whether
/// they agree.
///
/// The firmware votes between the three copies, so a disagreement is worth
/// surfacing rather than silently taking the first one that parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmoChannelSurvey {
    /// Per channel: the record, when it decrypted and its CRC held.
    pub records: Vec<(u8, Option<ImmoRecord>)>,
}

impl ImmoChannelSurvey {
    /// Read all three immobilizer channels out of a dump.
    pub fn read(dump: &Dump, keys: &Hitag2Keys) -> Self {
        let records = IMMO_CHANNELS
            .iter()
            .map(|&channel| {
                let record = dump
                    .analyze_channel(channel, Some(keys))
                    .and_then(|a| ImmoRecord::decode(&a.content).ok())
                    .map(|r| r.with_channel(channel))
                    .filter(|r| r.dat_dat_crc_ok());
                (channel, record)
            })
            .collect();
        Self { records }
    }

    /// The channels that produced a valid record.
    pub fn valid_channels(&self) -> Vec<u8> {
        self.records
            .iter()
            .filter(|(_, r)| r.is_some())
            .map(|(c, _)| *c)
            .collect()
    }

    /// The first valid record, which is the one the tools act on.
    pub fn first_valid(&self) -> Option<&ImmoRecord> {
        self.records.iter().find_map(|(_, r)| r.as_ref())
    }

    /// True when every readable copy holds the same identity.
    ///
    /// Only `datDat` is compared: the three channels are separate FEE records
    /// of slightly different lengths, so their trailing padding legitimately
    /// differs and comparing whole payloads would report a false disagreement.
    pub fn copies_agree(&self) -> bool {
        let mut valid = self.records.iter().filter_map(|(_, r)| r.as_ref());
        let Some(first) = valid.next() else {
            return true;
        };
        valid.all(|r| r.dat_dat_bytes() == first.dat_dat_bytes())
    }

    /// Copies whose `datDat` differs from the first readable one.
    ///
    /// The firmware votes between the three, so a split decision is worth
    /// naming rather than silently resolving.
    pub fn disagreeing_channels(&self) -> Vec<u8> {
        let Some(first) = self.first_valid() else {
            return Vec::new();
        };
        self.records
            .iter()
            .filter_map(|(c, r)| r.as_ref().map(|r| (*c, r)))
            .filter(|(_, r)| r.dat_dat_bytes() != first.dat_dat_bytes())
            .map(|(c, _)| c)
            .collect()
    }
}
