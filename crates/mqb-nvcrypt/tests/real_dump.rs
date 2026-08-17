//! End-to-end tests against a real Simos18 DFlash image.
//!
//! The unit tests build synthetic records, so they can only prove the code
//! agrees with itself. These prove it agrees with an actual ECU: a genuine
//! 96 KB DFlash read, decrypted with that ECU's real Device ID, checked against
//! the values the reference Python implementation prints for the same file.
//!
//! The dump is not in this repository — it is a specific ECU's NVRAM, including
//! its immobilizer keys. Every test here skips when it is absent, so a clean
//! checkout still passes.

use mqb_nvcrypt::dflash::{Alignment, GenerationSource};
use mqb_nvcrypt::{
    immo_record_from_dump, Dump, Hitag2Keys, ImmoChannelSurvey, ImmoRecord, StStatFct,
    IMMO_CHANNELS,
};

/// `CARGO_MANIFEST_DIR` is `.../VW_Flash_Rewrite/mqb-flash-rs/crates/mqb-nvcrypt`,
/// so four levels up is the directory holding the sibling research repos.
const DUMP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../Simos18_NVCRYPT/PMU0_DFlash.bin"
);

/// The Device ID of the ECU the dump came from.
const DEVICE_ID: [u8; 12] = [
    0x44, 0x80, 0x05, 0x11, 0x18, 0xa0, 0x48, 0x29, 0x02, 0x0c, 0x00, 0x20,
];

/// The identity that ECU actually holds.
const VIN: &str = "3VW4T7AU6GM041367";
const IDX_TUN: u8 = 0x88;
const NO_KEY_MST: u16 = 0xAFBB;
const NO_KEY_SECU: [u8; 16] = [
    0x7c, 0xe4, 0x3c, 0x94, 0x45, 0x20, 0x6b, 0xf2, 0xf5, 0x9c, 0x30, 0x52, 0xcb, 0x00, 0x15, 0x0d,
];

/// The flash generation counter, as printed by the reference tool (`7d05` is
/// the little-endian trailer form of 0x057D).
const GENERATION: u32 = 0x0000_057D;

fn load() -> Option<Dump> {
    let bytes = std::fs::read(DUMP).ok()?;
    Some(Dump::parse(bytes))
}

fn keys() -> Hitag2Keys {
    Hitag2Keys::from_device_id(&DEVICE_ID)
}

macro_rules! dump_or_skip {
    () => {
        match load() {
            Some(dump) => dump,
            None => {
                eprintln!("skipping: {DUMP} is not present");
                return;
            }
        }
    };
}

/// The record scanner and the generation-counter recovery, against a real
/// image: 457 records across 84 live channels, and a counter the FFFE page
/// header and the record CRCs both agree on.
#[test]
fn parses_the_real_image() {
    let dump = dump_or_skip!();

    assert_eq!(dump.records().len(), 457, "total records found");
    assert_eq!(dump.channels().len(), 84, "live channels");

    let generation = dump.generation().expect("the counter must be recoverable");
    assert_eq!(generation.value, GENERATION);
    assert_eq!(
        generation.source,
        GenerationSource::PageHeaderConfirmed,
        "the page header and the record CRCs must agree"
    );
    assert!(!generation.is_disputed());

    // Every live record's outer CRC must validate under that counter. This is
    // the real test of the framing model: 84 channels of varying length,
    // padding and alignment, all from one ECU.
    for channel in dump.channels() {
        let analysis = dump.analyze_channel(channel, Some(&keys())).unwrap();
        assert!(
            analysis.outer_ok(),
            "channel 0x{channel:02X} record CRC did not validate"
        );
    }
}

/// Channel 6 in full, against the reference tool's output for the same record.
#[test]
fn decrypts_the_immobilizer_record() {
    let dump = dump_or_skip!();
    let keys = keys();

    let record = dump.latest(6).expect("channel 6 is present");
    assert_eq!(record.length, 13, "13 FEE slots = 104 bytes");
    assert_eq!(record.crc, 0x5AA2);
    assert_eq!(dump.write_count(6), 4);

    let analysis = dump.analyze(record, Some(&keys));
    assert!(analysis.encrypted, "the immobilizer channels are encrypted");
    assert_eq!(
        analysis.alignment,
        Some(Alignment::Left {
            data_size: 104,
            pad: 0
        })
    );
    // record_way 0: the immobilizer channels carry no inner content CRC.
    assert_eq!(analysis.inner_crc, None);
    assert_eq!(analysis.content.len(), 104);

    let immo = ImmoRecord::decode(&analysis.content).unwrap();
    assert!(immo.dat_stat_crc_ok(), "datStat CRC");
    assert!(immo.dat_dat_crc_ok(), "datDat CRC");
    assert_eq!(immo.dat_stat_crc(), 0xEAC5);
    assert_eq!(immo.dat_dat_crc(), 0xDCB5);

    assert_eq!(immo.vin(), VIN);
    assert_eq!(immo.vin_copy().as_deref(), Some(VIN));
    assert_eq!(immo.vin_copy_ok(), Some(true));
    assert_eq!(immo.no_key_secu(), NO_KEY_SECU);
    assert_eq!(immo.no_key_mst(), NO_KEY_MST);
    assert_eq!(immo.idx_tun(), IDX_TUN);
    assert_eq!(immo.st_stat_fct(), StStatFct::Adapted);
    assert_eq!(immo.ct_dat_stat(), 17437);
    assert_eq!(immo.ct_dat_dat(), 3);
    assert_eq!(immo.no_rnd_old(), [0x3d, 0x93, 0xd9, 0x7a]);
    assert!(immo.b_auth_pre_vld());
    assert!(immo.b_inh_acs_mem());
    assert!(!immo.b_lock());
    assert!(!immo.b_lim_mod_ena());
    assert!(!immo.b_auth_mute());
    assert!(!immo.b_vld_chk_di());
    assert!(!immo.b_trig_fct_di());

    // Re-encoding an untouched record must reproduce the decrypted bytes
    // exactly — the property the dump editor depends on.
    assert_eq!(immo.encode(), analysis.content);
}

/// All three immobilizer channels carry the same identity, which is the
/// redundancy the firmware votes over.
#[test]
fn all_three_immobilizer_channels_agree() {
    let dump = dump_or_skip!();
    let survey = ImmoChannelSurvey::read(&dump, &keys());

    assert_eq!(survey.valid_channels(), IMMO_CHANNELS.to_vec());
    assert!(
        survey.copies_agree(),
        "the three copies must hold one identity"
    );
    assert!(survey.disagreeing_channels().is_empty());
    assert_eq!(survey.first_valid().unwrap().vin(), VIN);

    // The identity is byte-identical across all three, but the records are not
    // the same shape: channel 7 is right-aligned with one leading FEE padding
    // byte, so its payload is 103 bytes where 6 and 8 carry 104. That is
    // exactly why only datDat may be compared.
    let shapes: Vec<(usize, Option<Alignment>)> = IMMO_CHANNELS
        .iter()
        .map(|&c| {
            let a = dump.analyze_channel(c, Some(&keys())).unwrap();
            (a.content.len(), a.alignment)
        })
        .collect();
    assert_eq!(
        shapes,
        vec![
            (
                104,
                Some(Alignment::Left {
                    data_size: 104,
                    pad: 0
                })
            ),
            (
                103,
                Some(Alignment::Right {
                    data_size: 103,
                    skip: 1
                })
            ),
            (
                104,
                Some(Alignment::Left {
                    data_size: 104,
                    pad: 0
                })
            ),
        ]
    );

    let found = immo_record_from_dump(&dump, &keys()).expect("a readable record");
    assert_eq!(found.channel(), Some(6));
    assert_eq!(found.secrets().no_key_secu, NO_KEY_SECU);
}

/// A wrong Device ID must fail loudly rather than produce a plausible-looking
/// identity. The `datDat` CRC covers every field, so it is what catches this.
#[test]
fn a_wrong_device_id_yields_no_record() {
    let dump = dump_or_skip!();

    let mut wrong = DEVICE_ID;
    wrong[0] ^= 0xFF;
    let wrong_keys = Hitag2Keys::from_device_id(&wrong);

    assert!(
        immo_record_from_dump(&dump, &wrong_keys).is_none(),
        "a wrong Device ID must not yield an immobilizer record"
    );
    assert!(ImmoChannelSurvey::read(&dump, &wrong_keys)
        .valid_channels()
        .is_empty());
}

/// The write path, end to end on a real image: change the VIN in all three
/// immobilizer channels, re-encrypt, fix all three CRC layers, and read the
/// result back.
#[test]
fn rewrites_the_immobilizer_identity_in_a_real_image() {
    let mut dump = dump_or_skip!();
    let keys = keys();
    let original = dump.bytes().to_vec();

    const NEW_VIN: &str = "WVWZZZ1KZAW000001";
    const NEW_IDX_TUN: u8 = 0x6A;

    for channel in IMMO_CHANNELS {
        let analysis = dump.analyze_channel(channel, Some(&keys)).unwrap();
        let mut record = ImmoRecord::decode(&analysis.content).unwrap();
        record.set_vin(NEW_VIN).unwrap();
        record.set_idx_tun(NEW_IDX_TUN);
        dump.rewrite_channel(channel, &record.encode(), Some(&keys))
            .unwrap_or_else(|e| panic!("rewriting channel {channel}: {e}"));
    }

    // Re-parse from the bytes that would be written to disk, so this tests the
    // saved image rather than the in-memory bookkeeping.
    let reloaded = Dump::parse(dump.bytes().to_vec());
    assert_eq!(
        reloaded.generation().map(|g| g.value),
        Some(GENERATION),
        "rewriting must not disturb the generation counter"
    );

    let survey = ImmoChannelSurvey::read(&reloaded, &keys);
    assert_eq!(survey.valid_channels(), IMMO_CHANNELS.to_vec());
    for channel in IMMO_CHANNELS {
        let record = reloaded
            .analyze_channel(channel, Some(&keys))
            .and_then(|a| ImmoRecord::decode(&a.content).ok())
            .unwrap();
        assert!(record.dat_dat_crc_ok(), "channel {channel} datDat CRC");
        assert!(record.dat_stat_crc_ok(), "channel {channel} datStat CRC");
        assert_eq!(record.vin(), NEW_VIN);
        assert_eq!(record.vin_copy().as_deref(), Some(NEW_VIN));
        assert_eq!(record.idx_tun(), NEW_IDX_TUN);
        // Untouched fields survive the round trip byte for byte.
        assert_eq!(record.no_key_secu(), NO_KEY_SECU);
        assert_eq!(record.no_key_mst(), NO_KEY_MST);
        assert_eq!(record.ct_dat_dat(), 3);
        assert!(record.b_inh_acs_mem());
    }

    // Every *other* channel in the image is untouched, and the image is still
    // the same size — this is an in-place edit, not a rebuild.
    assert_eq!(dump.bytes().len(), original.len());
    for channel in reloaded.channels() {
        if IMMO_CHANNELS.contains(&channel) {
            continue;
        }
        let before = Dump::parse(original.clone());
        assert_eq!(
            before.latest(channel).map(|r| &r.data),
            reloaded.latest(channel).map(|r| &r.data),
            "channel 0x{channel:02X} must be untouched"
        );
    }
}

/// Writing a record back unchanged must be a byte-for-byte no-op. If it is not,
/// the encrypt/CRC path disagrees with the firmware somewhere, and every edit
/// would carry that error.
#[test]
fn an_unchanged_rewrite_is_a_no_op() {
    let mut dump = dump_or_skip!();
    let keys = keys();
    let original = dump.bytes().to_vec();

    for channel in IMMO_CHANNELS {
        let analysis = dump.analyze_channel(channel, Some(&keys)).unwrap();
        let content = analysis.content.clone();
        dump.rewrite_channel(channel, &content, Some(&keys))
            .unwrap();
    }

    assert_eq!(
        dump.bytes(),
        original.as_slice(),
        "re-encrypting unchanged content must reproduce the image exactly"
    );
}
