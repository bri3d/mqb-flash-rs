//! Integration tests for the UDS flash sequence using the FakeCanAdapter.
//!
//! Each test drives the full flash sequence against a `.can` fixture file and
//! asserts the sequence completes without error.  Because the fixture contains
//! a real seed/key pair captured from hardware, a failing SA2 VM will cause
//! the security-access T-line to mismatch → FakeCanAdapter warns and the
//! `27 12` response is never queued → the test times out with an auth error.

use std::path::PathBuf;

use mqb_flash_uds::flash::{flash_blocks, FlashOptions};
use mqb_flash_uds::interface::Interface;
use mqb_modules::modules::simos1810::S1810_FLASH_INFO;
use mqb_modules::PreparedBlockData;

/// Build a synthetic CAL (block 5) prepared block for simos18.10.
///
/// Data is 4 093 bytes of zeros — one full transfer chunk at the ECU's
/// reported maximum (0xFFD bytes of data per TransferData request).
/// The FakeCanAdapter auto-responds to every TransferData without inspecting
/// the payload, so the actual bytes are irrelevant.
fn synthetic_cal_block() -> PreparedBlockData {
    PreparedBlockData {
        block_number: 5,
        block_name: "CAL".to_owned(),
        block_encrypted_bytes: vec![0u8; 4093],
        boxcode: "TEST_5G0906259Q__0005".to_owned(),
        compression_type: 0x0A,
        encryption_type: 0x0A,
        should_erase: true,
        uds_checksum: [0, 0, 0, 0],
    }
}

/// Run the complete simos18.10 CAL flash sequence against the fixture.
///
/// Validates:
/// - Correct UDS session/security setup protocol
/// - SA2 VM key derivation (seed 0x80551824 → key 0x4835B093, simos18.10 script)
/// - Erase, RequestDownload, TransferData, TransferExit, Checksum sequence
/// - Verify-dependencies and ECUReset at the end
#[tokio::test]
async fn test_simos1810_cal_flash_sequence() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_test_writer()
        .try_init();
    let fixture = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/simos1810_cal.can"
    ));

    let blocks = vec![synthetic_cal_block()];

    let opts = FlashOptions {
        interface: Interface::Fake(fixture),
        // Must match fixture line "T 7E0 2e f1 5a 20 04 20 42 04 20 42 b1 3d"
        workshop_code: [0x20, 0x04, 0x20, 0x42, 0x04, 0x20, 0x42, 0xB1, 0x3D],
        patch_cboot: false,
        stmin_override: None,
        progress_tx: None,
    };

    flash_blocks(&S1810_FLASH_INFO, blocks, opts)
        .await
        .expect("flash sequence should complete without error");
}
