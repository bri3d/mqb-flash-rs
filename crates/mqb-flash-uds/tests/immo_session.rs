//! End-to-end tests of the immobilizer plumbing the standalone tool is built
//! on: one [`Session`], the full DID read, the assessment, and a download.
//!
//! The ECU is a fixture rather than hardware, so this exercises the real
//! ISO-TP, UDS and DID-decoding path without a bench.

use std::path::PathBuf;

use mqb_flash_uds::Session;
use mqb_immo::adapt::{adapt_plan, pclass_plan, snapshot_key_proof, PreflightExt};
use mqb_immo::diag::identity_checksum;
use mqb_immo::state::{
    decode_2ed, decode_2ee, decode_2ff, ImmoSnapshot, ImmoSupport, DID_STATE, DID_STATUS_BITS,
    IMMO_DIDS_FULL,
};
use mqb_immo::{adapt_preflight, assess, ImmoSecrets, ImmoState, Severity, DID_DOWNLOAD};
use mqb_modules::modules::simos18::S18_FLASH_INFO;
use mqb_nvcrypt::StStatFct;
use mqb_transport::Interface;

fn fixture() -> Interface {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "simos18_immo.can"]
        .iter()
        .collect();
    Interface::Fake(path)
}

fn open() -> Session {
    Session::open(&fixture(), &S18_FLASH_INFO, None).expect("the fixture opens")
}

/// The reference record's key, which the fixture's DID 0x2F9 is signed with.
const NO_KEY_SECU: [u8; 16] = [
    0x59, 0x67, 0xF8, 0xFB, 0xF7, 0xAF, 0x63, 0x4F, 0x17, 0xCF, 0x78, 0x65, 0xF1, 0x83, 0x24, 0xC3,
];

fn secrets(key: [u8; 16], vin: &str, idx_tun: u8) -> ImmoSecrets {
    ImmoSecrets {
        no_key_secu: key,
        no_key_mst: 0x2735,
        idx_tun,
        vin: vin.into(),
        ct_dat_bas_fazit: 0x01,
        st_stat_fct: StStatFct::Adapted,
        b_auth_mute: false,
        b_vld_chk_di: false,
        b_trig_fct_di: false,
        b_lim_mod_ena: false,
        b_lock: false,
        b_inh_acs_mem: false,
        channel: Some(6),
    }
}

async fn read_snapshot(session: &Session) -> ImmoSnapshot {
    let support = ImmoSupport::for_module(&S18_FLASH_INFO).expect("Simos18 is covered");
    let dids = session.read_dids(&S18_FLASH_INFO, &IMMO_DIDS_FULL).await;
    ImmoSnapshot::from_dids(support, dids)
}

/// One session answers the whole DID sweep, and the decoders agree with the
/// layouts the fixture was built from.
#[tokio::test]
async fn one_session_reads_the_whole_immobilizer_state() {
    let session = open();
    let snapshot = read_snapshot(&session).await;

    // Every DID in the list came back.
    for did in IMMO_DIDS_FULL {
        assert!(
            snapshot.raw(did).is_some(),
            "DID {did:#06X} was not answered"
        );
    }

    let adapt = decode_2ed(snapshot.raw(DID_STATE).unwrap()).unwrap();
    assert_eq!(adapt.st_stat_fct, 2);
    assert_eq!(adapt.ct_dat_bas_fazit, 1);
    assert_eq!(adapt.idx_lab, 0x0D);
    assert!(!adapt.b_lim_mod_ena);

    let bits = decode_2ee(snapshot.raw(DID_STATUS_BITS).unwrap()).unwrap();
    assert!(bits.ignition_on);
    assert!(bits.b_mst_cks_vld && bits.b_mst_key_vld);
    assert!(!bits.b_inh_acs_mem);

    let ext = decode_2ff(snapshot.raw(mqb_immo::state::DID_EXTENDED).unwrap()).unwrap();
    assert_eq!(ext.idx_tun, 0x6A);
    assert_eq!(ext.str_var_tun, [0x6A, 0, 0, 0, 0]);
    assert_eq!(ext.version_string(), "8.2.0");
    assert_eq!(ext.last_error, 0);

    assert_eq!(snapshot.vin().as_deref(), Some("3VW4T7AU6GM041367"));
    assert_eq!(snapshot.challenge(), Some([0x11, 0x22, 0x33, 0x44]));

    session.close().await;
}

/// A healthy ECU must assess as healthy — no risks, and the reported state of
/// 2 confirmed rather than assumed.
#[tokio::test]
async fn a_healthy_ecu_assesses_clean() {
    let session = open();
    let report = assess(&read_snapshot(&session).await);

    assert_eq!(report.severity, Severity::Ok, "{:#?}", report.findings);
    assert!(!report.has_risk());
    assert_eq!(report.reported_state, Some(2));
    assert_eq!(report.state, Some(ImmoState::Adapted));

    session.close().await;
}

/// The fixture's DID 0x2F9 really is the signature of what it reported, so the
/// key proof accepts the right key and rejects a wrong one. This is the check
/// that stands between a typo and the wrong-attempt lockout ladder.
#[tokio::test]
async fn the_identity_checksum_proves_the_key() {
    let session = open();
    let snapshot = read_snapshot(&session).await;

    // Recompute it independently, to catch the fixture drifting from the code.
    let expected = identity_checksum(
        &NO_KEY_SECU,
        snapshot.raw(mqb_immo::state::DID_FAZIT).unwrap(),
        snapshot.raw(mqb_immo::state::DID_VIN).unwrap(),
        snapshot.raw(DID_STATE).unwrap(),
        snapshot.raw(DID_STATUS_BITS).unwrap(),
        &snapshot.challenge().unwrap(),
    )
    .unwrap();
    assert_eq!(
        snapshot.identity_checksum().unwrap(),
        expected,
        "the fixture's 0x2F9 must be the real signature of what it reports"
    );

    assert_eq!(snapshot_key_proof(&snapshot, &NO_KEY_SECU), Some(true));
    assert_eq!(snapshot_key_proof(&snapshot, &[0u8; 16]), Some(false));

    session.close().await;
}

/// A PClass change to a value the ECU allows: the plan builds, preflight finds
/// no blockers, and the ECU accepts the write.
#[tokio::test]
async fn a_power_class_change_passes_preflight_and_is_accepted() {
    let session = open();
    let snapshot = read_snapshot(&session).await;
    let target = secrets(NO_KEY_SECU, "3VW4T7AU6GM041367", 0x6A);

    let plan = pclass_plan(&target, 0x6A).expect("the plan builds");
    assert_eq!(plan.encrypted_under, NO_KEY_SECU);
    assert!(plan.same_ecu);

    let items = adapt_preflight(&plan, &snapshot, &target, None, true);
    assert!(
        !items.is_blocked(),
        "unexpected blockers: {:#?}",
        items.blockers()
    );
    // Writing the value the ECU already holds is a warning, not a blocker: it
    // costs a relearn for nothing.
    assert!(items
        .iter()
        .any(|i| i.message.contains("already reports idxTun")));
    // And the relearn consequence is always stated.
    assert!(items
        .iter()
        .any(|i| i.message.contains("adaptation mode (stStatFct 4)")));

    session
        .write_did(&S18_FLASH_INFO, DID_DOWNLOAD, &plan.payload)
        .await
        .expect("the ECU accepts the download");

    session.close().await;
}

/// The interlock that fails silently on the ECU has to fail loudly here: an
/// idxTun outside the allow-list would be accepted by the download service and
/// leave a car that cranks but will not run.
#[tokio::test]
async fn an_idx_tun_outside_the_allow_list_is_blocked() {
    let session = open();
    let snapshot = read_snapshot(&session).await;
    let target = secrets(NO_KEY_SECU, "3VW4T7AU6GM041367", 0x6A);

    let plan = pclass_plan(&target, 0x88).expect("the plan builds");
    let items = adapt_preflight(&plan, &snapshot, &target, None, true);

    let blockers = items.blockers();
    assert!(
        blockers
            .iter()
            .any(|i| i.message.contains("not in this ECU's allow-list")),
        "expected the tuning interlock to block: {items:#?}"
    );

    session.close().await;
}

/// A transplant whose target key is not the one the ECU holds must be blocked
/// before any bytes go out — a wrong key fails the record CRC and arms the
/// download lockout ladder.
#[tokio::test]
async fn a_wrong_target_key_is_blocked() {
    let session = open();
    let snapshot = read_snapshot(&session).await;

    let wrong_target = secrets([0xAB; 16], "3VW4T7AU6GM041367", 0x6A);
    let donor = secrets([0xCD; 16], "WVWZZZ1KZAW000001", 0x6A);
    let plan = adapt_plan(&wrong_target, &donor, None, None).expect("the plan builds");

    let items = adapt_preflight(&plan, &snapshot, &wrong_target, Some(0x0D), false);
    assert!(items
        .blockers()
        .iter()
        .any(|i| i.message.contains("does not match the target dump")));

    session.close().await;
}

/// The session stays open across many operations — the whole point of it, and
/// what lets the tool poll while emulating a master.
#[tokio::test]
async fn a_session_serves_repeated_reads() {
    let session = open();
    for _ in 0..5 {
        let snapshot = read_snapshot(&session).await;
        assert_eq!(snapshot.vin().as_deref(), Some("3VW4T7AU6GM041367"));
    }
    // A fixture-backed connection is raw CAN, so master emulation would be
    // possible on it.
    assert!(session.raw_can().is_some());
    session.close().await;
}
