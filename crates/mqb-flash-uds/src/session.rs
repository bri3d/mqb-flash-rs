//! One ECU connection, held open across several operations.
//!
//! Opening a physical interface is not free — a J2534 device in particular
//! spins up DLL threads and a hardware channel on open and joins them again on
//! close, which takes long enough to be visible in a UI. A wizard that scans,
//! then probes the unlock state, then reads the immobilizer status, then
//! flashes would pay that four times over, and the ECU sees four separate
//! sessions where it should see one.
//!
//! [`Session`] owns the connection instead. Every operation runs over the
//! already-open device, and the free functions in [`crate::flash`] are thin
//! wrappers that open a session, do one thing, and close it — so a caller that
//! only wants one operation still gets the old behaviour.
//!
//! # The two shapes a connection can take
//!
//! * **Raw CAN** ([`Interface::SocketCan`], [`Interface::Panda`],
//!   [`Interface::Fake`], and `j2534` without native ISO-TP). The session owns
//!   an [`AsyncCanAdapter`]; software ISO-TP is layered on top per operation.
//!   That wrapper is cheap, so each operation still gets exactly the ISO-TP
//!   configuration it wants — and because the adapter fans frames out over a
//!   broadcast channel, more than one reader can share it. That is what lets
//!   the immobilizer tool answer authentication frames while polling UDS.
//! * **Hardware ISO 15765** (`j2534-isotp`). The channel *is* the connection
//!   and its ID pair and timing are fixed when it opens, so the session holds
//!   the transport directly. There are no raw CAN frames to see, so
//!   [`Session::raw_can`] returns `None`.

use std::collections::HashMap;

use automotive::can::AsyncCanAdapter;
use automotive::isotp::{IsoTPAdapter, IsoTPConfig};

use mqb_modules::{FlashInfo, PreparedBlockData};
use mqb_transport::{open_can_adapter, Interface};

use crate::identify::{ChannelIdentification, IDENT_CHANNELS};

use crate::flash::{
    make_isotp_config_with_timeout, read_dids, read_ecu_with_transport, run_probe,
    run_with_transport, send_obd_dtc_clear_via_adapter, send_progress, write_did, FlashError,
    FlashOptions, ProbeKind, ProbeOutcome, ProgressUpdate, FLASH_TIMEOUT, IDENT_TIMEOUT,
};

// The hardware ISO 15765 path needs its own OBD-II channel; the raw-CAN path
// layers one over the adapter it already has.
#[cfg(feature = "j2534")]
use crate::flash::send_obd_dtc_clear;
#[cfg(feature = "j2534")]
use automotive::can::Identifier;

/// The OBD-II tester address used for the emission DTC clear.
#[cfg(feature = "j2534")]
const OBD_TESTER_ID: u32 = 0x700;
/// The OBD-II ECU address used for the emission DTC clear.
#[cfg(feature = "j2534")]
const OBD_ECU_ID: u32 = 0x7E8;

/// An open connection to an ECU.
///
/// Dropping it closes the device. Prefer [`Session::close`] inside an async
/// context: J2534 teardown joins DLL threads, and doing that on the executor
/// stalls every other task — in a GUI, that is a multi-second freeze. `Drop`
/// falls back to moving the teardown onto a blocking thread when a Tokio
/// runtime is available.
pub struct Session {
    interface: Interface,
    inner: Option<Inner>,
    /// The diagnostic ID pair this session was opened for.
    channel: (u32, u32),
    /// How long to wait for a response to a single request.
    ///
    /// Held on the session rather than chosen per operation because the
    /// hardware ISO 15765 path bakes it into the channel at open — see
    /// [`Session::open_for_identify`].
    timeout: std::time::Duration,
}

enum Inner {
    Can(AsyncCanAdapter),
    #[cfg(feature = "j2534")]
    Native(NativeChannel),
}

#[cfg(feature = "j2534")]
struct NativeChannel {
    transport: automotive::j2534::J2534NativeIsoTpTransport,
    /// Kept so the transient OBD-II channel can be opened on the same device.
    dll: Option<String>,
    bitrate: u32,
}

/// Run `body` over whatever transport this session has.
///
/// A macro rather than a method because [`automotive::TransportLayer`] has
/// `async fn`s and so is not object-safe: the two arms have different concrete
/// types and cannot be unified behind a `dyn`. Expanding inline keeps the
/// generic call sites monomorphised, exactly as the per-interface functions
/// this replaced did.
macro_rules! with_transport {
    ($session:expr, $config:expr, |$t:ident| $body:expr) => {{
        match $session.inner.as_ref().expect("session is open") {
            Inner::Can(adapter) => {
                let isotp = IsoTPAdapter::new(adapter, $config);
                let $t = &isotp;
                $body
            }
            #[cfg(feature = "j2534")]
            Inner::Native(native) => {
                let $t = &native.transport;
                $body
            }
        }
    }};
}

impl Session {
    /// Open a connection to `flash_info`'s diagnostic channel.
    ///
    /// `stmin_override` is only consumed by the hardware ISO 15765 path, where
    /// the channel's TX pacing is fixed at open. On the raw-CAN path each
    /// operation builds its own ISO-TP layer, so the flash sequence applies its
    /// own STmin there.
    pub fn open(
        interface: &Interface,
        flash_info: &FlashInfo,
        stmin_override: Option<u32>,
    ) -> Result<Self, FlashError> {
        Self::open_with(interface, flash_info, stmin_override, FLASH_TIMEOUT)
    }

    /// Open a connection for identifying what is on a channel.
    ///
    /// Same as [`Session::open`] but with [`IDENT_TIMEOUT`] instead of
    /// [`FLASH_TIMEOUT`], because a scan asks addresses that may have nothing
    /// behind them and must not spend half a minute finding that out.
    ///
    /// **Read-only probing only.** On the hardware ISO 15765 path the timeout
    /// is fixed when the channel opens and cannot be raised again afterwards,
    /// so a session opened this way must not be used to flash.
    pub fn open_for_identify(
        interface: &Interface,
        flash_info: &FlashInfo,
    ) -> Result<Self, FlashError> {
        Self::open_with(interface, flash_info, None, IDENT_TIMEOUT)
    }

    fn open_with(
        interface: &Interface,
        flash_info: &FlashInfo,
        stmin_override: Option<u32>,
        timeout: std::time::Duration,
    ) -> Result<Self, FlashError> {
        tracing::info!(interface = %interface, project = flash_info.project_name, "Opening session");

        // Only the hardware ISO 15765 path consumes this: there the channel's
        // TX pacing is fixed at open, so it has to be known now. Everywhere
        // else the flash sequence applies its own STmin per operation.
        #[cfg(not(feature = "j2534"))]
        let _ = stmin_override;

        let inner = match interface {
            #[cfg(feature = "j2534")]
            Interface::J2534 {
                dll,
                bitrate,
                native_isotp: true,
            } => {
                let mut config = make_isotp_config_with_timeout(flash_info, timeout);
                let stmin_us = stmin_override.unwrap_or(flash_info.default_stmin_us);
                config.separation_time_min =
                    Some(std::time::Duration::from_micros(stmin_us as u64));
                let transport = open_native_isotp(dll.as_deref(), *bitrate, config)?;
                Inner::Native(NativeChannel {
                    transport,
                    dll: dll.clone(),
                    bitrate: *bitrate,
                })
            }
            #[cfg(not(feature = "j2534"))]
            Interface::J2534 {
                native_isotp: true, ..
            } => {
                return Err(FlashError::Interface(
                    "J2534 support is not enabled. \
                     Recompile with `--features mqb-flash-uds/j2534`."
                        .into(),
                ))
            }
            other => Inner::Can(
                open_can_adapter(other, "this operation")
                    .map_err(|e| FlashError::Interface(e.to_string()))?,
            ),
        };

        Ok(Self {
            interface: interface.clone(),
            inner: Some(inner),
            channel: channel_ids(flash_info),
            timeout,
        })
    }

    /// The interface this session was opened on.
    pub fn interface(&self) -> &Interface {
        &self.interface
    }

    /// ISO-TP configuration for an operation on this session.
    ///
    /// Only consulted on the raw-CAN path, where the ISO-TP layer is rebuilt
    /// per operation; the hardware ISO 15765 channel already carries the
    /// timeout it was opened with.
    fn config(&self, flash_info: &FlashInfo) -> IsoTPConfig {
        make_isotp_config_with_timeout(flash_info, self.timeout)
    }

    /// Whether this session can talk to `flash_info`'s diagnostic channel.
    ///
    /// Always true on a raw-CAN connection: ISO-TP is layered per operation, so
    /// any ID pair can be addressed over the one adapter — which is what lets a
    /// bus scan walk every channel on a single open device.
    ///
    /// On a hardware ISO 15765 connection the ID pair is fixed when the channel
    /// opens, so only the channel it was opened for can be reached. Asking for
    /// another would silently talk to the wrong ECU, so the operations refuse
    /// instead.
    pub fn can_serve(&self, flash_info: &FlashInfo) -> bool {
        // `flash_info` only matters on the hardware ISO-TP path, where the
        // channel's addresses were fixed at open.
        #[cfg(not(feature = "j2534"))]
        let _ = flash_info;

        match self.inner.as_ref() {
            Some(Inner::Can(_)) => true,
            #[cfg(feature = "j2534")]
            Some(Inner::Native(_)) => self.channel == channel_ids(flash_info),
            None => false,
        }
    }

    fn require_channel(&self, flash_info: &FlashInfo) -> Result<(), FlashError> {
        if self.can_serve(flash_info) {
            return Ok(());
        }
        let (tx, rx) = channel_ids(flash_info);
        Err(FlashError::Interface(format!(
            "this session is bound to the ISO 15765 channel 0x{:03X}/0x{:03X} and cannot reach \
             0x{tx:03X}/0x{rx:03X}. A hardware ISO-TP channel's addresses are fixed when it \
             opens — open a session for that channel instead.",
            self.channel.0, self.channel.1
        )))
    }

    /// The underlying CAN adapter, when this connection carries raw frames.
    ///
    /// `None` on a hardware ISO 15765 channel, where the adapter firmware owns
    /// the framing and only whole PDUs are visible. Callers that need raw CAN —
    /// immobilizer master emulation is the one — must handle that.
    ///
    /// The adapter broadcasts received frames, so reading from it does not take
    /// frames away from UDS traffic on the same session.
    pub fn raw_can(&self) -> Option<&AsyncCanAdapter> {
        match self.inner.as_ref()? {
            Inner::Can(adapter) => Some(adapter),
            #[cfg(feature = "j2534")]
            Inner::Native(_) => None,
        }
    }

    /// Run one read-only probe against the ECU.
    pub async fn probe(
        &self,
        flash_info: &'static FlashInfo,
        what: ProbeKind,
    ) -> Result<ProbeOutcome, FlashError> {
        self.require_channel(flash_info)?;
        let config = self.config(flash_info);
        with_transport!(self, config, |t| run_probe(t, flash_info, what).await)
    }

    /// Read the standard data-record sweep.
    pub async fn read_ecu_data(
        &self,
        flash_info: &FlashInfo,
    ) -> Result<HashMap<String, String>, FlashError> {
        self.require_channel(flash_info)?;
        let config = self.config(flash_info);
        with_transport!(self, config, |t| read_ecu_with_transport(t).await)
    }

    /// Read a list of DIDs, in order, returning only the ones the ECU answered.
    ///
    /// Returns an empty map when the session cannot reach that channel — the
    /// same fail-open shape as a DID the ECU simply refuses.
    pub async fn read_dids(&self, flash_info: &FlashInfo, dids: &[u16]) -> HashMap<u16, Vec<u8>> {
        if let Err(e) = self.require_channel(flash_info) {
            tracing::warn!("read_dids: {e}");
            return HashMap::new();
        }
        let config = self.config(flash_info);
        with_transport!(self, config, |t| read_dids(t, dids).await)
    }

    /// Write one DID.
    ///
    /// No session or SecurityAccess is opened first: the immobilizer's two
    /// write DIDs (`0x2E1` login and `0x2E2` download) are dispatched by the
    /// ECU ahead of every session and security check, so the default session is
    /// where they belong.
    pub async fn write_did(
        &self,
        flash_info: &FlashInfo,
        did: u16,
        value: &[u8],
    ) -> Result<(), FlashError> {
        self.require_channel(flash_info)?;
        let config = self.config(flash_info);
        with_transport!(self, config, |t| write_did(t, did, value).await)
    }

    /// Send the OBD-II mode `0x04` emission DTC clear. Best effort.
    ///
    /// VW ECUs want this before the programming precondition check. It runs on
    /// the fixed OBD-II ID pair rather than the module's own channel, so on a
    /// hardware ISO 15765 connection it needs a second channel of its own — the
    /// one case where a device really does have to be reopened.
    pub async fn clear_obd_dtcs(&self) {
        match self.inner.as_ref().expect("session is open") {
            Inner::Can(adapter) => send_obd_dtc_clear_via_adapter(adapter).await,
            #[cfg(feature = "j2534")]
            Inner::Native(native) => {
                let config = IsoTPConfig::new_from_tx_rx(
                    0,
                    Identifier::Standard(OBD_TESTER_ID),
                    Identifier::Standard(OBD_ECU_ID),
                );
                match open_native_isotp(native.dll.as_deref(), native.bitrate, config) {
                    Ok(obd) => {
                        send_obd_dtc_clear(&obd).await;
                        // The flash channel is reopened right after this, so
                        // the OBD channel must be fully torn down first.
                        let _ = tokio::task::spawn_blocking(move || drop(obd)).await;
                    }
                    Err(e) => {
                        tracing::warn!("OBD DTC clear channel open failed: {e} (continuing)")
                    }
                }
            }
        }
    }

    /// Flash a set of prepared blocks.
    ///
    /// Blocks go out in the order given — no reordering happens here. For a
    /// normal flash, sort by block number; for unlock, use the unlock order.
    pub async fn flash_blocks(
        &self,
        flash_info: &FlashInfo,
        blocks: &[PreparedBlockData],
        opts: &FlashOptions,
    ) -> Result<(), FlashError> {
        self.require_channel(flash_info)?;
        send_progress(opts, ProgressUpdate::ClearingDtcs);
        self.clear_obd_dtcs().await;

        // Fall back to the module's own STmin, not a global constant: Simos
        // tolerates 400 µs, the transmission and AWD ECUs need 900 µs.
        let mut config = self.config(flash_info);
        let stmin_us = opts.stmin_override.unwrap_or(flash_info.default_stmin_us);
        config.separation_time_min = Some(std::time::Duration::from_micros(stmin_us as u64));

        let result = with_transport!(self, config, |t| {
            run_with_transport(t, flash_info, blocks, opts).await
        });

        // After the ECU reboots, clear emission DTCs again (best effort).
        if result.is_ok() {
            self.clear_obd_dtcs().await;
        }
        result
    }

    /// Close the connection, moving the teardown off the async executor.
    pub async fn close(mut self) {
        if let Some(inner) = self.inner.take() {
            let _ = tokio::task::spawn_blocking(move || drop(inner)).await;
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return; // Already closed explicitly.
        };
        // J2534 teardown joins DLL threads; never do that on the executor.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || drop(inner));
            }
            Err(_) => drop(inner),
        }
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("interface", &self.interface.to_string())
            .field("open", &self.inner.is_some())
            .field("raw_can", &self.raw_can().is_some())
            .finish()
    }
}

/// The diagnostic ID pair a module answers on.
fn channel_ids(flash_info: &FlashInfo) -> (u32, u32) {
    (
        flash_info.control_module_identifier.txid,
        flash_info.control_module_identifier.rxid,
    )
}

/// Whether one open session can serve every identification channel.
///
/// True exactly when the interface carries raw CAN: ISO-TP is then layered per
/// operation, so any ID pair can be addressed over the one device. A hardware
/// ISO 15765 channel fixes its addresses at open and can only ever serve the
/// channel it was opened for — the same split [`Session::can_serve`] reports.
///
/// Decided from the interface *before* anything is opened, and deliberately not
/// by opening a session and asking it. Answering it the second way costs a
/// whole J2534 device open and close on the native path for a session that is
/// then thrown away — and worse, races that teardown against the next open,
/// because [`Session`]'s `Drop` can only hand teardown to a blocking task it
/// cannot await. `PassThruOpen` landing while the previous device is still
/// closing is `ERR_DEVICE_IN_USE` on a good DLL and a crash on a bad one.
fn shares_one_session(interface: &Interface) -> bool {
    mqb_transport::supports_raw_can(interface)
}

/// What a bus scan is doing, reported as it happens.
///
/// A scan walks three channels and spends [`IDENT_TIMEOUT`] on each silent one,
/// so even a healthy sweep takes a couple of seconds and a scan against a bench
/// ECU takes longer. Without this the caller has nothing to show but a static
/// label, which is indistinguishable from a hang.
#[derive(Debug, Clone)]
pub enum ScanProgress {
    /// About to probe `channel`, the `index`-th of `total`.
    ChannelStarted {
        channel: &'static crate::identify::IdentChannel,
        index: usize,
        total: usize,
    },
    /// `channel` answered and was identified.
    ChannelAnswered {
        channel: &'static crate::identify::IdentChannel,
    },
    /// Nothing usable on `channel` — silent, refused, or the open failed.
    /// Expected on the channels whose module is not fitted.
    ChannelSilent {
        channel: &'static crate::identify::IdentChannel,
    },
}

/// Identify every ECU channel on the bus.
///
/// See [`identify_all_channels_with_progress`]; this reports no progress.
pub async fn identify_all_channels(interface: &Interface) -> Vec<ChannelIdentification> {
    identify_all_channels_with_progress(interface, |_| {}).await
}

/// Identify every ECU channel on the bus, reporting progress per channel.
///
/// On a raw-CAN interface this opens the device **once** and walks all the
/// channels over it — ISO-TP is layered per channel, so the addresses can
/// change without touching the hardware. On a hardware ISO 15765 interface the
/// channel's addresses are fixed at open, so there is no choice but to open one
/// per channel; that is what this does, and it is why a J2534 scan is slower
/// through `j2534-isotp` than through `j2534`.
///
/// Channels that do not answer are simply absent from the result; a probe that
/// errors is logged and skipped, because one silent channel says nothing about
/// the others.
///
/// `on_progress` is called from the scan's own task, before and after each
/// channel. Keep it cheap — a send on a channel, not work.
pub async fn identify_all_channels_with_progress(
    interface: &Interface,
    on_progress: impl Fn(ScanProgress),
) -> Vec<ChannelIdentification> {
    let mut found = Vec::new();
    let total = IDENT_CHANNELS.len();
    let shared = if shares_one_session(interface) {
        IDENT_CHANNELS
            .first()
            .and_then(|c| Session::open_for_identify(interface, c.probe_flash_info()).ok())
    } else {
        None
    };

    for (index, channel) in IDENT_CHANNELS.iter().enumerate() {
        on_progress(ScanProgress::ChannelStarted {
            channel,
            index,
            total,
        });
        let flash_info = channel.probe_flash_info();
        let outcome = match &shared {
            Some(session) => session.probe(flash_info, ProbeKind::Identify).await,
            None => match Session::open_for_identify(interface, flash_info) {
                Ok(session) => {
                    let outcome = session.probe(flash_info, ProbeKind::Identify).await;
                    session.close().await;
                    outcome
                }
                Err(e) => Err(e),
            },
        };
        match outcome {
            Ok(ProbeOutcome::Identify(Some(ident))) => {
                found.push(ident);
                on_progress(ScanProgress::ChannelAnswered { channel });
            }
            Ok(_) => on_progress(ScanProgress::ChannelSilent { channel }),
            Err(e) => {
                tracing::debug!(channel = channel.label, "probe failed: {e}");
                on_progress(ScanProgress::ChannelSilent { channel });
            }
        }
    }

    if let Some(session) = shared {
        session.close().await;
    }
    found
}

#[cfg(feature = "j2534")]
fn open_native_isotp(
    dll: Option<&str>,
    bitrate: u32,
    config: IsoTPConfig,
) -> Result<automotive::j2534::J2534NativeIsoTpTransport, FlashError> {
    let bitrate_cfg =
        automotive::can::bitrate::BitrateBuilder::new::<automotive::j2534::J2534CanAdapter>()
            .bitrate(bitrate)
            .build()
            .map_err(|e| FlashError::Interface(format!("J2534 bitrate config error: {e}")))?;
    automotive::j2534::J2534NativeIsoTpTransport::new(dll, bitrate_cfg, config)
        .map_err(|e| FlashError::Interface(format!("J2534 ISO15765 open error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mqb_modules::modules::simos18::S18_FLASH_INFO;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    /// One session, several operations: the point of the type. A fixture-backed
    /// adapter stands in for a device, and the ISO-TP layer is rebuilt per
    /// operation over the same adapter.
    #[tokio::test]
    async fn a_fake_session_answers_more_than_one_operation() {
        let path = fixture("read_ecu_simos18.can");
        if !path.exists() {
            eprintln!("skipping: {} is not present", path.display());
            return;
        }
        let session = Session::open(&Interface::Fake(path), &S18_FLASH_INFO, None).unwrap();
        assert!(
            session.raw_can().is_some(),
            "a fixture connection must expose raw CAN"
        );
        assert!(session.read_ecu_data(&S18_FLASH_INFO).await.is_ok());
        session.close().await;
    }

    /// A scan must not inherit the flash sequence's 30 s response timeout: two
    /// of the three channels are normally silent, and waiting `FLASH_TIMEOUT`
    /// on each is a minute of dead time that reads as a hang.
    #[tokio::test]
    async fn identifying_waits_far_less_than_flashing() {
        let path = fixture("read_ecu_simos18.can");
        if !path.exists() {
            eprintln!("skipping: {} is not present", path.display());
            return;
        }
        let iface = Interface::Fake(path);

        let flashing = Session::open(&iface, &S18_FLASH_INFO, None).unwrap();
        assert_eq!(flashing.config(&S18_FLASH_INFO).timeout, FLASH_TIMEOUT);
        flashing.close().await;

        let identifying = Session::open_for_identify(&iface, &S18_FLASH_INFO).unwrap();
        assert_eq!(identifying.config(&S18_FLASH_INFO).timeout, IDENT_TIMEOUT);
        identifying.close().await;

        assert!(
            IDENT_TIMEOUT < FLASH_TIMEOUT,
            "a probe of a possibly-empty address must give up sooner than a flash"
        );
    }

    /// `shares_one_session` has to agree with what `can_serve` would have said
    /// about an opened session, because it replaced exactly that check. If the
    /// two drift apart the scan either loses the shared-session optimisation or
    /// starts opening a device it throws away again.
    #[tokio::test]
    async fn sharing_one_session_predicts_what_can_serve_would_answer() {
        let path = fixture("read_ecu_simos18.can");
        if !path.exists() {
            eprintln!("skipping: {} is not present", path.display());
            return;
        }
        let iface = Interface::Fake(path);
        assert!(shares_one_session(&iface), "a fixture carries raw CAN");

        let session = Session::open_for_identify(&iface, &S18_FLASH_INFO).unwrap();
        assert!(
            IDENT_CHANNELS
                .iter()
                .all(|c| session.can_serve(c.probe_flash_info())),
            "the predicate promised one session reaches every channel"
        );
        session.close().await;
    }

    /// The native ISO 15765 path must never be asked to open a speculative
    /// session: its channel is bound to one ID pair, so the session would be
    /// discarded, and `Drop` cannot await the J2534 teardown it starts — the
    /// next `PassThruOpen` would race a device that is still closing.
    #[test]
    fn a_hardware_isotp_interface_never_opens_a_shared_session() {
        assert!(!shares_one_session(&Interface::J2534 {
            dll: None,
            bitrate: 500_000,
            native_isotp: true,
        }));
        // The raw-CAN J2534 channel is a different story and still shares.
        assert!(shares_one_session(&Interface::J2534 {
            dll: None,
            bitrate: 500_000,
            native_isotp: false,
        }));
    }

    /// A hardware ISO 15765 connection has no raw CAN to offer, and callers
    /// that need it must be able to find that out.
    #[test]
    fn raw_can_is_absent_on_a_hardware_isotp_interface() {
        let iface = Interface::J2534 {
            dll: None,
            bitrate: 500_000,
            native_isotp: true,
        };
        assert!(!mqb_transport::supports_raw_can(&iface));
    }
}
