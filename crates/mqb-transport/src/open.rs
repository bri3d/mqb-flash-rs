//! Opening an [`Interface`] as a long-lived raw CAN adapter.
//!
//! The flashing paths in `mqb-flash-uds` each open an interface, run one
//! operation and close it again. Some tools need the opposite: a connection
//! that stays up while several things share it. The immobilizer tool is the
//! clearest case — it polls UDS status DIDs *and* answers authentication frames
//! on CAN `0x010`/`0x011` at the same time, over one bus.
//!
//! That works because [`AsyncCanAdapter`] fans received frames out over a
//! broadcast channel: an `IsoTPAdapter` and a raw `recv_filter` stream can read
//! the same adapter concurrently without stealing frames from each other.
//!
//! # Why `j2534-isotp` is not here
//!
//! [`Interface::J2534`] with `native_isotp` opens an ISO 15765 channel, where
//! the adapter firmware owns the framing and only complete PDUs come back.
//! There are no raw CAN frames to see, so it cannot carry the authentication
//! protocol. [`open_can_adapter`] refuses it with an error that says so rather
//! than silently producing a connection that can never hear the ECU.

use std::path::Path;

use automotive::can::AsyncCanAdapter;

use crate::{FakeCanAdapter, Interface};

/// Why an interface could not be opened as a raw CAN adapter.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The device or fixture could not be opened.
    #[error("{0}")]
    Interface(String),

    /// This interface cannot provide raw CAN frames.
    #[error(
        "'{interface}' is a hardware ISO 15765 channel: the adapter firmware owns the framing, \
         so no raw CAN frames are visible. {needed_for} needs raw CAN — use 'j2534' (software \
         ISO-TP) instead of 'j2534-isotp'."
    )]
    NoRawCan {
        interface: String,
        needed_for: &'static str,
    },

    /// This interface is not a CAN bus at all.
    #[error(
        "'{interface}' is an Ethernet (DoIP) transport, not a CAN bus: the entity routes UDS to a \
         logical address and no raw frames exist. {needed_for} needs raw CAN."
    )]
    NotCan {
        interface: String,
        needed_for: &'static str,
    },

    /// Support for this interface was not compiled in.
    #[error("{0}")]
    NotCompiledIn(String),
}

/// Open an interface as a raw CAN adapter that stays up until it is dropped.
///
/// `needed_for` names the caller in the error a hardware-ISO-TP interface
/// produces, e.g. `"immobilizer master emulation"`.
///
/// Dropping the returned adapter closes the device. For J2534 that teardown
/// joins DLL threads and can block, so drop it on a blocking thread
/// (`tokio::task::spawn_blocking(move || drop(adapter))`) rather than on an
/// async executor.
pub fn open_can_adapter(
    interface: &Interface,
    needed_for: &'static str,
) -> Result<AsyncCanAdapter, OpenError> {
    match interface {
        Interface::Fake(path) => open_fake(path),
        Interface::SocketCan(name) => open_socketcan(name),
        Interface::Panda => open_panda(),
        Interface::J2534 {
            dll,
            bitrate,
            native_isotp,
        } => {
            if *native_isotp {
                return Err(OpenError::NoRawCan {
                    interface: interface.to_string(),
                    needed_for,
                });
            }
            open_j2534(dll.as_deref(), *bitrate)
        }
        Interface::DoIp { .. } => Err(OpenError::NotCan {
            interface: interface.to_string(),
            needed_for,
        }),
    }
}

/// Whether this interface can carry raw CAN frames at all.
///
/// Lets a UI grey out master emulation before the user tries it, rather than
/// failing at connect time.
pub fn supports_raw_can(interface: &Interface) -> bool {
    !matches!(
        interface,
        Interface::J2534 {
            native_isotp: true,
            ..
        } | Interface::DoIp { .. }
    )
}

fn open_fake(path: &Path) -> Result<AsyncCanAdapter, OpenError> {
    let fake = FakeCanAdapter::new(path)
        .map_err(|e| OpenError::Interface(format!("fixture {}: {e}", path.display())))?;
    Ok(AsyncCanAdapter::new(fake))
}

fn open_panda() -> Result<AsyncCanAdapter, OpenError> {
    use automotive::can::bitrate::BitrateBuilder;
    let config = BitrateBuilder::new::<automotive::panda::Panda>()
        .bitrate(500_000)
        .build()
        .map_err(|e| OpenError::Interface(format!("Panda bitrate config error: {e}")))?;
    let panda = automotive::panda::Panda::new(config)
        .map_err(|e| OpenError::Interface(format!("Panda open error: {e}")))?;
    Ok(AsyncCanAdapter::new(panda))
}

#[cfg(all(target_os = "linux", feature = "socketcan"))]
fn open_socketcan(name: &str) -> Result<AsyncCanAdapter, OpenError> {
    let sc = automotive::socketcan::SocketCan::new(name)
        .map_err(|e| OpenError::Interface(format!("SocketCAN open error: {e}")))?;
    Ok(AsyncCanAdapter::new(sc))
}

#[cfg(not(all(target_os = "linux", feature = "socketcan")))]
fn open_socketcan(_name: &str) -> Result<AsyncCanAdapter, OpenError> {
    Err(OpenError::NotCompiledIn(
        "SocketCAN support is not enabled. Recompile with \
         `--features mqb-transport/socketcan` on Linux."
            .into(),
    ))
}

#[cfg(feature = "j2534")]
fn open_j2534(dll: Option<&str>, bitrate: u32) -> Result<AsyncCanAdapter, OpenError> {
    use automotive::can::bitrate::BitrateBuilder;
    let config = BitrateBuilder::new::<automotive::j2534::J2534CanAdapter>()
        .bitrate(bitrate)
        .build()
        .map_err(|e| OpenError::Interface(format!("J2534 bitrate config error: {e}")))?;
    let j = automotive::j2534::J2534CanAdapter::new(dll, config)
        .map_err(|e| OpenError::Interface(format!("J2534 open error: {e}")))?;
    Ok(AsyncCanAdapter::new(j))
}

#[cfg(not(feature = "j2534"))]
fn open_j2534(_dll: Option<&str>, _bitrate: u32) -> Result<AsyncCanAdapter, OpenError> {
    Err(OpenError::NotCompiledIn(
        "J2534 support is not enabled. Recompile with `--features mqb-transport/j2534`.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_isotp_cannot_carry_raw_can() {
        let iface = Interface::J2534 {
            dll: None,
            bitrate: 500_000,
            native_isotp: true,
        };
        assert!(!supports_raw_can(&iface));

        let Err(err) = open_can_adapter(&iface, "immobilizer master emulation") else {
            panic!("a hardware ISO-TP channel must not open as a raw CAN adapter");
        };
        let message = err.to_string();
        assert!(
            message.contains("immobilizer master emulation"),
            "{message}"
        );
        assert!(message.contains("j2534-isotp"), "{message}");
    }

    #[test]
    fn doip_is_not_a_can_bus() {
        let iface = Interface::DoIp {
            host: "169.254.1.2".into(),
            port: 13400,
        };
        assert!(!supports_raw_can(&iface));

        let Err(err) = open_can_adapter(&iface, "immobilizer master emulation") else {
            panic!("an Ethernet transport must not open as a raw CAN adapter");
        };
        let message = err.to_string();
        assert!(message.contains("doip:169.254.1.2"), "{message}");
        assert!(message.contains("immobilizer master emulation"), "{message}");
    }

    #[test]
    fn the_other_interfaces_claim_raw_can() {
        for iface in [
            Interface::Panda,
            Interface::SocketCan("can0".into()),
            Interface::Fake("fixture.can".into()),
            Interface::J2534 {
                dll: None,
                bitrate: 500_000,
                native_isotp: false,
            },
        ] {
            assert!(supports_raw_can(&iface), "{iface} should offer raw CAN");
        }
    }

    /// A missing fixture must be a clean error naming the path, not a panic.
    #[test]
    fn a_missing_fixture_reports_its_path() {
        let iface = Interface::Fake("definitely-not-here.can".into());
        let Err(err) = open_can_adapter(&iface, "testing") else {
            panic!("a missing fixture must not open");
        };
        assert!(err.to_string().contains("definitely-not-here.can"));
    }
}
