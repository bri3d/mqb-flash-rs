//! Transport interface selection.

use std::path::PathBuf;

/// Which physical interface to use for CAN/ISO-TP communication.
#[derive(Debug, Clone)]
pub enum Interface {
    /// Linux SocketCAN interface (e.g. `can0`).
    SocketCan(String),
    /// comma.ai Panda USB dongle.
    Panda,
    /// SAE J2534 PassThru device (Windows).
    ///
    /// `dll` — path to the PassThru DLL, or `None` to auto-discover via the
    /// Windows registry (`SOFTWARE\PassThruSupport.04.04`).
    ///
    /// `bitrate` — CAN bus bitrate in bits/sec.  Most VW/Audi OBD-II ports
    /// use 500 000 bps.
    ///
    /// `native_isotp` — when `true`, open an ISO 15765 channel (protocol 6)
    /// and let the adapter firmware handle all ISO-TP framing, flow-control
    /// timing, and STmin.  The CLI prefix for this mode is `j2534-isotp`.
    /// When `false` (default, prefix `j2534`), a raw CAN channel is opened
    /// and ISO-TP is emulated in software by the `automotive` crate.
    J2534 {
        dll: Option<String>,
        bitrate: u32,
        native_isotp: bool,
    },
    /// Fixture-driven fake interface for testing.  Path must point to a `.can`
    /// fixture file.  Use `fake:<path>` on the command line.
    Fake(PathBuf),
}

impl std::fmt::Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interface::SocketCan(ifname) => write!(f, "socketcan:{ifname}"),
            Interface::Panda => write!(f, "panda"),
            Interface::J2534 { dll: None, bitrate: 500_000, native_isotp } => {
                write!(f, "{}", if *native_isotp { "j2534-isotp" } else { "j2534" })
            }
            Interface::J2534 { dll: Some(path), bitrate: 500_000, native_isotp } => {
                write!(f, "{}:{path}", if *native_isotp { "j2534-isotp" } else { "j2534" })
            }
            Interface::J2534 { dll: None, bitrate, native_isotp } => {
                write!(f, "{}::{bitrate}", if *native_isotp { "j2534-isotp" } else { "j2534" })
            }
            Interface::J2534 { dll: Some(path), bitrate, native_isotp } => {
                write!(f, "{}:{path}:{bitrate}", if *native_isotp { "j2534-isotp" } else { "j2534" })
            }
            Interface::Fake(p) => write!(f, "fake:{}", p.display()),
        }
    }
}

impl std::str::FromStr for Interface {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(ifname) = s.strip_prefix("socketcan:") {
            return Ok(Interface::SocketCan(ifname.to_owned()));
        }
        if let Some(path_str) = s.strip_prefix("fake:") {
            return Ok(Interface::Fake(PathBuf::from(path_str)));
        }
        if let Some(rest) = s.strip_prefix("j2534-isotp") {
            return parse_j2534(rest, true);
        }
        if let Some(rest) = s.strip_prefix("j2534") {
            return parse_j2534(rest, false);
        }
        match s {
            "panda" => Ok(Interface::Panda),
            other => Err(format!(
                "Unknown interface: '{other}'. \
                 Use 'socketcan:<ifname>', 'panda', \
                 'j2534[:<dll>][:<bitrate>]' (software ISO-TP), \
                 'j2534-isotp[:<dll>][:<bitrate>]' (hardware ISO 15765), \
                 or 'fake:<fixture.can>'"
            )),
        }
    }
}

/// Parse the suffix after the `"j2534"` or `"j2534-isotp"` prefix.
///
/// Accepted forms:
/// * `""` — auto-discover DLL, 500 kbps
/// * `":<dll_path>"` — specific DLL, 500 kbps
/// * `"::<bitrate>"` — auto-discover DLL, custom bitrate
/// * `":<dll_path>:<bitrate>"` — specific DLL, custom bitrate
fn parse_j2534(rest: &str, native_isotp: bool) -> Result<Interface, String> {
    if rest.is_empty() {
        return Ok(Interface::J2534 { dll: None, bitrate: 500_000, native_isotp });
    }
    let rest = rest.strip_prefix(':').ok_or_else(|| {
        "j2534 interface must be 'j2534[:<dll>][:<bitrate>]' or 'j2534-isotp[:<dll>][:<bitrate>]'"
            .to_owned()
    })?;

    // Split on the last ':' so Windows paths like "C:\foo\bar.dll:250000" work.
    // A bare bitrate after '::' (empty dll) is also handled.
    if rest.is_empty() {
        return Ok(Interface::J2534 { dll: None, bitrate: 500_000, native_isotp });
    }

    // Check if the last colon-separated segment is a pure number (bitrate).
    if let Some(colon_pos) = rest.rfind(':') {
        let maybe_rate = &rest[colon_pos + 1..];
        if let Ok(rate) = maybe_rate.parse::<u32>() {
            let dll_part = &rest[..colon_pos];
            let dll = if dll_part.is_empty() { None } else { Some(dll_part.to_owned()) };
            return Ok(Interface::J2534 { dll, bitrate: rate, native_isotp });
        }
    }

    // No trailing bitrate — treat the whole rest as the DLL path.
    Ok(Interface::J2534 {
        dll: Some(rest.to_owned()),
        bitrate: 500_000,
        native_isotp,
    })
}
