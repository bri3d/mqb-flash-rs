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
    /// DoIP (ISO 13400-2) entity over Ethernet, `doip:<host>[:<port>]`.
    ///
    /// Not a CAN interface: the entity routes UDS to a logical ECU address, so
    /// there is no bus to see raw frames on.  `host` is usually the gateway's
    /// link-local address, discovered over UDP.
    DoIp { host: String, port: u16 },
}

/// Registered DoIP port (ISO 13400-2), TCP and UDP.
pub const DOIP_PORT: u16 = 13400;

impl std::fmt::Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Interface::SocketCan(ifname) => write!(f, "socketcan:{ifname}"),
            Interface::Panda => write!(f, "panda"),
            Interface::J2534 {
                dll,
                bitrate,
                native_isotp,
            } => {
                let prefix = if *native_isotp {
                    "j2534-isotp"
                } else {
                    "j2534"
                };
                match (dll, bitrate) {
                    (None, 500_000) => write!(f, "{prefix}"),
                    (Some(path), 500_000) => write!(f, "{prefix}:{path}"),
                    (None, br) => write!(f, "{prefix}::{br}"),
                    (Some(path), br) => write!(f, "{prefix}:{path}:{br}"),
                }
            }
            Interface::Fake(p) => write!(f, "fake:{}", p.display()),
            Interface::DoIp { host, port } if *port == DOIP_PORT => write!(f, "doip:{host}"),
            Interface::DoIp { host, port } => write!(f, "doip:{host}:{port}"),
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
        if let Some(rest) = s.strip_prefix("doip:") {
            return parse_doip(rest);
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
                 'doip:<host>[:<port>]' (Ethernet), \
                 or 'fake:<fixture.can>'"
            )),
        }
    }
}

/// Parse the suffix after `"doip:"` — `<host>` or `<host>:<port>`.
fn parse_doip(rest: &str) -> Result<Interface, String> {
    if rest.is_empty() {
        return Err("doip interface must be 'doip:<host>[:<port>]'".to_owned());
    }
    // Only a trailing numeric segment is a port; anything else is part of the
    // host, so a bare IPv6 literal stays intact.
    if let Some((host, maybe_port)) = rest.rsplit_once(':') {
        if let Ok(port) = maybe_port.parse::<u16>() {
            if host.is_empty() {
                return Err("doip interface must be 'doip:<host>[:<port>]'".to_owned());
            }
            return Ok(Interface::DoIp { host: host.to_owned(), port });
        }
    }
    Ok(Interface::DoIp { host: rest.to_owned(), port: DOIP_PORT })
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
        return Ok(Interface::J2534 {
            dll: None,
            bitrate: 500_000,
            native_isotp,
        });
    }
    let rest = rest.strip_prefix(':').ok_or_else(|| {
        "j2534 interface must be 'j2534[:<dll>][:<bitrate>]' or 'j2534-isotp[:<dll>][:<bitrate>]'"
            .to_owned()
    })?;

    // Split on the last ':' so Windows paths like "C:\foo\bar.dll:250000" work.
    // A bare bitrate after '::' (empty dll) is also handled.
    if rest.is_empty() {
        return Ok(Interface::J2534 {
            dll: None,
            bitrate: 500_000,
            native_isotp,
        });
    }

    // Check if the last colon-separated segment is a pure number (bitrate).
    if let Some(colon_pos) = rest.rfind(':') {
        let maybe_rate = &rest[colon_pos + 1..];
        if let Ok(rate) = maybe_rate.parse::<u32>() {
            let dll_part = &rest[..colon_pos];
            let dll = if dll_part.is_empty() {
                None
            } else {
                Some(dll_part.to_owned())
            };
            return Ok(Interface::J2534 {
                dll,
                bitrate: rate,
                native_isotp,
            });
        }
    }

    // No trailing bitrate — treat the whole rest as the DLL path.
    Ok(Interface::J2534 {
        dll: Some(rest.to_owned()),
        bitrate: 500_000,
        native_isotp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Interface {
        s.parse().unwrap()
    }

    #[test]
    fn doip_round_trips() {
        for s in ["doip:169.254.1.2", "doip:192.168.0.10:13401", "doip:gateway.local"] {
            assert_eq!(parse(s).to_string(), s);
        }
    }

    #[test]
    fn the_default_doip_port_is_implicit() {
        let Interface::DoIp { host, port } = parse("doip:169.254.1.2") else {
            panic!("doip: must parse as DoIp");
        };
        assert_eq!(host, "169.254.1.2");
        assert_eq!(port, DOIP_PORT);
    }

    /// A bare IPv6 literal is all host: only a numeric tail is a port.
    #[test]
    fn an_ipv6_host_keeps_its_colons() {
        let Interface::DoIp { host, port } = parse("doip:fe80::1%eth0") else {
            panic!("an IPv6 host must parse as DoIp");
        };
        assert_eq!(host, "fe80::1%eth0");
        assert_eq!(port, DOIP_PORT);
    }

    #[test]
    fn doip_needs_a_host() {
        assert!("doip:".parse::<Interface>().is_err());
        assert!("doip::13400".parse::<Interface>().is_err());
    }
}
