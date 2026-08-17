//! CAN/ISO-TP transport selection.
//!
//! This crate holds the transport-layer pieces shared by the flashing tool and
//! the diagnostics tool, with no dependency on flashing logic (no LZSS, no
//! SA2, no ECU flash configs):
//!
//! * [`Interface`] — selects the physical CAN interface (SocketCAN, Panda,
//!   J2534, or a fixture-driven fake) and parses/formats the CLI string form.
//! * [`FakeCanAdapter`] — a fixture-driven `CanAdapter` for tests.
//! * [`open_can_adapter`] — opens an interface as a long-lived raw CAN adapter,
//!   for tools that keep one connection up and share it between several users.

pub mod fake_adapter;
pub mod interface;
pub mod open;

pub use fake_adapter::FakeCanAdapter;
pub use interface::Interface;
pub use open::{open_can_adapter, supports_raw_can, OpenError};
