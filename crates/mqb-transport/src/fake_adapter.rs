//! Fixture-based fake CAN adapter for offline testing.
//!
//! # Fixture file format (`.can`)
//!
//! Plain-text, one line per UDS message.  ISO-TP framing is handled
//! internally — fixture entries contain raw **UDS PDU bytes** only
//! (no ISO-TP length or SN header bytes).
//!
//! ```text
//! # comment lines start with '#'
//! # T = tester→ECU (UDS message we send)
//! # R = ECU→tester (UDS message we receive back)
//! # <dir> <11-bit-id-hex> <uds-bytes-hex-space-separated>
//! T 7E0 10 03
//! R 7E8 50 03 00 32 01 f4
//! T 7E0 22 f1 90
//! R 7E8 62 f1 90 57 56 57 55 46 37 41 55 32 47 57 39 38 37 36 35 30
//! ```
//!
//! ## Multi-frame messages
//!
//! Both tester TX and ECU RX messages may be longer than 7 bytes.
//! The adapter performs ISO-TP reassembly on incoming tester CAN frames,
//! matching the completed UDS PDU against the next T-line.  Outgoing
//! R-line UDS PDUs are automatically fragmented into ISO-TP CAN frames
//! (First Frame + Consecutive Frames) before being placed in the receive
//! queue.
//!
//! ## TransferData (SID 0x36)
//!
//! Any complete incoming `0x36` (TransferData) message automatically
//! elicits a `76 <counter>` positive response **without** a fixture
//! entry.  This avoids embedding large flash data blobs in fixtures.
//!
//! ## Ordered vs. interactive mode
//!
//! By default the adapter runs in **ordered** mode: the fixture is a
//! script, and each incoming UDS PDU must match the next pending T-line in
//! sequence.  This is exactly what a deterministic flash sequence needs.
//!
//! A fixture whose comment header contains the directive
//!
//! ```text
//! # mode: interactive
//! ```
//!
//! is instead loaded in **interactive** mode.  Here the T/R pairs become a
//! request-keyed lookup table: any incoming request is answered with its
//! mapped R-lines regardless of order, so a GUI can be clicked through
//! non-deterministically.  Requests with no fixture entry are answered by
//! generic per-service synthetic handlers (session control, tester
//! present, clear-DTC, write, IO-control, routine start/stop, security
//! access), falling back to NRC `0x31` (requestOutOfRange) for anything
//! still unknown.

use std::collections::{HashMap, VecDeque};
use std::path::Path;

use automotive::can::{CanAdapter, Frame, Identifier};

use mqb_isotp::{fragment, Reassembler};

// ── Fixture entry ─────────────────────────────────────────────────────────────

struct FixtureEntry {
    direction: Direction,
    id: u32,
    /// Raw UDS PDU bytes (no ISO-TP framing).
    uds: Vec<u8>,
}

#[derive(PartialEq)]
enum Direction {
    Tx,
    Rx,
}

/// How the adapter resolves an incoming request into a response.
enum Responder {
    /// Sequential script — each request must match the next pending T-line.
    Ordered(VecDeque<FixtureEntry>),
    /// Request-keyed lookup — `request UDS bytes → list of response UDS PDUs`.
    Interactive(HashMap<Vec<u8>, Vec<Vec<u8>>>),
}

// ── FakeCanAdapter ────────────────────────────────────────────────────────────

/// A blocking [`CanAdapter`] that replays a `.can` fixture file.
///
/// Fixture entries use raw UDS PDU bytes; ISO-TP fragmentation and
/// reassembly are handled internally.
pub struct FakeCanAdapter {
    responder: Responder,
    rx_queue: VecDeque<Frame>,
    /// CAN ID used for ECU→tester frames we fabricate (FC, auto-responses).
    ecu_tx_id: u32,
    /// ISO-TP reassembly state for an ongoing multi-frame tester message.
    isotp_pending: Option<Reassembler>,
}

impl FakeCanAdapter {
    /// Build a new adapter from a `.can` fixture file.
    pub fn new(fixture_path: &Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(fixture_path)?;
        let (interactive, entries) = parse_fixture(&content);
        let ecu_tx_id = entries
            .iter()
            .find(|e| e.direction == Direction::Rx)
            .map(|e| e.id)
            .unwrap_or(0x7E8);

        let responder = if interactive {
            Responder::Interactive(build_response_map(entries))
        } else {
            Responder::Ordered(VecDeque::from(entries))
        };

        Ok(Self {
            responder,
            rx_queue: VecDeque::new(),
            ecu_tx_id,
            isotp_pending: None,
        })
    }

    /// Fragment `uds` into ISO-TP CAN frames and push them onto `rx_queue`.
    fn enqueue_uds_response(&mut self, uds: &[u8]) {
        for frame in fragment(uds, self.ecu_tx_id) {
            self.rx_queue.push_back(frame);
        }
    }

    /// Called when a complete incoming UDS PDU has been reassembled.
    ///
    /// * SID 0x36 (TransferData) → auto-respond with `76 <counter>`.
    /// * Ordered mode → advance the fixture and enqueue R-frames.
    /// * Interactive mode → keyed lookup, then a synthetic per-service
    ///   response, then NRC `0x31` for anything unknown.
    fn handle_complete_uds(&mut self, uds: &[u8]) {
        let sid = uds.first().copied().unwrap_or(0);

        if sid == 0x36 {
            let counter = uds.get(1).copied().unwrap_or(0);
            tracing::trace!(
                "FakeCanAdapter: auto-responding to TransferData counter=0x{counter:02X}"
            );
            self.enqueue_uds_response(&[0x76, counter]);
            return;
        }

        // Resolve the response PDUs first so no borrow of `self.responder`
        // is held across the `enqueue_uds_response` calls below.
        let responses: Vec<Vec<u8>> = match &mut self.responder {
            Responder::Ordered(fixture) => {
                let mut out = Vec::new();
                match fixture.front() {
                    Some(expected)
                        if expected.direction == Direction::Tx && expected.uds == uds =>
                    {
                        fixture.pop_front();
                        // Drain all immediately-following R-entries.
                        while matches!(fixture.front(), Some(e) if e.direction == Direction::Rx) {
                            out.push(fixture.pop_front().expect("front was Some").uds);
                        }
                    }
                    Some(expected) => {
                        tracing::warn!(
                            "FakeCanAdapter: unexpected UDS (got {:02X?}, expected {:02X?})",
                            uds,
                            expected.uds,
                        );
                    }
                    None => {
                        tracing::warn!(
                            "FakeCanAdapter: fixture exhausted, no entry for {:02X?}",
                            uds,
                        );
                    }
                }
                out
            }
            Responder::Interactive(map) => match map.get(uds) {
                Some(r) if !r.is_empty() => r.clone(),
                _ => vec![synth_uds_response(uds)],
            },
        };

        for r in responses {
            self.enqueue_uds_response(&r);
        }
    }
}

/// Build the request-keyed response table for interactive mode.
///
/// Each `T` line opens a new request; every `R` line that follows it (until
/// the next `T`) is one of that request's responses.
fn build_response_map(entries: Vec<FixtureEntry>) -> HashMap<Vec<u8>, Vec<Vec<u8>>> {
    let mut map: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
    let mut current: Option<Vec<u8>> = None;
    for e in entries {
        match e.direction {
            Direction::Tx => {
                map.insert(e.uds.clone(), Vec::new());
                current = Some(e.uds);
            }
            Direction::Rx => {
                if let Some(req) = current.as_ref() {
                    if let Some(slot) = map.get_mut(req) {
                        slot.push(e.uds);
                    }
                }
            }
        }
    }
    map
}

/// Synthesize a generic positive (or negative) response for a request that
/// has no explicit fixture entry — used only in interactive mode.
///
/// These cover the services whose response is a fixed echo of the request
/// (so a generator need not enumerate every possible payload): session
/// control, tester present, clear-DTC, write, IO-control, and routine
/// start/stop.  SecurityAccess is also handled — requestSeed returns a
/// fixed seed and sendKey is always accepted.  Everything else gets NRC
/// `0x31` (requestOutOfRange).
fn synth_uds_response(uds: &[u8]) -> Vec<u8> {
    let sid = uds.first().copied().unwrap_or(0);
    match sid {
        // DiagnosticSessionControl → positive with standard P2/P2* timings.
        0x10 => {
            let sub = uds.get(1).copied().unwrap_or(0x01);
            vec![0x50, sub, 0x00, 0x32, 0x01, 0xF4]
        }
        // TesterPresent → positive.
        0x3E => {
            let sub = uds.get(1).copied().unwrap_or(0x00);
            vec![0x7E, sub]
        }
        // ClearDiagnosticInformation → positive.
        0x14 => vec![0x54],
        // WriteDataByIdentifier → echo the 2-byte DID.
        0x2E if uds.len() >= 3 => vec![0x6E, uds[1], uds[2]],
        // InputOutputControlByIdentifier → echo DID + controlParameter
        // (+ controlState, which the GUI ignores but UDS allows).
        0x2F if uds.len() >= 3 => {
            let mut r = Vec::with_capacity(uds.len());
            r.push(0x6F);
            r.extend_from_slice(&uds[1..]);
            r
        }
        // RoutineControl Start/Stop/RequestResults → echo subfunction + RID.
        // (A RequestResults poll with a real status payload is normally
        // supplied as an explicit fixture entry; this is the fallback.)
        0x31 if uds.len() >= 4 => vec![0x71, uds[1], uds[2], uds[3]],
        // SecurityAccess.  A requestSeed (odd subfunction) returns a fixed
        // non-zero 4-byte seed; a sendKey (even subfunction) is always
        // accepted.  The fake adapter can't validate a real key, so any
        // login the tester computes succeeds — enough to click through the
        // login path offline.
        0x27 if uds.len() >= 2 => {
            let sub = uds[1];
            if sub % 2 == 1 {
                vec![0x67, sub, 0x01, 0x02, 0x03, 0x04]
            } else {
                vec![0x67, sub]
            }
        }
        // Anything else: requestOutOfRange.
        _ => vec![0x7F, sid, 0x31],
    }
}

// ── Fixture parser ────────────────────────────────────────────────────────────

/// Parse a fixture file into `(interactive, entries)`.
///
/// `interactive` is `true` when a comment line carries the
/// `mode: interactive` directive (see the module docs).
fn parse_fixture(content: &str) -> (bool, Vec<FixtureEntry>) {
    let mut entries = Vec::new();
    let mut interactive = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            let directive = comment.trim();
            if directive.eq_ignore_ascii_case("mode: interactive")
                || directive.eq_ignore_ascii_case("@interactive")
            {
                interactive = true;
            }
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let dir_str = parts.next().unwrap_or("");
        let id_str = parts.next().unwrap_or("");
        let data_str = parts.next().unwrap_or("");

        let direction = match dir_str {
            "T" => Direction::Tx,
            "R" => Direction::Rx,
            _ => continue,
        };
        let id: u32 = match u32::from_str_radix(id_str, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let uds: Vec<u8> = data_str
            .split_whitespace()
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if !uds.is_empty() {
            entries.push(FixtureEntry { direction, id, uds });
        }
    }
    (interactive, entries)
}

// ── CanAdapter impl ───────────────────────────────────────────────────────────

impl CanAdapter for FakeCanAdapter {
    fn send(&mut self, frames: &mut VecDeque<Frame>) -> automotive::Result<()> {
        while let Some(frame) = frames.pop_front() {
            tracing::trace!(
                loopback = frame.loopback,
                data = ?frame.data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                "FakeCanAdapter::send frame"
            );
            if frame.loopback {
                continue;
            }

            // AsyncCanAdapter::send() awaits a loopback echo before resolving.
            // Return a loopback copy so the send future doesn't block forever.
            let mut loopback = frame.clone();
            loopback.loopback = true;
            self.rx_queue.push_back(loopback);

            let data = &frame.data;
            if data.is_empty() {
                continue;
            }

            let frame_type = data[0] >> 4;

            match frame_type {
                0x0 => {
                    // Single Frame: byte[0] low nibble = UDS length
                    let len = (data[0] & 0x0F) as usize;
                    if len == 0 || len > 7 || data.len() < 1 + len {
                        tracing::warn!("FakeCanAdapter: malformed SF (data={:02X?})", data);
                        continue;
                    }
                    self.isotp_pending = None;
                    self.handle_complete_uds(&data[1..1 + len]);
                }

                0x1 => {
                    // First Frame: total_len from bytes [0..2]
                    let total_len = (((data[0] & 0x0F) as usize) << 8)
                        | (data.get(1).copied().unwrap_or(0) as usize);

                    // Auto-respond with ClearToSend flow control.
                    let fc_data = [0x30u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    if let Ok(fc) =
                        Frame::new(frame.bus, Identifier::from(self.ecu_tx_id), &fc_data)
                    {
                        self.rx_queue.push_back(fc);
                    }

                    // Start ISO-TP reassembly: FF carries bytes 2..7
                    let payload_end = data.len().min(8);
                    let mut r = Reassembler::new(total_len);
                    r.push_first_frame(&data[2..payload_end]);
                    self.isotp_pending = Some(r);
                }

                0x2 => {
                    // Consecutive Frame: payload starts at byte[1]
                    if let Some(pending) = self.isotp_pending.as_mut() {
                        let payload_end = data.len().min(8);
                        if payload_end <= 1 {
                            continue;
                        }
                        pending.push_consecutive_frame(&data[1..payload_end]);

                        if pending.is_complete() {
                            let uds = self.isotp_pending.take().unwrap().take();
                            self.handle_complete_uds(&uds);
                        }
                    } else {
                        tracing::warn!("FakeCanAdapter: CF with no pending ISO-TP session");
                    }
                }

                0x3 => {
                    // Flow Control (tester responding to an ECU First Frame).
                    // We already enqueued all CFs at once, so nothing to do here.
                }

                _ => {
                    tracing::warn!(
                        "FakeCanAdapter: unknown ISO-TP frame type 0x{:X} (data={:02X?})",
                        frame_type,
                        data,
                    );
                }
            }
        }
        Ok(())
    }

    fn recv(&mut self) -> automotive::Result<Vec<Frame>> {
        if self.rx_queue.is_empty() {
            // Yield briefly so the polling loop does not busy-spin.
            std::thread::sleep(std::time::Duration::from_millis(5));
            return Ok(vec![]);
        }
        Ok(self.rx_queue.drain(..).collect())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_mode_is_the_default() {
        let (interactive, entries) = parse_fixture("T 7E0 10 03\nR 7E8 50 03\n");
        assert!(!interactive);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn directive_selects_interactive_mode() {
        let (interactive, _) = parse_fixture("# mode: interactive\nT 7E0 22 f1 90\n");
        assert!(interactive);
    }

    #[test]
    fn response_map_groups_replies_by_request() {
        let (_, entries) = parse_fixture(
            "# mode: interactive\n\
             T 7E0 22 f1 90\n\
             R 7E8 62 f1 90 41\n\
             T 7E0 22 f1 9e\n\
             R 7E8 62 f1 9e 42\n",
        );
        let map = build_response_map(entries);
        assert_eq!(
            map.get(&vec![0x22, 0xF1, 0x90]).unwrap(),
            &[vec![0x62, 0xF1, 0x90, 0x41]]
        );
        assert_eq!(
            map.get(&vec![0x22, 0xF1, 0x9E]).unwrap(),
            &[vec![0x62, 0xF1, 0x9E, 0x42]]
        );
    }

    #[test]
    fn synth_covers_generic_services() {
        assert_eq!(
            synth_uds_response(&[0x10, 0x03]),
            vec![0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]
        );
        assert_eq!(synth_uds_response(&[0x3E, 0x00]), vec![0x7E, 0x00]);
        assert_eq!(synth_uds_response(&[0x14, 0xFF, 0xFF, 0xFF]), vec![0x54]);
        assert_eq!(
            synth_uds_response(&[0x2E, 0x12, 0x34, 0xAA]),
            vec![0x6E, 0x12, 0x34]
        );
        assert_eq!(
            synth_uds_response(&[0x2F, 0x12, 0x34, 0x03, 0x01]),
            vec![0x6F, 0x12, 0x34, 0x03, 0x01],
        );
        assert_eq!(
            synth_uds_response(&[0x31, 0x01, 0x02, 0x03]),
            vec![0x71, 0x01, 0x02, 0x03]
        );
        // SecurityAccess: requestSeed (odd) → seed; sendKey (even) → accepted.
        assert_eq!(
            synth_uds_response(&[0x27, 0x03]),
            vec![0x67, 0x03, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(
            synth_uds_response(&[0x27, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]),
            vec![0x67, 0x04],
        );
        // Unknown read → requestOutOfRange.
        assert_eq!(
            synth_uds_response(&[0x22, 0xAB, 0xCD]),
            vec![0x7F, 0x22, 0x31]
        );
    }
}
