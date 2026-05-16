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

use std::collections::VecDeque;
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

// ── FakeCanAdapter ────────────────────────────────────────────────────────────

/// A blocking [`CanAdapter`] that replays a `.can` fixture file.
///
/// Fixture entries use raw UDS PDU bytes; ISO-TP fragmentation and
/// reassembly are handled internally.
pub struct FakeCanAdapter {
    fixture:        VecDeque<FixtureEntry>,
    rx_queue:       VecDeque<Frame>,
    /// CAN ID used for ECU→tester frames we fabricate (FC, auto-responses).
    ecu_tx_id:      u32,
    /// ISO-TP reassembly state for an ongoing multi-frame tester message.
    isotp_pending:  Option<Reassembler>,
}

impl FakeCanAdapter {
    /// Build a new adapter from a `.can` fixture file.
    pub fn new(fixture_path: &Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(fixture_path)?;
        let entries = parse_fixture(&content);
        let ecu_tx_id = entries
            .iter()
            .find(|e| e.direction == Direction::Rx)
            .map(|e| e.id)
            .unwrap_or(0x7E8);

        Ok(Self {
            fixture: VecDeque::from(entries),
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
    /// * Anything else → advance the fixture and enqueue R-frames.
    fn handle_complete_uds(&mut self, uds: &[u8]) {
        let sid = uds.first().copied().unwrap_or(0);

        if sid == 0x36 {
            let counter = uds.get(1).copied().unwrap_or(0);
            tracing::trace!("FakeCanAdapter: auto-responding to TransferData counter=0x{counter:02X}");
            self.enqueue_uds_response(&[0x76, counter]);
            return;
        }

        if let Some(expected) = self.fixture.front() {
            if expected.direction == Direction::Tx && expected.uds == uds {
                self.fixture.pop_front();
                // Enqueue all immediately following R-entries.
                loop {
                    match self.fixture.front() {
                        Some(e) if e.direction == Direction::Rx => {
                            let entry = self.fixture.pop_front().expect("front was Some");
                            self.enqueue_uds_response(&entry.uds);
                        }
                        _ => break,
                    }
                }
            } else {
                tracing::warn!(
                    "FakeCanAdapter: unexpected UDS (got {:02X?}, expected {:02X?})",
                    uds,
                    expected.uds,
                );
            }
        }
    }
}

// ── Fixture parser ────────────────────────────────────────────────────────────

fn parse_fixture(content: &str) -> Vec<FixtureEntry> {
    let mut entries = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let dir_str  = parts.next().unwrap_or("");
        let id_str   = parts.next().unwrap_or("");
        let data_str = parts.next().unwrap_or("");

        let direction = match dir_str {
            "T" => Direction::Tx,
            "R" => Direction::Rx,
            _   => continue,
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
    entries
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
                    if let Ok(fc) = Frame::new(frame.bus, Identifier::from(self.ecu_tx_id), &fc_data) {
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
