//! ISO-TP (ISO 15765-2) CAN frame codec.
//!
//! Provides frame fragmentation and multi-frame reassembly helpers used by
//! CAN adapter implementations.

use automotive::can::{Frame, Identifier};

// ── Fragmentation ─────────────────────────────────────────────────────────────

/// Fragment a UDS PDU into ISO-TP CAN frames addressed to `id`.
///
/// Single Frame (≤7 bytes): `[0x0N, data...]`
/// First Frame + Consecutive Frames (>7 bytes).
/// All frames are zero-padded to 8 bytes.
pub fn fragment(uds: &[u8], id: u32) -> Vec<Frame> {
    let mut frames = Vec::new();

    if uds.len() <= 7 {
        // Single Frame
        let mut data = vec![uds.len() as u8];
        data.extend_from_slice(uds);
        data.resize(8, 0x00);
        if let Ok(f) = Frame::new(0, Identifier::from(id), &data) {
            frames.push(f);
        }
        return frames;
    }

    let total = uds.len();

    // First Frame: [0x1H, 0xLL, payload[0..6]]
    let mut ff = vec![
        0x10u8 | (((total >> 8) & 0x0F) as u8),
        (total & 0xFF) as u8,
    ];
    ff.extend_from_slice(&uds[..6.min(total)]);
    ff.resize(8, 0x00);
    if let Ok(f) = Frame::new(0, Identifier::from(id), &ff) {
        frames.push(f);
    }

    // Consecutive Frames: [0x2N, payload...]
    let mut sn = 1u8;
    let mut offset = 6;
    while offset < uds.len() {
        let end = (offset + 7).min(uds.len());
        let mut cf = vec![0x20 | sn];
        cf.extend_from_slice(&uds[offset..end]);
        cf.resize(8, 0x00);
        if let Ok(f) = Frame::new(0, Identifier::from(id), &cf) {
            frames.push(f);
        }
        sn = (sn + 1) & 0x0F;
        offset = end;
    }

    frames
}

// ── Reassembly ────────────────────────────────────────────────────────────────

/// ISO-TP multi-frame reassembler.
///
/// Accumulates payload bytes from First Frame and Consecutive Frame CAN
/// frames until the complete UDS PDU has been received.
pub struct Reassembler {
    buf: Vec<u8>,
    total_len: usize,
}

impl Reassembler {
    /// Create a new reassembler expecting `total_len` bytes of UDS payload.
    pub fn new(total_len: usize) -> Self {
        Self {
            buf: Vec::with_capacity(total_len),
            total_len,
        }
    }

    /// Append payload bytes carried by a First Frame.
    ///
    /// The caller should pass the frame bytes *after* the 2-byte FF header
    /// (i.e. `&frame_data[2..]`).
    pub fn push_first_frame(&mut self, payload: &[u8]) {
        self.buf.extend_from_slice(payload);
    }

    /// Append payload bytes carried by a Consecutive Frame.
    ///
    /// The caller should pass the frame bytes *after* the SN byte
    /// (i.e. `&frame_data[1..]`).  Only as many bytes as needed to reach
    /// `total_len` are accepted; excess bytes are silently ignored.
    pub fn push_consecutive_frame(&mut self, payload: &[u8]) {
        let remaining = self.total_len.saturating_sub(self.buf.len());
        if remaining == 0 {
            return;
        }
        let take = remaining.min(payload.len());
        self.buf.extend_from_slice(&payload[..take]);
    }

    /// Returns `true` when the buffer has received at least `total_len` bytes.
    pub fn is_complete(&self) -> bool {
        self.buf.len() >= self.total_len
    }

    /// Consume the reassembler and return the accumulated UDS payload.
    pub fn take(self) -> Vec<u8> {
        self.buf
    }
}
