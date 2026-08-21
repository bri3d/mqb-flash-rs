//! Parsing, decrypting and rewriting the NVRAM records in a DFlash image.
//!
//! Simos18 emulates EEPROM in the Tricore's DFlash. The store is organised into
//! 127 *channels*; each write appends a new record, and when a page fills the
//! live records are copied into a freshly erased one (garbage collection),
//! bumping a 32-bit **flash generation counter**. The latest record for a
//! channel is therefore the one at the highest offset, and older copies of the
//! same channel are left behind in the image.
//!
//! A record is framed from the end:
//!
//! ```text
//! data[length*8] | inv_crc[3] | length[1] | channel[1] | 0x46 | crc[2]
//! ```
//!
//! `inv_crc` is `((crc ^ 0xFFFF) << 4)` in 24 bits — a redundant copy that makes
//! record discovery reliable. `crc` is the **outer** record CRC ([`INIT_OUTER`])
//! over the record's *logical* bytes followed by an 8-byte trailer carrying the
//! generation counter. The logical size is not stored, so [`Alignment`]
//! recovers it by trying every plausible framing.
//!
//! Some channels carry a second, **inner** CRC ([`INIT_INNER`]) as a 2-byte
//! little-endian prefix on the plaintext (`record_way == 1`); others do not
//! (`record_way == 0`, which includes the immobilizer channels). Encrypted
//! channels are XORed with the Hitag2 keystream for their channel number.

use std::collections::BTreeMap;

use crate::crc::{crc16_8005, INIT_INNER, INIT_OUTER};
use crate::hitag2::{crypt, derive_iv, derive_key};

/// The record marker byte that identifies an NVRAM channel record.
const MARKER: u8 = 0x46;

/// Highest channel number the firmware uses.
const MAX_CHANNEL: u8 = 127;

/// Records are a whole number of 8-byte FEE slots, at most 32 of them.
const MAX_SLOTS: u8 = 32;

/// The Hitag2 key/IV pair for one ECU, derived from its Device ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hitag2Keys {
    pub key: [u8; 6],
    pub iv: [u8; 4],
}

impl Hitag2Keys {
    /// Derive both halves from a 12-byte Tricore Device ID.
    pub fn from_device_id(device_id: &[u8]) -> Self {
        Self {
            key: derive_key(device_id),
            iv: derive_iv(device_id),
        }
    }
}

/// One NVRAM channel record found in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// NVRAM channel number.
    pub channel: u8,
    /// Length in 8-byte FEE slots; the data region is `length * 8` bytes.
    pub length: u8,
    /// Offset of the data region within the image.
    pub offset: usize,
    /// The data region as stored (still encrypted on encrypted channels).
    pub data: Vec<u8>,
    /// The outer record CRC as stored.
    pub crc: u16,
}

impl Record {
    /// Size of the data region in bytes.
    pub fn slot_len(&self) -> usize {
        self.data.len()
    }

    /// Offset of the 3-byte inverted-CRC field.
    fn inv_crc_offset(&self) -> usize {
        self.offset + self.slot_len()
    }

    /// Offset of the 2-byte big-endian outer CRC.
    fn crc_offset(&self) -> usize {
        self.offset + self.slot_len() + 3 + 3
    }

    /// The 8-byte trailer the outer CRC is computed over, after the record's
    /// logical bytes.
    fn trailer(&self, generation: u32) -> [u8; 8] {
        let g = generation.to_le_bytes();
        [
            g[0],
            g[1],
            g[2],
            g[3],
            self.length,
            0x00,
            MARKER,
            self.channel,
        ]
    }
}

/// An FEE page header record (`0xFFFE`), which carries the page sequence
/// number. Its low 16 bits are the generation counter every record CRC uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageHeader {
    pub offset: usize,
    pub length: u8,
    pub data: Vec<u8>,
    pub crc: u16,
    /// The 32-bit page-switch counter, stored big-endian at `data[4..8]`.
    pub seq: Option<u32>,
    /// Whether the header's own CRC checks out against that sequence number.
    pub valid: bool,
}

/// How a record's logical bytes are laid out within its FEE slots.
///
/// The firmware CRCs the channel's *logical* data size, which is not stored, so
/// the framing has to be recovered by trying each possibility against the CRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    /// Logical bytes start at the beginning of the slot; `pad` trailing bytes
    /// are FEE padding excluded from the CRC.
    Left { data_size: usize, pad: usize },
    /// Logical bytes end at the end of the slot; `skip` leading bytes are FEE
    /// padding excluded from the CRC.
    Right { data_size: usize, skip: usize },
    /// The record straddles an FEE block boundary: a block-management byte is
    /// interleaved in the image at `gap` but is not part of the CRC stream.
    Split {
        data_size: usize,
        gap: usize,
        pad: usize,
    },
}

impl Alignment {
    /// Number of leading image bytes that are padding rather than payload.
    pub fn skip(self) -> usize {
        match self {
            Alignment::Right { skip, .. } => skip,
            _ => 0,
        }
    }

    /// The record's logical byte count, as CRCed by the firmware.
    pub fn data_size(self) -> usize {
        match self {
            Alignment::Left { data_size, .. }
            | Alignment::Right { data_size, .. }
            | Alignment::Split { data_size, .. } => data_size,
        }
    }

    /// A short label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Alignment::Left { .. } => "left",
            Alignment::Right { .. } => "right",
            Alignment::Split { .. } => "split",
        }
    }
}

/// What [`analyze`] worked out about one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAnalysis {
    /// The recovered framing, or `None` when the outer CRC never validated.
    pub alignment: Option<Alignment>,
    /// Whether the payload had to be Hitag2-decrypted to make sense.
    pub encrypted: bool,
    /// The inner content CRC, when this channel carries one (`record_way 1`).
    pub inner_crc: Option<u16>,
    /// The channel's content: the plaintext payload with any inner CRC prefix
    /// and trailing padding removed.
    pub content: Vec<u8>,
    /// Trailing plaintext padding after the content, when the inner CRC pinned
    /// the content length.
    pub pad: Vec<u8>,
    /// The full plaintext payload, inner CRC prefix and padding included.
    pub plaintext: Vec<u8>,
}

impl RecordAnalysis {
    /// Whether the outer record CRC validated.
    pub fn outer_ok(&self) -> bool {
        self.alignment.is_some()
    }
}

/// Where the flash generation counter came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationSource {
    /// Read from the `0xFFFE` page header and confirmed by brute force.
    PageHeaderConfirmed,
    /// Read from the page header; brute force disagreed. The header wins, but
    /// something is off about the image.
    PageHeaderDisputed { brute_forced: u32 },
    /// Read from the page header; brute force could not run.
    PageHeader,
    /// Recovered by brute-forcing record CRCs; no usable page header.
    BruteForced,
}

/// The flash generation counter and how it was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation {
    pub value: u32,
    pub source: GenerationSource,
}

impl Generation {
    /// True when the page header and the record CRCs disagree — the image is
    /// readable but something about it is inconsistent.
    pub fn is_disputed(self) -> bool {
        matches!(self.source, GenerationSource::PageHeaderDisputed { .. })
    }
}

/// Why a record could not be rewritten.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    /// No live record for that channel.
    #[error("no record for channel {channel} in this image")]
    NoSuchChannel { channel: u8 },

    /// The generation counter is unknown, so no outer CRC can be computed.
    #[error("the flash generation counter is unknown, so the record CRC cannot be recomputed")]
    UnknownGeneration,

    /// The record's own outer CRC never validated, so its framing is unknown
    /// and rewriting it would corrupt the image.
    #[error(
        "channel {channel}'s record CRC does not validate, so its framing is unknown; \
         refusing to rewrite it"
    )]
    UnknownAlignment { channel: u8 },

    /// Split records interleave a block-management byte, and the reference
    /// implementation has never been exercised against one on an *encrypted*
    /// channel, so writing one would be a guess.
    #[error(
        "channel {channel}'s record straddles an FEE block boundary; rewriting a split \
         record is not supported"
    )]
    SplitRecord { channel: u8 },

    /// The replacement content is not the size the record holds.
    #[error("channel {channel} holds {expected} content bytes, but {got} were supplied")]
    WrongLength {
        channel: u8,
        expected: usize,
        got: usize,
    },

    /// Decrypting an encrypted channel needs the Device ID keys.
    #[error("channel {channel} is encrypted; rewriting it needs the ECU's Device ID")]
    KeysRequired { channel: u8 },

    /// The rewritten record did not read back as intended. The image is left
    /// unmodified.
    #[error("the rewritten record for channel {channel} did not read back correctly: {detail}")]
    VerifyFailed { channel: u8, detail: String },
}

/// A parsed DFlash image.
#[derive(Debug, Clone)]
pub struct Dump {
    data: Vec<u8>,
    records: Vec<Record>,
    headers: Vec<PageHeader>,
    /// Index into `records` of the newest record for each channel.
    latest: BTreeMap<u8, usize>,
    /// How many records exist for each channel, i.e. how often it was written.
    writes: BTreeMap<u8, usize>,
    generation: Option<Generation>,
}

impl Dump {
    /// Parse a raw DFlash image.
    pub fn parse(data: Vec<u8>) -> Self {
        let records = parse_records(&data);
        let headers = find_page_headers(&data);

        let mut latest: BTreeMap<u8, usize> = BTreeMap::new();
        let mut writes: BTreeMap<u8, usize> = BTreeMap::new();
        for (i, rec) in records.iter().enumerate() {
            *writes.entry(rec.channel).or_insert(0) += 1;
            latest
                .entry(rec.channel)
                .and_modify(|best| {
                    if rec.offset > records[*best].offset {
                        *best = i;
                    }
                })
                .or_insert(i);
        }

        let live: Vec<&Record> = latest.values().map(|&i| &records[i]).collect();
        let generation = find_generation(&headers, &live);

        Self {
            data,
            records,
            headers,
            latest,
            writes,
            generation,
        }
    }

    /// The image bytes, including any rewrites.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Every record found, newest and superseded alike.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// The FEE page headers.
    pub fn page_headers(&self) -> &[PageHeader] {
        &self.headers
    }

    /// The flash generation counter, when it could be determined.
    pub fn generation(&self) -> Option<Generation> {
        self.generation
    }

    /// The channels that have at least one record, in ascending order.
    pub fn channels(&self) -> Vec<u8> {
        self.latest.keys().copied().collect()
    }

    /// The newest record for a channel.
    pub fn latest(&self, channel: u8) -> Option<&Record> {
        self.latest.get(&channel).map(|&i| &self.records[i])
    }

    /// How many times a channel has been written in this image.
    pub fn write_count(&self, channel: u8) -> usize {
        self.writes.get(&channel).copied().unwrap_or(0)
    }

    /// Resolve the framing, decrypt if needed, and recover the content of a
    /// record.
    pub fn analyze(&self, record: &Record, keys: Option<&Hitag2Keys>) -> RecordAnalysis {
        analyze(record, self.generation.map(|g| g.value), keys)
    }

    /// Analyze the newest record for a channel.
    pub fn analyze_channel(
        &self,
        channel: u8,
        keys: Option<&Hitag2Keys>,
    ) -> Option<RecordAnalysis> {
        self.latest(channel).map(|r| self.analyze(r, keys))
    }

    /// Replace a channel's content, re-encrypting and fixing both CRC layers.
    ///
    /// `content` must be exactly the length the existing record holds — this
    /// rewrites a record in place and cannot change the FEE framing. The image
    /// is only modified once the rewritten record has been read back and
    /// verified, so a failure leaves it untouched.
    pub fn rewrite_channel(
        &mut self,
        channel: u8,
        content: &[u8],
        keys: Option<&Hitag2Keys>,
    ) -> Result<(), WriteError> {
        let index = *self
            .latest
            .get(&channel)
            .ok_or(WriteError::NoSuchChannel { channel })?;
        let generation = self.generation.ok_or(WriteError::UnknownGeneration)?.value;

        let record = self.records[index].clone();
        let before = self.analyze(&record, keys);
        let alignment = before
            .alignment
            .ok_or(WriteError::UnknownAlignment { channel })?;
        if let Alignment::Split { .. } = alignment {
            return Err(WriteError::SplitRecord { channel });
        }
        if before.encrypted && keys.is_none() {
            return Err(WriteError::KeysRequired { channel });
        }
        if content.len() != before.content.len() {
            return Err(WriteError::WrongLength {
                channel,
                expected: before.content.len(),
                got: content.len(),
            });
        }

        // Rebuild the plaintext payload the same shape as the one we read: an
        // inner CRC prefix only if this channel carries one, then the content,
        // then whatever plaintext padding followed it.
        let mut plaintext = Vec::with_capacity(before.plaintext.len());
        if before.inner_crc.is_some() {
            plaintext.extend_from_slice(&crc16_8005(INIT_INNER, content).to_le_bytes());
        }
        plaintext.extend_from_slice(content);
        plaintext.extend_from_slice(&before.pad);
        debug_assert_eq!(plaintext.len(), before.plaintext.len());

        let stored = if before.encrypted {
            let keys = keys.expect("checked above");
            crypt(&plaintext, &keys.key, &keys.iv, channel as u16)
        } else {
            plaintext.clone()
        };

        // Splice the payload back in, then recompute both CRC fields.
        let skip = alignment.skip();
        let mut slot = record.data.clone();
        slot[skip..skip + stored.len()].copy_from_slice(&stored);

        let covered = match alignment {
            Alignment::Left { data_size, .. } => &slot[..data_size],
            Alignment::Right { skip, .. } => &slot[skip..],
            Alignment::Split { .. } => unreachable!("rejected above"),
        };
        let mut crc_input = covered.to_vec();
        crc_input.extend_from_slice(&record.trailer(generation));
        let crc = crc16_8005(INIT_OUTER, &crc_input);
        let inv = ((crc as u32 ^ 0xFFFF) << 4) & 0x00FF_FFFF;

        // Stage the whole edit, verify it, and only then keep it.
        let mut staged = self.data.clone();
        staged[record.offset..record.offset + slot.len()].copy_from_slice(&slot);
        staged[record.inv_crc_offset()..record.inv_crc_offset() + 3]
            .copy_from_slice(&inv.to_be_bytes()[1..4]);
        let crc_at = record.crc_offset();
        staged[crc_at..crc_at + 2].copy_from_slice(&crc.to_be_bytes());

        let candidate = Dump::parse(staged);
        let readback =
            candidate
                .analyze_channel(channel, keys)
                .ok_or_else(|| WriteError::VerifyFailed {
                    channel,
                    detail: "the rewritten record could not be found again".into(),
                })?;
        if !readback.outer_ok() {
            return Err(WriteError::VerifyFailed {
                channel,
                detail: "the recomputed record CRC does not validate".into(),
            });
        }
        if readback.content != content {
            return Err(WriteError::VerifyFailed {
                channel,
                detail: "the record did not decrypt back to the requested content".into(),
            });
        }

        *self = candidate;
        Ok(())
    }
}

/// Scan an image for NVRAM channel records.
pub fn parse_records(data: &[u8]) -> Vec<Record> {
    let mut records = Vec::new();
    if data.len() < 5 {
        return records;
    }
    for pos in 2..data.len() - 2 {
        if data[pos] != MARKER {
            continue;
        }
        let channel = data[pos - 1];
        let length = data[pos - 2];
        if channel > MAX_CHANNEL || !(1..=MAX_SLOTS).contains(&length) {
            continue;
        }
        let slot_len = length as usize * 8;
        let Some(offset) = (pos - 2).checked_sub(slot_len + 3) else {
            continue;
        };

        let crc = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
        let inv_at = offset + slot_len;
        let actual_inv = u32::from_be_bytes([0, data[inv_at], data[inv_at + 1], data[inv_at + 2]]);
        if actual_inv != ((crc as u32 ^ 0xFFFF) << 4) & 0x00FF_FFFF {
            continue;
        }

        records.push(Record {
            channel,
            length,
            offset,
            data: data[offset..offset + slot_len].to_vec(),
            crc,
        });
    }
    records
}

/// Scan an image for `0xFFFE` FEE page headers.
pub fn find_page_headers(data: &[u8]) -> Vec<PageHeader> {
    let mut headers = Vec::new();
    if data.len() < 5 {
        return headers;
    }
    for pos in 2..data.len() - 2 {
        if data[pos] != 0xFE || data[pos - 1] != 0xFF {
            continue;
        }
        let length = data[pos - 2];
        if !(1..=MAX_SLOTS).contains(&length) {
            continue;
        }
        let slot_len = length as usize * 8;
        let Some(offset) = (pos - 2).checked_sub(slot_len + 3) else {
            continue;
        };
        let crc = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
        let inv_at = offset + slot_len;
        let actual_inv = u32::from_be_bytes([0, data[inv_at], data[inv_at + 1], data[inv_at + 2]]);
        if actual_inv != ((crc as u32 ^ 0xFFFF) << 4) & 0x00FF_FFFF {
            continue;
        }

        let d = data[offset..offset + slot_len].to_vec();
        let seq = (d.len() >= 8).then(|| u32::from_be_bytes([d[4], d[5], d[6], d[7]]));
        let valid = seq.is_some_and(|seq| {
            let g = seq.to_le_bytes();
            let trailer = [g[0], g[1], 0, 0, length, 0, 0xFE, 0xFF];
            let mut buf = d.clone();
            buf.extend_from_slice(&trailer);
            crc16_8005(INIT_OUTER, &buf) == crc
        });
        headers.push(PageHeader {
            offset,
            length,
            data: d,
            crc,
            seq,
            valid,
        });
    }
    headers
}

/// Determine the flash generation counter, cross-checking the page header
/// against a brute-force search over the record CRCs.
fn find_generation(headers: &[PageHeader], live: &[&Record]) -> Option<Generation> {
    let from_header = headers
        .iter()
        .filter(|h| h.valid)
        .filter_map(|h| h.seq)
        .next()
        .or_else(|| headers.iter().filter_map(|h| h.seq).next());
    let brute = brute_force_generation(live);

    match (from_header, brute) {
        (Some(header), Some(brute)) if header & 0xFFFF == brute & 0xFFFF => Some(Generation {
            value: header,
            source: GenerationSource::PageHeaderConfirmed,
        }),
        (Some(header), Some(brute)) => Some(Generation {
            value: header,
            source: GenerationSource::PageHeaderDisputed {
                brute_forced: brute,
            },
        }),
        (Some(header), None) => Some(Generation {
            value: header,
            source: GenerationSource::PageHeader,
        }),
        (None, Some(brute)) => Some(Generation {
            value: brute,
            source: GenerationSource::BruteForced,
        }),
        (None, None) => None,
    }
}

/// Recover the generation counter from the record CRCs alone.
///
/// The counter appears only in the CRCed trailer, so every candidate has to be
/// tried; the one validating the most records wins, which over a real image is
/// unambiguous because a wrong candidate would have to collide on every channel
/// at once. A single record cannot pin it — with 65 536 candidates against a
/// 16-bit CRC, roughly one wrong value also fits — so `None` beats a coin-flip.
pub fn brute_force_generation(records: &[&Record]) -> Option<u32> {
    // Any one record may be damaged — a torn write, or an uncovered framing —
    // so try a handful of starting points rather than letting the first decide.
    records
        .iter()
        .take(8)
        .find_map(|probe| brute_force_from_probe(probe, records))
}

fn brute_force_from_probe(probe: &Record, records: &[&Record]) -> Option<u32> {
    let slot = probe.data.len();

    // The CRC runs left to right, so the state after the record's data is
    // computed once per framing and only the 8-byte trailer is re-run per
    // candidate. Without this the search is a few billion byte-operations.
    let mut prefixes: Vec<u16> = Vec::with_capacity(16);
    for n in (slot.saturating_sub(7)..=slot).rev() {
        prefixes.push(crc16_8005(INIT_OUTER, &probe.data[..n]));
        prefixes.push(crc16_8005(INIT_OUTER, &probe.data[slot - n..]));
    }

    let mut best: Option<(u32, usize)> = None;
    let mut hits_at_best = 0usize;
    for candidate in 0u32..0x1_0000 {
        let trailer = probe.trailer(candidate);
        if !prefixes
            .iter()
            .any(|&state| crc16_8005(state, &trailer) == probe.crc)
        {
            continue;
        }
        let hits = records
            .iter()
            .filter(|r| aligned_outer_crc(r, candidate).is_some())
            .count();
        if best.is_none() || hits > hits_at_best {
            best = Some((candidate, hits));
            hits_at_best = hits;
        }
    }

    // One record's worth of evidence is one CRC's worth: not enough.
    let (value, hits) = best?;
    (hits >= 2).then_some(value)
}

/// The cheap half of [`validate_outer_crc`]: the two single-block framings,
/// skipping the quadratic split search. Used where a fast yes/no is enough.
fn aligned_outer_crc(record: &Record, generation: u32) -> Option<Alignment> {
    let slot = record.data.len();
    let trailer = record.trailer(generation);
    for n in (slot.saturating_sub(7)..=slot).rev() {
        let mut buf = record.data[..n].to_vec();
        buf.extend_from_slice(&trailer);
        if crc16_8005(INIT_OUTER, &buf) == record.crc {
            return Some(Alignment::Left {
                data_size: n,
                pad: slot - n,
            });
        }
        let mut buf = record.data[slot - n..].to_vec();
        buf.extend_from_slice(&trailer);
        if crc16_8005(INIT_OUTER, &buf) == record.crc {
            return Some(Alignment::Right {
                data_size: n,
                skip: slot - n,
            });
        }
    }
    None
}

/// Recover a record's framing by finding which one makes the outer CRC check.
pub fn validate_outer_crc(record: &Record, generation: u32) -> Option<Alignment> {
    // Within a single FEE block the logical data is at most one slot's worth of
    // padding shorter than the stored region, and sits at one end or the other.
    if let Some(alignment) = aligned_outer_crc(record, generation) {
        return Some(alignment);
    }

    let slot = record.data.len();
    let trailer = record.trailer(generation);
    let matches = |bytes: &[u8]| {
        let mut buf = bytes.to_vec();
        buf.extend_from_slice(&trailer);
        crc16_8005(INIT_OUTER, &buf) == record.crc
    };

    // Straddling a block boundary: one management byte sits in the image but
    // not in the CRC stream.
    for gap in 1..slot {
        let mut seg = Vec::with_capacity(slot - 1);
        seg.extend_from_slice(&record.data[..gap]);
        seg.extend_from_slice(&record.data[gap + 1..]);
        for n in (seg.len().saturating_sub(6)..=seg.len()).rev() {
            if matches(&seg[..n]) {
                return Some(Alignment::Split {
                    data_size: n,
                    gap,
                    pad: seg.len() - n,
                });
            }
        }
    }
    None
}

/// Recover the content length pinned by an inner CRC prefix.
///
/// The prefix covers exactly the channel's logical content, whose length is not
/// stored anywhere, so every length is tried. `None` means this channel has no
/// inner CRC (`record_way 0`) — or the payload is still ciphertext.
pub fn recover_inner_crc(payload: &[u8]) -> Option<usize> {
    if payload.len() < 2 {
        return None;
    }
    let prefix = u16::from_le_bytes([payload[0], payload[1]]);
    let body = &payload[2..];
    (0..=body.len()).find(|&n| crc16_8005(INIT_INNER, &body[..n]) == prefix)
}

/// Did Hitag2 turn this ciphertext into something that looks like plaintext?
///
/// Channels with an inner CRC prove themselves; this heuristic only carries the
/// `record_way 0` channels, where nothing is self-validating. Plaintext there is
/// structured data with runs of zeroes, and the immobilizer channels start with
/// `bAuthPreVld`, always `0xAA` or `0x55`.
fn looks_decrypted(raw: &[u8], decrypted: &[u8]) -> bool {
    if decrypted.len() < 8 {
        return false;
    }
    let raw_zeroes = raw.iter().filter(|&&b| b == 0).count();
    let dec_zeroes = decrypted.iter().filter(|&&b| b == 0).count();
    if matches!(decrypted[0], 0xAA | 0x55) && raw_zeroes < raw.len() / 4 {
        return true;
    }
    dec_zeroes > raw_zeroes + 4 && dec_zeroes >= decrypted.len() / 8
}

/// Resolve both CRC layers and recover the content of one record.
pub fn analyze(
    record: &Record,
    generation: Option<u32>,
    keys: Option<&Hitag2Keys>,
) -> RecordAnalysis {
    let alignment = generation.and_then(|g| validate_outer_crc(record, g));
    let skip = alignment.map_or(0, Alignment::skip);
    let payload = &record.data[skip..];

    // Stored plaintext with an inner CRC proves itself immediately.
    let mut plaintext = payload.to_vec();
    let mut encrypted = false;
    let mut content_len = recover_inner_crc(payload);

    if content_len.is_none() {
        if let Some(keys) = keys {
            let decrypted = crypt(payload, &keys.key, &keys.iv, record.channel as u16);
            if let Some(n) = recover_inner_crc(&decrypted) {
                content_len = Some(n);
                plaintext = decrypted;
                encrypted = true;
            } else if looks_decrypted(payload, &decrypted) {
                plaintext = decrypted;
                encrypted = true;
            }
        }
    }

    match content_len {
        Some(n) => RecordAnalysis {
            alignment,
            encrypted,
            inner_crc: Some(u16::from_le_bytes([plaintext[0], plaintext[1]])),
            content: plaintext[2..2 + n].to_vec(),
            pad: plaintext[2 + n..].to_vec(),
            plaintext,
        },
        // record_way 0, or a channel we have no key for: the payload is the
        // content, and there is no prefix or padding to separate out.
        None => RecordAnalysis {
            alignment,
            encrypted,
            inner_crc: None,
            content: plaintext.clone(),
            pad: Vec::new(),
            plaintext,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame one record the way the firmware does.
    fn frame(channel: u8, payload: &[u8], generation: u32) -> Vec<u8> {
        assert_eq!(payload.len() % 8, 0);
        let length = (payload.len() / 8) as u8;
        let g = generation.to_le_bytes();
        let trailer = [g[0], g[1], g[2], g[3], length, 0x00, MARKER, channel];

        let mut crc_input = payload.to_vec();
        crc_input.extend_from_slice(&trailer);
        let crc = crc16_8005(INIT_OUTER, &crc_input);
        let inv = ((crc as u32 ^ 0xFFFF) << 4) & 0x00FF_FFFF;

        let mut out = payload.to_vec();
        out.extend_from_slice(&inv.to_be_bytes()[1..4]);
        out.extend_from_slice(&[length, channel, MARKER]);
        out.extend_from_slice(&crc.to_be_bytes());
        out
    }

    /// A synthetic image holding the record under test plus a couple of filler
    /// channels.
    ///
    /// The filler is not decoration: with 65 536 candidates against a 16-bit
    /// CRC, one record cannot pin the generation counter. Several channels
    /// agreeing is what makes it unambiguous.
    fn synthetic(channel: u8, payload: &[u8], generation: u32) -> Vec<u8> {
        let mut image = vec![0u8; 64]; // leading slack, so offsets are not zero
        image.extend_from_slice(&frame(channel, payload, generation));
        for filler in [0x70u8, 0x71, 0x72] {
            image.extend_from_slice(&frame(filler, &[filler; 8], generation));
        }
        image.extend_from_slice(&[0u8; 64]);
        image
    }

    #[test]
    fn parses_a_synthetic_record() {
        let payload: Vec<u8> = (0..24u8).collect();
        let dump = Dump::parse(synthetic(9, &payload, 0x057D));
        let rec = dump.latest(9).expect("channel 9 present");
        assert_eq!(rec.length, 3);
        assert_eq!(rec.data, payload);
        assert_eq!(dump.generation().map(|g| g.value), Some(0x057D));
    }

    /// The counter lives only in the CRCed trailer, so recovering it at all
    /// depends on the brute-force search agreeing with the CRC model.
    #[test]
    fn brute_forces_the_generation_counter() {
        let payload: Vec<u8> = (0..32u8).map(|b| b.wrapping_mul(7)).collect();
        let dump = Dump::parse(synthetic(0x20, &payload, 0x1234));
        let gen = dump.generation().expect("a counter is recoverable");
        assert_eq!(gen.value, 0x1234);
        assert_eq!(gen.source, GenerationSource::BruteForced);
        let rec = dump.latest(0x20).unwrap();
        assert!(dump.analyze(rec, None).outer_ok());
    }

    /// One record is one CRC's worth of evidence, not enough to pin a 16-bit
    /// counter. Guessing would silently mis-frame every record in the image.
    #[test]
    fn a_single_record_cannot_pin_the_counter() {
        let payload: Vec<u8> = (0..24u8).collect();
        let mut image = vec![0u8; 64];
        image.extend_from_slice(&frame(9, &payload, 0x057D));
        image.extend_from_slice(&[0u8; 64]);

        let dump = Dump::parse(image);
        assert_eq!(dump.records().len(), 1);
        assert_eq!(dump.generation(), None);
    }

    /// An encrypted `record_way 0` channel round-trips through a rewrite, with
    /// both the ciphertext and the outer CRC updated.
    #[test]
    fn rewrites_an_encrypted_record() {
        let keys = Hitag2Keys::from_device_id(&[
            0x44, 0x80, 0x05, 0x11, 0x18, 0xa0, 0x48, 0x29, 0x02, 0x0c, 0x00, 0x20,
        ]);
        let channel = 6u8;
        // Plaintext that trips `looks_decrypted`: leading 0xAA and plenty of
        // zeroes, exactly like a real immobilizer record.
        let mut plain = vec![0u8; 104];
        plain[0] = 0xAA;
        plain[1..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7]);
        plain[30..47].copy_from_slice(b"3VW4T7AU6GM041367");

        let cipher = crypt(&plain, &keys.key, &keys.iv, channel as u16);
        let mut dump = Dump::parse(synthetic(channel, &cipher, 0x057D));

        let before = dump.analyze_channel(channel, Some(&keys)).unwrap();
        assert!(before.encrypted, "the heuristic must spot the ciphertext");
        assert_eq!(before.content, plain);

        let mut edited = plain.clone();
        edited[30..47].copy_from_slice(b"WVWZZZ1KZAW000001");
        dump.rewrite_channel(channel, &edited, Some(&keys)).unwrap();

        let after = dump.analyze_channel(channel, Some(&keys)).unwrap();
        assert!(after.outer_ok(), "the outer CRC must be fixed up");
        assert_eq!(after.content, edited);
        assert!(after.encrypted);

        // And the bytes on disk really did change: this is not a no-op that
        // happens to read back the same way.
        let rec = dump.latest(channel).unwrap();
        assert_ne!(rec.data, cipher);
    }

    /// A plaintext `record_way 1` channel keeps its inner CRC prefix in step
    /// with the new content.
    #[test]
    fn rewrites_an_inner_crc_record() {
        let content = b"111SC8F0H800".to_vec();
        let mut payload = crc16_8005(INIT_INNER, &content).to_le_bytes().to_vec();
        payload.extend_from_slice(&content);
        payload.extend_from_slice(&[0u8; 2]); // plaintext fill out to 16 bytes

        let mut dump = Dump::parse(synthetic(1, &payload, 0x057D));
        let before = dump.analyze_channel(1, None).unwrap();
        assert_eq!(before.content, content);
        assert!(!before.encrypted);

        let edited = b"222SC8F0H800".to_vec();
        dump.rewrite_channel(1, &edited, None).unwrap();

        let after = dump.analyze_channel(1, None).unwrap();
        assert_eq!(after.content, edited);
        assert_eq!(after.inner_crc, Some(crc16_8005(INIT_INNER, &edited)));
        assert!(after.outer_ok());
    }

    /// Content of the wrong size must be refused rather than silently
    /// truncated: the record's FEE framing is fixed.
    #[test]
    fn refuses_content_of_the_wrong_size() {
        let payload: Vec<u8> = (0..24u8).collect();
        let mut dump = Dump::parse(synthetic(9, &payload, 0x057D));
        let err = dump.rewrite_channel(9, &[0u8; 4], None).unwrap_err();
        assert!(matches!(err, WriteError::WrongLength { .. }), "{err}");
        // And nothing was written.
        assert_eq!(dump.latest(9).unwrap().data, payload);
    }

    /// A record whose CRC does not validate has unknown framing, so it must not
    /// be rewritten on a guess.
    #[test]
    fn refuses_a_record_with_an_unrecoverable_framing() {
        let payload: Vec<u8> = (0..24u8).collect();
        let mut image = synthetic(9, &payload, 0x057D);
        // Corrupt the payload but leave the CRC fields alone, so the record is
        // still discoverable yet no longer validates. The filler channels keep
        // the counter recoverable, so this exercises the per-record check.
        image[64] ^= 0xFF;
        let mut dump = Dump::parse(image);
        assert_eq!(dump.generation().map(|g| g.value), Some(0x057D));

        let err = dump.rewrite_channel(9, &payload, None).unwrap_err();
        assert!(
            matches!(err, WriteError::UnknownAlignment { .. }),
            "expected the framing check to refuse it, got: {err}"
        );
    }

    /// Superseded copies of a channel stay in the image; the newest wins.
    #[test]
    fn the_newest_record_for_a_channel_wins() {
        let old: Vec<u8> = vec![0xAA; 8];
        let new: Vec<u8> = vec![0xBB; 8];
        let mut image = synthetic(4, &old, 0x0100);
        image.extend_from_slice(&frame(4, &new, 0x0100));
        let dump = Dump::parse(image);
        assert_eq!(dump.write_count(4), 2);
        assert_eq!(dump.latest(4).unwrap().data, new);
    }
}
