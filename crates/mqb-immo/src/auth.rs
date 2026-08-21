//! The immobilizer authentication protocol, and the master (cluster) emulator.
//!
//! The engine ECU is the immobilizer **slave**; the instrument cluster is the
//! **master**. They authenticate over two 8-byte CAN frames — the ECU asks on
//! `0x010`, the master answers on `0x011` — using one primitive throughout:
//!
//! ```text
//! word = CRC32( AES128-ECB( noKeySecu, MK ‖ idxTun ‖ operandA ‖ operandB ‖ domain ) )
//! ```
//!
//! Two values come out of it per exchange: `CrcSlave`, which the ECU sends, and
//! `CrcMaster`, which the ECU expects back. Each travels with its upper two
//! bytes XOR-masked by the sender's 2-byte PIN — `noKeySlave` one way,
//! `noKeyMst` the other.
//!
//! Three protocol variants use that primitive, differing in who contributes
//! entropy ([`Variant`]). The ECU tells them apart by a message-type byte, and
//! [`classify`] does the same.
//!
//! Everything a master needs comes out of the ECU's own encrypted NVRAM, which
//! already requires the Hitag2 Device-ID keys to read — so this is a bench
//! convenience, not a way around the immobilizer.
//!
//! Nothing here touches a bus: [`ImmoMaster::handle_request`] takes a frame and
//! returns a frame.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;

use mqb_nvcrypt::ImmoSecrets;

/// CAN identifier the ECU sends authentication requests on.
pub const CAN_ID_REQUEST: u32 = 0x010;

/// CAN identifier the master answers on.
pub const CAN_ID_RESPONSE: u32 = 0x011;

/// The fixed filler that stands in for an absent random in variant C.
///
/// It renders as ASCII "casc" in a decompiler, but it is not a string — the
/// bytes are built from `mov` immediates.
pub const FILLER: [u8; 4] = [0x63, 0x61, 0x73, 0x63];

/// The three hard-coded 4-byte master keys, selected by `idxLab`.
pub const MASTER_KEY_0D: [u8; 4] = [0xb3, 0xfe, 0x92, 0x96];
/// Master key for `idxLab == 0x10`.
pub const MASTER_KEY_10: [u8; 4] = [0x85, 0x41, 0x22, 0x3f];
/// Master key for every other `idxLab`.
pub const MASTER_KEY_OTHER: [u8; 4] = [0x9c, 0xf7, 0xfe, 0xb7];

/// Every master key, in the order the emulator tries them when `idxLab` is
/// unknown.
pub const MASTER_KEY_CANDIDATES: [[u8; 4]; 3] = [MASTER_KEY_0D, MASTER_KEY_10, MASTER_KEY_OTHER];

/// The 4-byte master key `idxLab` selects.
///
/// `idxLab` is production data from `strDatBasFazit`; it is *not* in the
/// immobilizer NVRAM record, so a dump alone cannot say which key applies. A
/// live ECU publishes it unauthenticated in DID `0x2ED`.
pub fn master_key_for_idx_lab(idx_lab: u8) -> [u8; 4] {
    match idx_lab {
        0x0D => MASTER_KEY_0D,
        0x10 => MASTER_KEY_10,
        _ => MASTER_KEY_OTHER,
    }
}

// ── The primitive ─────────────────────────────────────────────────────────────

/// Single-block AES-128-ECB encryption.
///
/// The firmware's S-box and round-constant tables are the standard ones, so
/// this is plain AES-128 with no vendor modification.
pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut buf = *block;
    cipher.encrypt_block((&mut buf).into());
    buf
}

/// The protocol's one derived value: `CRC32(AES128(noKeySecu, block))`, 4 bytes
/// little-endian.
///
/// The block is `MK ‖ idxTun ‖ operandA ‖ operandB ‖ domain` and must come to
/// exactly 16 bytes. `domain` is a per-message-type constant providing domain
/// separation, which is what stops one direction's value being replayed as the
/// other's.
pub fn auth_word(
    no_key_secu: &[u8; 16],
    mk: [u8; 4],
    idx_tun: u8,
    operand_a: &[u8],
    operand_b: &[u8],
    domain: &[u8],
) -> [u8; 4] {
    let mut block = [0u8; 16];
    block[0..4].copy_from_slice(&mk);
    block[4] = idx_tun;
    let mut at = 5;
    for part in [operand_a, operand_b, domain] {
        block[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    debug_assert_eq!(at, 16, "the authentication block must be exactly 16 bytes");

    let cipher = aes128_encrypt_block(no_key_secu, &block);
    crc32fast::hash(&cipher).to_le_bytes()
}

/// Which authentication variant an exchange is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Bidirectional: both sides contribute a random, over two rounds.
    A,
    /// Slave-driven: single shot, only the ECU contributes entropy.
    B,
    /// Master-driven: single shot, only the master contributes entropy, and the
    /// exchange is pipelined.
    C,
}

impl Variant {
    /// A short label for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Variant::A => "A (bidirectional)",
            Variant::B => "B (slave-driven)",
            Variant::C => "C (master-driven)",
        }
    }
}

/// `CrcMaster` — the value the ECU expects the master to produce.
pub fn crc_master(
    no_key_secu: &[u8; 16],
    mk: [u8; 4],
    idx_tun: u8,
    variant: Variant,
    rnd_slave: Option<[u8; 4]>,
    rnd_master: Option<[u8; 4]>,
) -> [u8; 4] {
    match variant {
        Variant::A => auth_word(
            no_key_secu,
            mk,
            idx_tun,
            &rnd_slave.expect("variant A needs the slave random"),
            &rnd_master.expect("variant A needs the master random"),
            &[0x0c, 0x0d, 0x0e],
        ),
        Variant::B => {
            // The two directions are separated by using the random and its
            // bitwise complement.
            let rs = rnd_slave.expect("variant B needs the slave random");
            let inverted = rs.map(|b| b ^ 0xFF);
            auth_word(
                no_key_secu,
                mk,
                idx_tun,
                &inverted,
                &[0x08, 0x09, 0x0a, 0x0b],
                &[0x0c, 0x0d, 0x0e],
            )
        }
        Variant::C => auth_word(
            no_key_secu,
            mk,
            idx_tun,
            &FILLER,
            &rnd_master.expect("variant C needs the master random"),
            &[0x0f, 0x10, 0x11],
        ),
    }
}

/// `CrcSlave` — the value the ECU itself produces.
pub fn crc_slave(
    no_key_secu: &[u8; 16],
    mk: [u8; 4],
    idx_tun: u8,
    variant: Variant,
    rnd_slave: Option<[u8; 4]>,
    rnd_master: Option<[u8; 4]>,
) -> [u8; 4] {
    match variant {
        Variant::A => auth_word(
            no_key_secu,
            mk,
            idx_tun,
            &rnd_master.expect("variant A needs the master random"),
            &rnd_slave.expect("variant A needs the slave random"),
            &[0x05, 0x06, 0x07],
        ),
        Variant::B => auth_word(
            no_key_secu,
            mk,
            idx_tun,
            &rnd_slave.expect("variant B needs the slave random"),
            &[0x01, 0x02, 0x03, 0x04],
            &[0x05, 0x06, 0x07],
        ),
        Variant::C => auth_word(
            no_key_secu,
            mk,
            idx_tun,
            &rnd_master.expect("variant C needs the master random"),
            &FILLER,
            &[0x11, 0x12, 0x13],
        ),
    }
}

/// Guess the variant and round from an 8-byte ECU request frame.
///
/// Variants A and C carry a message-type byte in `[0]` and zeros in `[5..7]`;
/// variant B has no type byte at all — its `[0..4]` are the ECU's random — so
/// it is what anything else must be.
pub fn classify(frame: &[u8; 8]) -> (Variant, u8) {
    if frame[5] == 0 && frame[6] == 0 {
        match frame[0] {
            0x01 => return (Variant::A, 1),
            0x02 => return (Variant::A, 2),
            0x03 => return (Variant::C, 1),
            _ => {}
        }
    }
    (Variant::B, 1)
}

// ── The ECU's verdict ─────────────────────────────────────────────────────────

/// Released: `bAuthVld && bFctEna && !bLock`.
pub const ECU_ST_RELEASED: u8 = 0x01;
/// `bMstKeyVld` — the PIN mask in our reply matched.
pub const ECU_ST_KEY_VALID: u8 = 0x02;
/// `bMstCksVld` — the `CrcMaster` in our reply matched.
pub const ECU_ST_CKS_VALID: u8 = 0x04;

/// One line summarising the ECU's status byte.
pub fn describe_ecu_status(status: Option<u8>) -> String {
    let Some(st) = status else {
        return "unknown — no status-bearing frame seen yet (variant B requests never carry one)"
            .to_string();
    };
    let flags: Vec<&str> = [
        (ECU_ST_CKS_VALID, "bMstCksVld"),
        (ECU_ST_KEY_VALID, "bMstKeyVld"),
        (ECU_ST_RELEASED, "released"),
    ]
    .into_iter()
    .filter(|(bit, _)| st & bit != 0)
    .map(|(_, name)| name)
    .collect();
    let state = if st & ECU_ST_RELEASED != 0 {
        "UNLOCKED"
    } else {
        "LOCKED"
    };
    let detail = if flags.is_empty() {
        "nothing verified".to_string()
    } else {
        flags.join(" ")
    };
    format!("{state}  st={st:02X} [{detail}]")
}

/// Why the ECU is not released, or `None` if it is.
pub fn ecu_status_hint(status: Option<u8>) -> Option<&'static str> {
    let st = status?;
    if st & ECU_ST_RELEASED != 0 {
        return None;
    }
    if st & ECU_ST_CKS_VALID == 0 {
        return Some("CrcMaster rejected — wrong noKeySecu, master key (idxLab) or idxTun");
    }
    if st & ECU_ST_KEY_VALID == 0 {
        return Some("CrcMaster accepted, PIN mask rejected — wrong noKeyMst");
    }
    Some(
        "master fully verified but the ECU is still held: check bLock, ImoIf_bFctEna, and bit 0 \
         of byte 7 in a variant B/C reply",
    )
}

// ── The master ────────────────────────────────────────────────────────────────

/// Source of the master's 4-byte randoms.
///
/// Behind a trait so tests can pin the randoms and reproduce an exchange
/// exactly.
pub trait MasterRng: Send {
    fn next_random(&mut self) -> [u8; 4];
}

/// The real thing.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl MasterRng for OsRandom {
    fn next_random(&mut self) -> [u8; 4] {
        rand::random()
    }
}

/// A fixed sequence, cycled. For tests and for reproducing a captured exchange.
#[derive(Debug, Clone)]
pub struct FixedRng {
    values: Vec<[u8; 4]>,
    next: usize,
}

impl FixedRng {
    pub fn new(values: Vec<[u8; 4]>) -> Self {
        assert!(!values.is_empty(), "FixedRng needs at least one value");
        Self { values, next: 0 }
    }
}

impl MasterRng for FixedRng {
    fn next_random(&mut self) -> [u8; 4] {
        let value = self.values[self.next % self.values.len()];
        self.next += 1;
        value
    }
}

/// One line of narration from the emulator, for the UI's frame log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterEvent {
    pub message: String,
    /// True for lines that report a problem rather than progress.
    pub is_problem: bool,
}

/// Stateful emulation of the immobilizer master (instrument cluster).
///
/// Feed it each 8-byte request the ECU sends on [`CAN_ID_REQUEST`]; it returns
/// the reply to send on [`CAN_ID_RESPONSE`], or `None` when no reply is due.
///
/// # Resolving `idxLab` without being told
///
/// `idxLab` selects the master key but is not in the NVRAM record. Two
/// mechanisms narrow it:
///
/// * The ECU's status byte says whether the `CrcMaster` we sent was accepted,
///   so a rejected candidate is dropped and the next tried; three candidates
///   converge within three exchanges.
/// * In variant A round 2 and in variant B the ECU transmits `CrcSlave[0..2]`
///   unmasked, so a master holding `noKeySecu` and `idxTun` can compute the same
///   value under each candidate and keep whichever matches — recovering
///   `noKeySlave` from the masked half as a by-product.
///
/// Against a live ECU none of this is needed: read `idxLab` from DID `0x2ED`.
pub struct ImmoMaster {
    no_key_secu: [u8; 16],
    no_key_mst: [u8; 2],
    idx_tun: u8,
    candidates: Vec<[u8; 4]>,
    rng: Box<dyn MasterRng>,
    rnd_master: Option<[u8; 4]>,
    rnd_slave: Option<[u8; 4]>,
    variant: Option<Variant>,
    no_key_slave: Option<[u8; 2]>,
    ecu_status: Option<u8>,
    mk_confirmed: bool,
    awaiting_verdict: bool,
    exhausted_keys: bool,
    exchanges: u32,
    /// Narration since the caller last drained it.
    pub log: Vec<MasterEvent>,
}

impl std::fmt::Debug for ImmoMaster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImmoMaster")
            .field("idx_tun", &self.idx_tun)
            .field("candidates", &self.candidates.len())
            .field("variant", &self.variant)
            .field("ecu_status", &self.ecu_status)
            .field("mk_confirmed", &self.mk_confirmed)
            .field("exchanges", &self.exchanges)
            .finish_non_exhaustive()
    }
}

impl ImmoMaster {
    /// Build a master from an immobilizer record's secrets.
    ///
    /// `mk` is the 4-byte master key when it is known (read `idxLab` from DID
    /// `0x2ED` and pass [`master_key_for_idx_lab`]); `None` starts with all
    /// three candidates and narrows them from the ECU's own traffic.
    pub fn new(secrets: &ImmoSecrets, mk: Option<[u8; 4]>) -> Self {
        Self::with_rng(secrets, mk, Box::new(OsRandom))
    }

    /// As [`ImmoMaster::new`], with the randoms supplied by `rng`.
    pub fn with_rng(secrets: &ImmoSecrets, mk: Option<[u8; 4]>, rng: Box<dyn MasterRng>) -> Self {
        Self {
            no_key_secu: secrets.no_key_secu,
            no_key_mst: secrets.no_key_mst.to_be_bytes(),
            idx_tun: secrets.idx_tun,
            candidates: mk.map_or_else(|| MASTER_KEY_CANDIDATES.to_vec(), |k| vec![k]),
            rng,
            rnd_master: None,
            rnd_slave: None,
            variant: None,
            no_key_slave: None,
            ecu_status: None,
            mk_confirmed: false,
            awaiting_verdict: false,
            exhausted_keys: false,
            exchanges: 0,
            log: Vec::new(),
        }
    }

    /// The master key currently in use.
    pub fn master_key(&self) -> [u8; 4] {
        self.candidates[0]
    }

    /// The master key, once only one candidate is left.
    pub fn master_key_resolved(&self) -> Option<[u8; 4]> {
        (self.candidates.len() == 1).then(|| self.candidates[0])
    }

    /// Whether the ECU has accepted a `CrcMaster` from us, which confirms the
    /// key in use.
    pub fn master_key_confirmed(&self) -> bool {
        self.mk_confirmed
    }

    /// `noKeySlave`, recovered from an ECU reply. Not needed to authenticate —
    /// it only protects the ECU→master direction — but it proves the crypto chain.
    pub fn no_key_slave(&self) -> Option<[u8; 2]> {
        self.no_key_slave
    }

    /// The variant the ECU is using, once a frame has been seen.
    pub fn variant(&self) -> Option<Variant> {
        self.variant
    }

    /// The ECU's most recent status byte.
    pub fn ecu_status(&self) -> Option<u8> {
        self.ecu_status
    }

    /// How many requests have been answered.
    pub fn exchanges(&self) -> u32 {
        self.exchanges
    }

    /// Whether the ECU has reported itself released.
    pub fn authenticated(&self) -> bool {
        self.ecu_status.is_some_and(|st| st & ECU_ST_RELEASED != 0)
    }

    /// One line describing where the ECU stands.
    pub fn status_line(&self) -> String {
        format!("immobilizer: {}", describe_ecu_status(self.ecu_status))
    }

    /// Take the narration accumulated since the last call.
    pub fn drain_log(&mut self) -> Vec<MasterEvent> {
        std::mem::take(&mut self.log)
    }

    fn note(&mut self, message: impl Into<String>) {
        self.log.push(MasterEvent {
            message: message.into(),
            is_problem: false,
        });
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.log.push(MasterEvent {
            message: message.into(),
            is_problem: true,
        });
    }

    /// A new master random, guaranteed to differ from the previous one: variant
    /// A round 2 and variant C reject an equal pair as a replay.
    ///
    /// `status_bit` forces the low bit of the last byte, which variant C needs —
    /// there byte 7 is both the last random byte and the master status word, and
    /// `bAuthVld` tests bit 0 of it.
    fn fresh_random(&mut self, status_bit: bool) -> [u8; 4] {
        let mut r = self.rng.next_random();
        if status_bit {
            r[3] |= ECU_ST_RELEASED;
        }
        if Some(r) == self.rnd_master {
            r[0] ^= 0x01;
        }
        r
    }

    /// `CrcMaster` with its top two bytes XOR-masked by `noKeyMst`.
    fn mask(&self, cm: [u8; 4]) -> [u8; 4] {
        [
            cm[0],
            cm[1],
            cm[2] ^ self.no_key_mst[0],
            cm[3] ^ self.no_key_mst[1],
        ]
    }

    /// Record the ECU's verdict on the reply we last sent, and rotate the
    /// master-key candidate when it says the `CrcMaster` was wrong.
    fn note_status(&mut self, st: u8) {
        if Some(st) != self.ecu_status {
            let line = describe_ecu_status(Some(st));
            self.note(line);
            if let Some(hint) = ecu_status_hint(Some(st)) {
                if self.ecu_status.is_some() {
                    self.warn(hint);
                }
            }
        }
        self.ecu_status = Some(st);

        if !self.awaiting_verdict {
            return; // Nothing of ours has been judged yet.
        }
        self.awaiting_verdict = false;

        if st & ECU_ST_CKS_VALID != 0 {
            self.mk_confirmed = true;
        } else if self.candidates.len() > 1 {
            let dropped = self.candidates.remove(0);
            let next = self.candidates[0];
            self.note(format!(
                "master key {} rejected, trying {}",
                hex(&dropped),
                hex(&next)
            ));
        } else if !self.exhausted_keys {
            self.exhausted_keys = true;
            self.warn("every master key was rejected — check noKeySecu and idxTun");
        }
    }

    /// Narrow the master-key candidates against the ECU's own `CrcSlave`, whose
    /// low two bytes travel unmasked, and recover `noKeySlave` from the rest.
    fn observe_slave_response(
        &mut self,
        cs_low: [u8; 2],
        cs_masked: [u8; 2],
        rnd_slave: Option<[u8; 4]>,
        rnd_master: Option<[u8; 4]>,
    ) {
        let variant = match self.variant {
            Some(v) => v,
            None => return,
        };
        let survivors: Vec<([u8; 4], [u8; 4])> = self
            .candidates
            .iter()
            .map(|&cand| {
                (
                    cand,
                    crc_slave(
                        &self.no_key_secu,
                        cand,
                        self.idx_tun,
                        variant,
                        rnd_slave,
                        rnd_master,
                    ),
                )
            })
            .filter(|(_, cs)| cs[0] == cs_low[0] && cs[1] == cs_low[1])
            .collect();

        if survivors.is_empty() {
            self.warn(
                "CrcSlave matched no master key — stale randoms, or a wrong noKeySecu / idxTun",
            );
            return;
        }

        self.candidates = survivors.iter().map(|(c, _)| *c).collect();
        if let [(_, cs)] = survivors[..] {
            let recovered = [cs[2] ^ cs_masked[0], cs[3] ^ cs_masked[1]];
            self.no_key_slave = Some(recovered);
            let mk = hex(&self.candidates[0]);
            self.note(format!(
                "locked master key {mk}, recovered noKeySlave {}",
                hex(&recovered)
            ));
        }
    }

    /// Consume one ECU→master frame and produce the master→ECU reply.
    pub fn handle_request(&mut self, frame: &[u8; 8]) -> Option<[u8; 8]> {
        let (variant, round) = classify(frame);
        self.variant = Some(variant);
        self.exchanges += 1;

        match (variant, round) {
            // Round 1: the ECU published its random; our reply carries ours and
            // the response over both. Byte 7 is the last random byte, not a
            // status word — variant A is the one path where bAuthVld does not
            // test RX[7] & 1.
            (Variant::A, 1) => {
                let rs = take4(&frame[1..5]);
                self.rnd_slave = Some(rs);
                let rm = self.fresh_random(false);
                self.rnd_master = Some(rm);
                let cm = crc_master(
                    &self.no_key_secu,
                    self.master_key(),
                    self.idx_tun,
                    Variant::A,
                    Some(rs),
                    Some(rm),
                );
                self.awaiting_verdict = true;
                Some(join(self.mask(cm), rm))
            }

            // Round 2: the ECU is proving itself, and byte 7 is its verdict on
            // our last reply. Bytes 1..3 hold a real CrcSlave only once it has
            // released; otherwise they are fresh randoms.
            (Variant::A, _) => {
                self.note_status(frame[7]);
                if let (Some(rs), Some(rm)) = (self.rnd_slave, self.rnd_master) {
                    if frame[7] & ECU_ST_RELEASED != 0 {
                        self.observe_slave_response(
                            [frame[1], frame[2]],
                            [frame[3], frame[4]],
                            Some(rs),
                            Some(rm),
                        );
                    }
                }
                None
            }

            // Only the ECU has a random, so byte 7 of our reply is purely the
            // master status word and its bit 0 must be set for bAuthVld.
            // Variant B requests carry no status byte of their own, so the
            // CrcSlave in them is always real.
            (Variant::B, _) => {
                let rs = take4(&frame[0..4]);
                self.rnd_slave = Some(rs);
                self.observe_slave_response(
                    [frame[4], frame[5]],
                    [frame[6], frame[7]],
                    Some(rs),
                    None,
                );
                let cm = crc_master(
                    &self.no_key_secu,
                    self.master_key(),
                    self.idx_tun,
                    Variant::B,
                    Some(rs),
                    None,
                );
                self.awaiting_verdict = true;
                let masked = self.mask(cm);
                Some([
                    masked[0],
                    masked[1],
                    masked[2],
                    masked[3],
                    0,
                    0,
                    0,
                    ECU_ST_RELEASED | ECU_ST_KEY_VALID | ECU_ST_CKS_VALID,
                ])
            }

            // Pipelined: byte 7 judges the previous reply and bytes 1..5 answer
            // that same exchange, while our reply carries the next random in
            // bytes 4..8, where byte 7 doubles as the status word.
            (Variant::C, _) => {
                self.note_status(frame[7]);
                if let Some(rm) = self.rnd_master {
                    if frame[7] & ECU_ST_RELEASED != 0 {
                        self.observe_slave_response(
                            [frame[1], frame[2]],
                            [frame[3], frame[4]],
                            None,
                            Some(rm),
                        );
                    }
                }
                let rm = self.fresh_random(true);
                self.rnd_master = Some(rm);
                let cm = crc_master(
                    &self.no_key_secu,
                    self.master_key(),
                    self.idx_tun,
                    Variant::C,
                    None,
                    Some(rm),
                );
                self.awaiting_verdict = true;
                Some(join(self.mask(cm), rm))
            }
        }
    }
}

fn take4(slice: &[u8]) -> [u8; 4] {
    slice.try_into().expect("a 4-byte window")
}

fn join(a: [u8; 4], b: [u8; 4]) -> [u8; 8] {
    [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mqb_nvcrypt::{ImmoRecord, StStatFct};

    /// The reference NVRAM record from NVCRYPT.md.
    fn secrets() -> ImmoSecrets {
        ImmoSecrets {
            no_key_secu: [
                0x59, 0x67, 0xF8, 0xFB, 0xF7, 0xAF, 0x63, 0x4F, 0x17, 0xCF, 0x78, 0x65, 0xF1, 0x83,
                0x24, 0xC3,
            ],
            no_key_mst: 0x2735,
            idx_tun: 0x6A,
            vin: "1VWAT7A31FC022915".into(),
            ct_dat_bas_fazit: 1,
            st_stat_fct: StStatFct::Adapted,
            b_auth_mute: false,
            b_vld_chk_di: false,
            b_trig_fct_di: false,
            b_lim_mod_ena: false,
            b_lock: false,
            b_inh_acs_mem: true,
            channel: None,
        }
    }

    fn fixed(values: &[[u8; 4]]) -> Box<dyn MasterRng> {
        Box::new(FixedRng::new(values.to_vec()))
    }

    /// FIPS-197 C.1. The cipher is the library's, so this pins our wiring of
    /// it — key and block byte order in particular.
    #[test]
    fn aes_fips197_vector() {
        let key: [u8; 16] = std::array::from_fn(|i| i as u8);
        let block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(
            aes128_encrypt_block(&key, &block),
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
    }

    #[test]
    fn master_key_selection() {
        assert_eq!(master_key_for_idx_lab(0x0D), MASTER_KEY_0D);
        assert_eq!(master_key_for_idx_lab(0x10), MASTER_KEY_10);
        assert_eq!(master_key_for_idx_lab(0x00), MASTER_KEY_OTHER);
        assert_eq!(master_key_for_idx_lab(0xFF), MASTER_KEY_OTHER);
    }

    #[test]
    fn classifies_each_variant() {
        assert_eq!(classify(&[0x01, 1, 2, 3, 4, 0, 0, 0]), (Variant::A, 1));
        assert_eq!(classify(&[0x02, 1, 2, 3, 4, 0, 0, 7]), (Variant::A, 2));
        assert_eq!(classify(&[0x03, 1, 2, 3, 4, 0, 0, 7]), (Variant::C, 1));
        // No type byte and a full frame: variant B.
        assert_eq!(
            classify(&[0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4]),
            (Variant::B, 1)
        );
        // A type byte but non-zero [5..7] is still variant B.
        assert_eq!(classify(&[0x01, 1, 2, 3, 4, 9, 9, 0]), (Variant::B, 1));
    }

    /// A variant A reply must satisfy the ECU's own verification, re-implemented
    /// here from the firmware rather than reusing our helper's output.
    #[test]
    fn variant_a_reply_satisfies_the_ecus_check() {
        let s = secrets();
        let mut m = ImmoMaster::with_rng(
            &s,
            Some(MASTER_KEY_OTHER),
            fixed(&[[0x11, 0x22, 0x33, 0x44]]),
        );
        let rs = [0xaa, 0xbb, 0xcc, 0xdd];
        let reply = m
            .handle_request(&[0x01, rs[0], rs[1], rs[2], rs[3], 0, 0, 0])
            .expect("round 1 gets a reply");

        let rm = take4(&reply[4..8]);
        let cm = crc_master(
            &s.no_key_secu,
            MASTER_KEY_OTHER,
            s.idx_tun,
            Variant::A,
            Some(rs),
            Some(rm),
        );
        // bMstCksVld
        assert_eq!(reply[0], cm[0]);
        assert_eq!(reply[1], cm[1]);
        // bMstKeyVld
        assert_eq!(reply[2], cm[2] ^ (s.no_key_mst >> 8) as u8);
        assert_eq!(reply[3], cm[3] ^ (s.no_key_mst & 0xFF) as u8);
    }

    /// Consecutive master randoms must differ, or variant A round 2 and
    /// variant C reject the exchange as a replay.
    #[test]
    fn master_randoms_are_never_repeated() {
        let s = secrets();
        // An RNG that always returns the same value — the worst case the
        // freshness guard exists for.
        let mut m = ImmoMaster::with_rng(&s, Some(MASTER_KEY_OTHER), fixed(&[[7, 7, 7, 7]]));
        let mut seen = Vec::new();
        for _ in 0..8 {
            let reply = m
                .handle_request(&[0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0])
                .unwrap();
            seen.push(take4(&reply[4..8]));
        }
        assert!(
            seen.windows(2).all(|w| w[0] != w[1]),
            "a repeated master random would be rejected as a replay: {seen:?}"
        );
    }

    /// Variant C overloads byte 7: it is the last random byte *and* the master
    /// status word, and `bAuthVld` tests bit 0 — so it must never come out even,
    /// whatever the RNG says.
    #[test]
    fn variant_c_forces_the_status_bit() {
        let s = secrets();
        let mut m = ImmoMaster::with_rng(&s, Some(MASTER_KEY_OTHER), fixed(&[[0, 0, 0, 0]]));
        let reply = m.handle_request(&[0x03, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(reply[7] & ECU_ST_RELEASED, ECU_ST_RELEASED);
    }

    /// Variant B's reply carries the status word in byte 7, with bit 0 set, and
    /// derives CrcMaster from the *complement* of the ECU's random.
    #[test]
    fn variant_b_reply_shape() {
        let s = secrets();
        let mut m = ImmoMaster::new(&s, Some(MASTER_KEY_OTHER));
        let rs = [0xaa, 0xbb, 0xcc, 0xdd];
        let frame = [rs[0], rs[1], rs[2], rs[3], 0x11, 0x22, 0x33, 0x44];
        let reply = m.handle_request(&frame).unwrap();

        let cm = crc_master(
            &s.no_key_secu,
            MASTER_KEY_OTHER,
            s.idx_tun,
            Variant::B,
            Some(rs),
            None,
        );
        assert_eq!(reply[0], cm[0]);
        assert_eq!(reply[1], cm[1]);
        assert_eq!(reply[2], cm[2] ^ 0x27);
        assert_eq!(reply[3], cm[3] ^ 0x35);
        assert_eq!(&reply[4..7], &[0, 0, 0]);
        assert_ne!(reply[7] & ECU_ST_RELEASED, 0, "bit 0 gates bAuthVld");
    }

    /// A master that does not know `idxLab` must recover it from the ECU's own
    /// CrcSlave bytes, and get `noKeySlave` for free.
    #[test]
    fn recovers_the_master_key_and_no_key_slave_from_traffic() {
        let s = secrets();
        let truth_mk = MASTER_KEY_10;
        let truth_ks = [0x9e, 0x42];

        let mut m = ImmoMaster::with_rng(&s, None, fixed(&[[0x11, 0x22, 0x33, 0x44]]));
        let rs = [0xaa, 0xbb, 0xcc, 0xdd];
        let r1 = m
            .handle_request(&[0x01, rs[0], rs[1], rs[2], rs[3], 0, 0, 0])
            .unwrap();
        let rm = take4(&r1[4..8]);

        // The ECU replies as a released variant-A slave would.
        let cs = crc_slave(
            &s.no_key_secu,
            truth_mk,
            s.idx_tun,
            Variant::A,
            Some(rs),
            Some(rm),
        );
        m.handle_request(&[
            0x02,
            cs[0],
            cs[1],
            cs[2] ^ truth_ks[0],
            cs[3] ^ truth_ks[1],
            0,
            0,
            0x07,
        ]);

        assert_eq!(m.master_key_resolved(), Some(truth_mk));
        assert_eq!(m.no_key_slave(), Some(truth_ks));
        assert!(m.authenticated());
        assert!(m.master_key_confirmed());
    }

    /// A rejected CrcMaster must move the emulator on to the next candidate
    /// rather than stalling on the first.
    #[test]
    fn rotates_the_master_key_when_the_ecu_rejects_it() {
        let s = secrets();
        let mut m = ImmoMaster::with_rng(&s, None, fixed(&[[1, 2, 3, 4]]));
        let first = m.master_key();

        m.handle_request(&[0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0]);
        // bMstCksVld clear: our CrcMaster was wrong.
        m.handle_request(&[0x02, 0, 0, 0, 0, 0, 0, ECU_ST_KEY_VALID]);

        assert_ne!(m.master_key(), first);
        assert!(!m.master_key_confirmed());
        assert!(!m.authenticated());

        // ... and a released status confirms the key and reads as unlocked.
        m.handle_request(&[0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0]);
        m.handle_request(&[0x02, 0, 0, 0, 0, 0, 0, 0x07]);
        assert!(m.master_key_confirmed());
        assert!(m.authenticated());
    }

    /// Running out of candidates has to say so, once, rather than silently
    /// retrying the last one forever.
    #[test]
    fn reports_when_every_master_key_is_rejected() {
        let s = secrets();
        let mut m = ImmoMaster::with_rng(&s, None, fixed(&[[1, 2, 3, 4]]));
        for _ in 0..4 {
            m.handle_request(&[0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0]);
            m.handle_request(&[0x02, 0, 0, 0, 0, 0, 0, 0x00]);
        }
        let log = m.drain_log();
        let exhausted: Vec<_> = log
            .iter()
            .filter(|e| e.message.contains("every master key"))
            .collect();
        assert_eq!(exhausted.len(), 1, "said once, not once per exchange");
        assert!(exhausted[0].is_problem);
    }

    /// The status decoders must name the right culprit, because that is what a
    /// user acts on.
    #[test]
    fn status_hints_name_the_culprit() {
        assert!(describe_ecu_status(Some(0x07)).starts_with("UNLOCKED"));
        assert_eq!(ecu_status_hint(Some(0x07)), None);

        assert!(describe_ecu_status(Some(0x00)).starts_with("LOCKED"));
        assert!(ecu_status_hint(Some(0x00)).unwrap().contains("noKeySecu"));
        assert!(ecu_status_hint(Some(ECU_ST_CKS_VALID))
            .unwrap()
            .contains("noKeyMst"));
        assert!(ecu_status_hint(Some(ECU_ST_CKS_VALID | ECU_ST_KEY_VALID))
            .unwrap()
            .contains("bLock"));
        assert!(describe_ecu_status(None).contains("no status-bearing frame"));
    }

    /// The secrets a master needs come straight out of a decoded record.
    #[test]
    fn builds_from_a_decoded_record() {
        let hex = "AAC985528F0000D43A0000F88B005967F8FBF7AF634F17CF7865F18324C3\
                   3156574154374133314643303232393135016AAA2735000000\
                   00A5050000030000 00BF80";
        let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let bytes: Vec<u8> = (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect();
        let record = ImmoRecord::decode(&bytes).unwrap();
        assert!(record.dat_dat_crc_ok());

        let master = ImmoMaster::new(&record.secrets(), Some(MASTER_KEY_OTHER));
        assert_eq!(master.master_key(), MASTER_KEY_OTHER);
        assert!(!master.authenticated());
    }
}
