//! Shared J2534 04.04 PassThru wire types, function-pointer signatures,
//! and helper utilities used by both [`super::j2534_adapter`] (raw CAN) and
//! [`super::j2534_isotp_adapter`] (native ISO 15765).

// ── PASSTHRU_MSG ───────────────────────────────────────────────────────────

/// Identical layout to `PASSTHRU_MSG` in the SAE J2534 04.04 specification.
///
/// `repr(C)` with natural alignment.  Because every field before `data` is a
/// `u32` at a 4-byte-aligned offset the binary layout is the same as
/// `repr(C, packed(1))`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PassThruMsg {
    pub protocol_id: u32,
    pub rx_status: u32,
    pub tx_flags: u32,
    pub timestamp: u32,
    pub data_size: u32,
    pub extra_data_index: u32,
    pub data: [u8; 4128],
}

impl Default for PassThruMsg {
    fn default() -> Self {
        // SAFETY: all-zero bytes are valid for this POD struct.
        unsafe { std::mem::zeroed() }
    }
}

impl PassThruMsg {
    /// Build a message carrying `payload` after a 4-byte big-endian CAN ID.
    /// Used for both `PROTOCOL_CAN` and `PROTOCOL_ISO15765` frames.
    pub fn new(protocol_id: u32, can_id: u32, payload: &[u8]) -> Self {
        let id_bytes = can_id.to_be_bytes();
        let mut data = [0u8; 4128];
        data[..4].copy_from_slice(&id_bytes);
        data[4..4 + payload.len()].copy_from_slice(payload);
        let data_size = (4 + payload.len()) as u32;
        Self {
            protocol_id,
            data,
            data_size,
            extra_data_index: data_size,
            ..Default::default()
        }
    }
}

// ── SCONFIG / SCONFIG_LIST ─────────────────────────────────────────────────

/// Single parameter entry passed to `PassThruIoctl(SET_CONFIG, …)`.
#[repr(C)]
pub struct SConfig {
    pub parameter: u32,
    pub value: u32,
}

/// Header block for `PassThruIoctl(SET_CONFIG, …)`.
#[repr(C)]
pub struct SConfigList {
    pub num_of_params: u32,
    pub config_ptr: *mut SConfig,
}

// ── Constants ──────────────────────────────────────────────────────────────

pub const STATUS_NOERROR: i32 = 0x00;
pub const ERR_BUFFER_EMPTY: i32 = 0x10;
pub const ERR_TIMEOUT: i32 = 0x09;

/// `PassThruIoctl` IOCTL ID for reading/writing channel configuration.
pub const IOCTL_SET_CONFIG: u32 = 0x04;

// ── Helper ─────────────────────────────────────────────────────────────────

/// Call `PassThruIoctl(SET_CONFIG)` with a single `(parameter, value)` pair.
///
/// Returns the raw J2534 status code.
pub fn set_config(
    ioctl_fn: FnPassThruIoctl,
    channel_id: u32,
    parameter: u32,
    value: u32,
) -> i32 {
    let mut cfg = SConfig { parameter, value };
    let mut list = SConfigList { num_of_params: 1, config_ptr: &mut cfg };
    unsafe {
        ioctl_fn(
            channel_id,
            IOCTL_SET_CONFIG,
            &mut list as *mut SConfigList as *mut _,
            std::ptr::null_mut(),
        )
    }
}

// ── Function-pointer signatures ────────────────────────────────────────────

pub type FnPassThruOpen =
    unsafe extern "system" fn(*const u8, *mut u32) -> i32;
pub type FnPassThruClose =
    unsafe extern "system" fn(u32) -> i32;
pub type FnPassThruConnect =
    unsafe extern "system" fn(u32, u32, u32, u32, *mut u32) -> i32;
pub type FnPassThruDisconnect =
    unsafe extern "system" fn(u32) -> i32;
pub type FnPassThruReadMsgs =
    unsafe extern "system" fn(u32, *mut PassThruMsg, *mut u32, u32) -> i32;
pub type FnPassThruWriteMsgs =
    unsafe extern "system" fn(u32, *mut PassThruMsg, *mut u32, u32) -> i32;
pub type FnPassThruStartMsgFilter =
    unsafe extern "system" fn(
        u32,
        u32,
        *const PassThruMsg,
        *const PassThruMsg,
        *const PassThruMsg,
        *mut u32,
    ) -> i32;
pub type FnPassThruIoctl =
    unsafe extern "system" fn(u32, u32, *mut std::ffi::c_void, *mut std::ffi::c_void) -> i32;

// ── Diagnostics ────────────────────────────────────────────────────────────

pub fn status_str(ret: i32) -> &'static str {
    match ret {
        0x00 => "STATUS_NOERROR",
        0x01 => "ERR_NOT_SUPPORTED",
        0x02 => "ERR_INVALID_CHANNEL_ID",
        0x03 => "ERR_INVALID_PROTOCOL_ID",
        0x04 => "ERR_NULL_PARAMETER",
        0x05 => "ERR_INVALID_IOCTL_VALUE",
        0x06 => "ERR_INVALID_FLAGS",
        0x07 => "ERR_FAILED",
        0x08 => "ERR_DEVICE_NOT_CONNECTED",
        0x09 => "ERR_TIMEOUT",
        0x0A => "ERR_INVALID_MSG",
        0x0B => "ERR_INVALID_TIME_INTERVAL",
        0x0C => "ERR_EXCEEDED_LIMIT",
        0x0D => "ERR_INVALID_MSG_ID",
        0x0E => "ERR_DEVICE_IN_USE",
        0x0F => "ERR_INVALID_IOCTL_ID",
        0x10 => "ERR_BUFFER_EMPTY",
        0x11 => "ERR_BUFFER_FULL",
        0x12 => "ERR_BUFFER_OVERFLOW",
        0x13 => "ERR_PIN_INVALID",
        0x14 => "ERR_CHANNEL_IN_USE",
        0x15 => "ERR_MSG_PROTOCOL_ID",
        0x16 => "ERR_INVALID_FILTER_ID",
        0x17 => "ERR_NO_FLOW_CONTROL",
        0x18 => "ERR_NOT_UNIQUE",
        0x19 => "ERR_INVALID_BAUDRATE",
        0x1A => "ERR_INVALID_DEVICE_ID",
        _    => "ERR_UNKNOWN",
    }
}
