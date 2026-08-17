//! mqb-immo — the Simos18 immobilizer bench tool.
//!
//! Four things, one window:
//!
//! * **Live state** — read the immobilizer's status DIDs. Unauthenticated, so
//!   it works against any ECU on the bus with no keys and no dump.
//! * **Master emulator** — play the instrument cluster on CAN `0x010`/`0x011`
//!   so a bench ECU releases without patching the immobilizer out.
//! * **Identity** — write a record over UDS: a transplant, a power class, or a
//!   VIN.
//! * **DFlash** — decrypt an NVRAM image, inspect every channel, and write an
//!   edited immobilizer record back.
//!
//! Design rules, in priority order:
//!
//! * **Nothing is written that the user did not see first.** Every write shows
//!   the plaintext record, the ciphertext, the exact request bytes and the
//!   result of every check, and needs an explicit confirmation.
//! * **A check that could not run says so.** An unread DID is reported as
//!   unverified, never as a pass — the same fail-open rule the flash wizard
//!   uses, and for the same reason: a confident wrong verdict about whether a
//!   car will start is worse than no verdict.
//! * **Consequences are stated before the fact, not after.** Every download
//!   leaves the ECU in adaptation mode; an interface behind the gateway cannot
//!   finish the job. Both are on screen before the button is live.
//! * **Keys come from the ECU's own NVRAM.** Reading that already needs the
//!   Hitag2 Device-ID keys, so this is bench convenience, not a bypass.
//!
//! Everything here is Simos18-only: the research behind it covers no other
//! module, and [`mqb_immo::state::ImmoSupport`] enforces that.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod connection;
mod secrets;
mod state;
mod theme;
mod view;
mod view_dflash;
mod view_identity;
mod view_live;
mod view_master;
mod view_secrets;
mod widgets;

use iced::Subscription;

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive("mqb_immo_gui=info".parse().unwrap())
                .from_env_lossy()
                .add_directive("wgpu_core=warn".parse().unwrap())
                .add_directive("wgpu_hal=warn".parse().unwrap())
                .add_directive("naga=warn".parse().unwrap()),
        )
        .init();

    iced::application(state::State::default, state::update, view::view)
        .title("MQB Immobilizer")
        .subscription(subscription)
        .window_size((1120.0_f32, 900.0_f32))
        .run()
}

fn subscription(_state: &state::State) -> Subscription<state::Message> {
    // The connection task runs for the life of the application, so the device
    // is opened and closed on demand rather than per operation.
    connection::subscription().map(state::Message::Connection)
}
