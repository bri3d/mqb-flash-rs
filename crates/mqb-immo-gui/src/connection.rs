//! The background task that owns the ECU connection.
//!
//! Everything that touches the bus happens here, on one Tokio task, so the UI
//! thread never blocks and the device is opened exactly once per connection.
//!
//! The task talks to the UI over two channels: [`Command`] in, [`Event`] out.
//! The first event is always [`Event::Ready`], which hands the UI the command
//! sender.
//!
//! # Why one task and not one task per job
//!
//! Immobilizer work needs two things at once on the same bus: UDS reads of the
//! status DIDs, and — on the powertrain bus — answering the ECU's
//! authentication requests on CAN `0x010` within its retry window. [`Session`]
//! allows that because the adapter broadcasts received frames, but both have to
//! be driven from one place or the raw stream stalls while a UDS read is in
//! flight. Hence the select loops below.
//!
//! Master emulation is only possible on an interface that exposes raw CAN. A
//! tester behind the vehicle gateway, or on a hardware ISO 15765 channel, sees
//! no `0x010` traffic at all — so the connection reports whether raw CAN is
//! available and the UI disables the feature when it is not.

use std::time::Duration;

use automotive::can::{Frame, Identifier};
use automotive::StreamExt;
use tokio::sync::mpsc;

use mqb_flash_uds::Session;
use mqb_immo::auth::{ImmoMaster, MasterEvent, CAN_ID_REQUEST, CAN_ID_RESPONSE};
use mqb_immo::state::{decode_2ed, ImmoSnapshot, ImmoSupport, IMMO_DIDS_FULL};
use mqb_immo::{assess, master_key_for_idx_lab, ImmoReport, ImmoSecrets, Variant};
use mqb_modules::modules::simos18::S18_FLASH_INFO;
use mqb_transport::{supports_raw_can, Interface};

/// How often the live view refreshes while polling.
const POLL_INTERVAL: Duration = Duration::from_millis(900);

/// What the UI asks the connection to do.
#[derive(Debug, Clone)]
pub enum Command {
    Connect(Interface),
    Disconnect,
    /// Read the immobilizer state once.
    ReadState,
    /// Turn periodic refresh on or off.
    SetPolling(bool),
    /// Start answering authentication requests.
    StartMaster {
        secrets: Box<ImmoSecrets>,
        key: MasterKeySelection,
    },
    StopMaster,
    /// Send an immobilizer download (`2E 02 E2`).
    SendDownload {
        payload: Vec<u8>,
    },
}

/// How the master key is decided.
///
/// `idxLab` selects it and is not in the immobilizer record. Reading DID
/// `0x2ED` settles it in one request; narrowing costs up to three failed
/// exchanges but works against an ECU that will not answer UDS at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKeySelection {
    /// Read `idxLab` from DID `0x2ED` and derive the key.
    FromEcu,
    /// Start with all three candidates and drop the ones the ECU rejects.
    Narrow,
    /// Use exactly this key.
    Fixed([u8; 4]),
}

/// What the connection tells the UI.
#[derive(Debug, Clone)]
pub enum Event {
    /// Handed over once, at startup.
    Ready(mpsc::UnboundedSender<Command>),
    Connected {
        interface: String,
        /// Whether raw CAN frames are visible, i.e. whether master emulation
        /// is possible at all on this interface.
        raw_can: bool,
    },
    ConnectFailed(String),
    Disconnected,
    /// A fresh immobilizer state read.
    State(Box<LiveState>),
    StateFailed(String),
    MasterStarted {
        master_key: [u8; 4],
        /// How the key was decided, for the log.
        source: String,
    },
    MasterUpdate(Box<MasterUpdate>),
    MasterStopped,
    DownloadFinished(Result<(), String>),
    /// A line for the activity log.
    Log(String),
}

/// One immobilizer state read, decoded and assessed.
#[derive(Debug, Clone)]
pub struct LiveState {
    pub snapshot: ImmoSnapshot,
    pub report: ImmoReport,
}

/// The master emulator's progress after handling one request.
#[derive(Debug, Clone)]
pub struct MasterUpdate {
    pub request: [u8; 8],
    pub reply: Option<[u8; 8]>,
    pub variant: Option<Variant>,
    pub ecu_status: Option<u8>,
    pub authenticated: bool,
    pub master_key: [u8; 4],
    pub master_key_confirmed: bool,
    pub no_key_slave: Option<[u8; 2]>,
    pub exchanges: u32,
    pub log: Vec<MasterEvent>,
}

/// The iced subscription that runs the connection for the lifetime of the app.
pub fn subscription() -> iced::Subscription<Event> {
    iced::Subscription::run(connection_stream)
}

fn connection_stream() -> impl iced::futures::Stream<Item = Event> {
    iced::stream::channel(
        64,
        |mut output: iced::futures::channel::mpsc::Sender<Event>| async move {
            use iced::futures::SinkExt;
            let (command_tx, command_rx) = mpsc::unbounded_channel();
            if output.send(Event::Ready(command_tx)).await.is_err() {
                return;
            }
            run(command_rx, output).await;
        },
    )
}

/// The event sink, wrapped so the loops below can emit without ceremony.
struct Out(iced::futures::channel::mpsc::Sender<Event>);

impl Out {
    async fn send(&mut self, event: Event) {
        use iced::futures::SinkExt;
        let _ = self.0.send(event).await;
    }

    async fn log(&mut self, message: impl Into<String>) {
        self.send(Event::Log(message.into())).await;
    }
}

/// Whether the enclosing loop should keep running.
enum Flow {
    Continue,
    /// Leave the connected loop and close the session.
    Disconnect,
}

async fn run(
    mut commands: mpsc::UnboundedReceiver<Command>,
    output: iced::futures::channel::mpsc::Sender<Event>,
) {
    let mut out = Out(output);

    while let Some(command) = commands.recv().await {
        let Command::Connect(interface) = command else {
            // Nothing else is meaningful while disconnected.
            continue;
        };

        let label = interface.to_string();
        out.log(format!("Opening {label}…")).await;

        // Opening a device loads a DLL and starts threads; never on the executor.
        let opened = {
            let interface = interface.clone();
            tokio::task::spawn_blocking(move || Session::open(&interface, &S18_FLASH_INFO, None))
                .await
        };
        let session = match opened {
            Ok(Ok(session)) => session,
            Ok(Err(e)) => {
                out.send(Event::ConnectFailed(e.to_string())).await;
                continue;
            }
            Err(e) => {
                out.send(Event::ConnectFailed(format!("open task failed: {e}")))
                    .await;
                continue;
            }
        };

        let raw_can = session.raw_can().is_some() && supports_raw_can(&interface);
        out.send(Event::Connected {
            interface: label,
            raw_can,
        })
        .await;
        if !raw_can {
            out.log(
                "This interface carries no raw CAN frames, so immobilizer master emulation is \
                 unavailable. Diagnostics and identity writes work normally.",
            )
            .await;
        }

        connected(&session, &mut commands, &mut out).await;

        session.close().await;
        out.send(Event::Disconnected).await;
    }
}

/// The connected loop: idle polling, with master emulation as an inner mode.
async fn connected(
    session: &Session,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    out: &mut Out,
) {
    let mut polling = false;
    let mut master: Option<ImmoMaster> = None;

    loop {
        if master.is_some() {
            match master_loop(session, commands, out, &mut master, &mut polling).await {
                Flow::Disconnect => return,
                Flow::Continue => continue,
            }
        }

        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { return };
                    match handle_command(session, out, command, &mut polling, &mut master).await {
                        Flow::Disconnect => return,
                        Flow::Continue => {}
                    }
                    if master.is_some() {
                        break; // Switch to the master loop.
                    }
                }
                _ = ticker.tick(), if polling => {
                    read_state(session, out).await;
                }
            }
        }
    }
}

/// The master-emulation mode: the same loop, plus the raw `0x010` stream.
///
/// The stream is created here rather than once per connection because it
/// borrows the adapter, so recreating it keeps that borrow from outliving a
/// disconnect. Frames the adapter itself sent are filtered out — the loopback
/// echo would otherwise be answered as if the ECU had asked twice.
async fn master_loop(
    session: &Session,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    out: &mut Out,
    master: &mut Option<ImmoMaster>,
    polling: &mut bool,
) -> Flow {
    let Some(adapter) = session.raw_can() else {
        out.log("This interface cannot see raw CAN frames; master emulation stopped.")
            .await;
        *master = None;
        out.send(Event::MasterStopped).await;
        return Flow::Continue;
    };

    let mut frames = Box::pin(adapter.recv_filter(|frame| {
        !frame.loopback && frame.id == Identifier::Standard(CAN_ID_REQUEST) && frame.data.len() == 8
    }));

    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Answering the ECU is time-critical: it retries for three cycles
            // and then gives up on the exchange, so this arm is checked first.
            biased;

            frame = frames.next() => {
                let Some(frame) = frame else {
                    out.log("The CAN stream ended; master emulation stopped.").await;
                    *master = None;
                    out.send(Event::MasterStopped).await;
                    return Flow::Continue;
                };
                let Some(emulator) = master.as_mut() else { return Flow::Continue };

                let mut request = [0u8; 8];
                request.copy_from_slice(&frame.data);
                let reply = emulator.handle_request(&request);

                if let Some(reply) = reply {
                    match Frame::new(0, Identifier::Standard(CAN_ID_RESPONSE), &reply) {
                        Ok(frame) => adapter.send(&frame).await,
                        Err(e) => out.log(format!("Could not build the reply frame: {e}")).await,
                    }
                }

                out.send(Event::MasterUpdate(Box::new(MasterUpdate {
                    request,
                    reply,
                    variant: emulator.variant(),
                    ecu_status: emulator.ecu_status(),
                    authenticated: emulator.authenticated(),
                    master_key: emulator.master_key(),
                    master_key_confirmed: emulator.master_key_confirmed(),
                    no_key_slave: emulator.no_key_slave(),
                    exchanges: emulator.exchanges(),
                    log: emulator.drain_log(),
                }))).await;
            }

            command = commands.recv() => {
                let Some(command) = command else { return Flow::Disconnect };
                match handle_command(session, out, command, polling, master).await {
                    Flow::Disconnect => return Flow::Disconnect,
                    Flow::Continue => {}
                }
                if master.is_none() {
                    return Flow::Continue;
                }
            }

            _ = ticker.tick(), if *polling => {
                read_state(session, out).await;
            }
        }
    }
}

async fn handle_command(
    session: &Session,
    out: &mut Out,
    command: Command,
    polling: &mut bool,
    master: &mut Option<ImmoMaster>,
) -> Flow {
    match command {
        Command::Connect(_) => {
            out.log("Already connected; disconnect first.").await;
            Flow::Continue
        }
        Command::Disconnect => Flow::Disconnect,

        Command::ReadState => {
            read_state(session, out).await;
            Flow::Continue
        }

        Command::SetPolling(on) => {
            *polling = on;
            out.log(if on {
                "Refreshing the immobilizer state continuously."
            } else {
                "Stopped refreshing."
            })
            .await;
            Flow::Continue
        }

        Command::StartMaster { secrets, key } => {
            if session.raw_can().is_none() {
                out.log(
                    "Master emulation needs raw CAN frames, which this interface does not \
                     provide.",
                )
                .await;
                return Flow::Continue;
            }

            let (key, source) = match key {
                MasterKeySelection::Fixed(key) => (Some(key), "supplied".to_string()),

                // Narrowing is what the user asked for, so do not short-circuit
                // it by reading idxLab — the point is to exercise the candidate
                // search against an ECU that may not answer UDS at all.
                MasterKeySelection::Narrow => (
                    None,
                    "narrowing the three candidates from the ECU's own traffic".to_string(),
                ),

                // idxLab is not in the NVRAM record, but a live ECU publishes it
                // unauthenticated — so ask rather than guess.
                MasterKeySelection::FromEcu => match read_idx_lab(session).await {
                    Some(idx_lab) => (
                        Some(master_key_for_idx_lab(idx_lab)),
                        format!("idxLab 0x{idx_lab:02X} from DID 0x2ED"),
                    ),
                    None => (
                        None,
                        "DID 0x2ED did not answer, so falling back to narrowing from traffic"
                            .to_string(),
                    ),
                },
            };

            let emulator = ImmoMaster::new(&secrets, key);
            let in_use = emulator.master_key();
            *master = Some(emulator);
            out.send(Event::MasterStarted {
                master_key: in_use,
                source,
            })
            .await;
            Flow::Continue
        }

        Command::StopMaster => {
            if master.take().is_some() {
                out.send(Event::MasterStopped).await;
            }
            Flow::Continue
        }

        Command::SendDownload { payload } => {
            out.log(format!(
                "Sending the immobilizer download: 2E 02 E2, {} bytes.",
                payload.len()
            ))
            .await;
            let result = session
                .write_did(&S18_FLASH_INFO, mqb_immo::DID_DOWNLOAD, &payload)
                .await;
            match &result {
                Ok(()) => out.log("The ECU accepted the download.").await,
                Err(e) => out.log(format!("The ECU rejected the download: {e}")).await,
            }
            // Whatever happened, the state has probably moved.
            read_state(session, out).await;
            out.send(Event::DownloadFinished(result.map_err(|e| e.to_string())))
                .await;
            Flow::Continue
        }
    }
}

/// Read every immobilizer DID and assess the result.
async fn read_state(session: &Session, out: &mut Out) {
    let Some(support) = ImmoSupport::for_module(&S18_FLASH_INFO) else {
        out.send(Event::StateFailed(
            "the immobilizer rules do not cover this module".into(),
        ))
        .await;
        return;
    };

    let dids = session.read_dids(&S18_FLASH_INFO, &IMMO_DIDS_FULL).await;
    if dids.is_empty() {
        out.send(Event::StateFailed(
            "the ECU did not answer any immobilizer DID. Check the ignition and the wiring.".into(),
        ))
        .await;
        return;
    }

    let snapshot = ImmoSnapshot::from_dids(support, dids);
    let report = assess(&snapshot);
    out.send(Event::State(Box::new(LiveState { snapshot, report })))
        .await;
}

/// `idxLab` from DID `0x2ED`, which needs no key and no session.
async fn read_idx_lab(session: &Session) -> Option<u8> {
    let dids = session
        .read_dids(&S18_FLASH_INFO, &[mqb_immo::state::DID_STATE])
        .await;
    let payload = dids.get(&mqb_immo::state::DID_STATE)?;
    decode_2ed(payload).map(|state| state.idx_lab)
}
