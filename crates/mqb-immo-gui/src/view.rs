//! The window: connection bar, tabs, and the activity log.

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length};

use crate::state::{Connection, InterfaceKind, Message, State, Tab};
use crate::widgets::{blurb, coloured, panel, MONO};
use crate::{theme, view_dflash, view_identity, view_live, view_master};

pub fn view(state: &State) -> Element<'_, Message> {
    column![
        connection_bar(state),
        tab_bar(state),
        container(tab_content(state))
            .padding(12)
            .width(Length::Fill)
            .height(Length::Fill),
        activity_log(state),
    ]
    .into()
}

/// The one piece of chrome that is always visible: what we are connected to.
fn connection_bar(state: &State) -> Element<'_, Message> {
    let kinds = [
        (InterfaceKind::J2534, "J2534 (raw CAN)"),
        (InterfaceKind::J2534IsoTp, "J2534 (hardware ISO-TP)"),
        (InterfaceKind::Panda, "Panda"),
        (InterfaceKind::SocketCan, "SocketCAN"),
    ];
    let mut picker = row![].spacing(10).align_y(Alignment::Center);
    for (kind, label) in kinds {
        picker = picker.push(iced::widget::radio(
            label,
            kind,
            Some(state.interface_kind),
            Message::InterfaceKindChanged,
        ));
    }

    let detail: Element<Message> = match state.interface_kind {
        InterfaceKind::SocketCan => text_input("can0", &state.socketcan_name)
            .on_input(Message::SocketCanNameChanged)
            .width(Length::Fixed(120.0))
            .size(12)
            .into(),
        InterfaceKind::J2534 | InterfaceKind::J2534IsoTp => {
            text_input("PassThru DLL (blank = auto-discover)", &state.j2534_dll)
                .on_input(Message::J2534DllChanged)
                .width(Length::Fixed(320.0))
                .size(12)
                .into()
        }
        InterfaceKind::Panda => Space::new().into(),
    };

    let action: Element<Message> = match &state.connection {
        Connection::Disconnected => button(text("Connect").size(13))
            .on_press(Message::ConnectPressed)
            .into(),
        Connection::Connecting => button(text("Connecting…").size(13)).into(),
        Connection::Connected { .. } => button(text("Disconnect").size(13))
            .on_press(Message::DisconnectPressed)
            .into(),
    };

    let status: Element<Message> = match &state.connection {
        Connection::Disconnected => coloured("Not connected", theme::muted),
        Connection::Connecting => coloured("Opening the interface…", theme::unknown),
        Connection::Connected { interface, raw_can } => {
            let note = if *raw_can {
                "raw CAN available"
            } else {
                "no raw CAN — master emulation unavailable"
            };
            coloured(format!("Connected on {interface} ({note})"), theme::good)
        }
    };

    // Say up front when the chosen interface cannot carry master emulation:
    // better to see it while choosing than after connecting.
    let caveat: Element<Message> =
        if !state.interface_supports_master() && !state.connection.is_connected() {
            coloured(
                "A hardware ISO 15765 channel hides the raw frames, so the master emulator cannot \
             hear the ECU. Use 'J2534 (raw CAN)' for that.",
                theme::warning,
            )
        } else {
            Space::new().height(0.0).into()
        };

    panel(
        column![
            row![picker, detail, Space::new().width(Length::Fill), action]
                .spacing(12)
                .align_y(Alignment::Center),
            status,
            caveat,
        ]
        .spacing(6),
    )
}

fn tab_bar(state: &State) -> Element<'_, Message> {
    let mut tabs = row![].spacing(6);
    for tab in Tab::ALL {
        let selected = state.tab == tab;
        let label = text(tab.label()).size(13);
        let mut control = button(label);
        if !selected {
            control = control.on_press(Message::TabSelected(tab));
        }
        tabs = tabs.push(control);
    }
    container(tabs).padding([8, 12]).into()
}

fn tab_content(state: &State) -> Element<'_, Message> {
    let body = match state.tab {
        Tab::Live => view_live::view(state),
        Tab::Master => view_master::view(state),
        Tab::Identity => view_identity::view(state),
        Tab::Dflash => view_dflash::view(state),
    };
    scrollable(column![blurb(state.tab.blurb()), body].spacing(10))
        .height(Length::Fill)
        .into()
}

fn activity_log(state: &State) -> Element<'_, Message> {
    let lines = state
        .log
        .iter()
        .rev()
        .take(6)
        .rev()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    container(
        scrollable(text(lines).size(11).font(MONO))
            .width(Length::Fill)
            .height(Length::Fixed(84.0)),
    )
    .padding(8)
    .width(Length::Fill)
    .style(|t: &iced::Theme| container::Style {
        background: Some(theme::panel_background(t).into()),
        ..Default::default()
    })
    .into()
}
