use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

use futures_util::stream::StreamExt;
use netlink_packet_audit::AuditMessage;
use netlink_proto::sys::TokioSocket;
use tokio::sync::mpsc;

/// `AUDIT_USER_START` is emitted when a PAM session is opened
const AUDIT_USER_START: u16 = 1105;
/// `AUDIT_USER_END` is emitted when a PAM session is closed
const AUDIT_USER_END: u16 = 1106;

/// Listens for audit messages on the systemd-provided netlink socket and sends a
/// notification on the provided channel whenever a user session is opened or closed,
/// indicating that there rwhod status may have changed.
pub async fn audit_change_notifier(sender: mpsc::Sender<()>, socket_fd: OwnedFd) {
    // SAFETY: `socket_fd` is a systemd-provided netlink socket, already
    // bound and subscribed to the audit multicast group.
    let socket = unsafe { TokioSocket::from_raw_fd(socket_fd.into_raw_fd()) };

    let (connection, _handle, mut messages) = netlink_proto::from_socket_with_codec::<
        AuditMessage,
        TokioSocket,
        netlink_packet_audit::NetlinkAuditCodec,
    >(socket);

    tokio::spawn(connection);

    tracing::info!("Listening for realtime session updates via the Linux audit log");

    loop {
        match messages.next().await {
            Some((msg, _addr))
                if matches!(msg.header.message_type, AUDIT_USER_START | AUDIT_USER_END) =>
            {
                tracing::debug!("Received session-related audit message: {:?}", msg);
                if sender.send(()).await.is_err() {
                    tracing::debug!("Realtime update receiver dropped, stopping audit watcher");
                    return;
                }
            }
            Some((msg, _addr)) => {
                tracing::trace!(
                    "Ignoring audit message unrelated to sessions (type {})",
                    msg.header.message_type
                );
            }
            None => {
                tracing::warn!(
                    "Audit netlink connection closed unexpectedly; realtime updates disabled \
                     for the rest of this run"
                );
                return;
            }
        }
    }
}
