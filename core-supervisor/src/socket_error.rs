//! Non-panicking classification for Linux socket I/O failures.
//!
//! Socket failures are ordinary events on an adversarial or restricted network.
//! The data plane classifies them into retry, reconnect, fallback, or terminal
//! actions instead of aborting a task. This module performs classification only;
//! it does not open raw sockets or claim that an AF_PACKET backend is attached.

use std::io;
use std::time::Duration;

/// Structured socket failure categories used by the data-plane event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPlaneError {
    /// Non-blocking I/O has no data ready. Register interest and retry later.
    WouldBlock,
    /// A system call was interrupted. Retry the operation without tearing down state.
    Interrupted,
    /// The current network interface is unavailable. Select a verified fallback path.
    NetworkDown,
    /// The remote peer reset the connection. Mark the path unhealthy and reconnect.
    ConnectionReset,
    /// The peer closed its write side. Stop writing and drain/close cleanly.
    BrokenPipe,
    /// An operation requires a connected socket but the peer is absent.
    NotConnected,
    /// Any other operating-system I/O failure. Retain only the stable error kind.
    Other(io::ErrorKind),
}

/// The action an event loop should take after a classified socket failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketRecoveryAction {
    /// Wait for readiness notification; do not spin or close the connection.
    RegisterWritable,
    /// Retry with a short bounded delay.
    RetryAfter(Duration),
    /// Preserve session state and select another already-verified path.
    ReconnectViaFallback,
    /// Gracefully close the local half of the connection.
    CloseGracefully,
}

impl DataPlaneError {
    /// Classify an I/O error without exposing platform-specific raw error text.
    #[must_use]
    pub fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock => Self::WouldBlock,
            io::ErrorKind::Interrupted => Self::Interrupted,
            io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            io::ErrorKind::NotConnected => Self::NotConnected,
            _ => match error.raw_os_error() {
                // Linux errno constants. EAGAIN and EWOULDBLOCK have the same
                // value on Linux, but ErrorKind handles platform variance first.
                Some(11) => Self::WouldBlock,
                Some(4) => Self::Interrupted,
                Some(100) => Self::NetworkDown,
                Some(104) => Self::ConnectionReset,
                Some(32) => Self::BrokenPipe,
                Some(107) => Self::NotConnected,
                _ => Self::Other(error.kind()),
            },
        }
    }

    /// Return a bounded, non-panicking recovery action for the event loop.
    #[must_use]
    pub fn recovery_action(self) -> SocketRecoveryAction {
        match self {
            Self::WouldBlock => SocketRecoveryAction::RegisterWritable,
            Self::Interrupted => SocketRecoveryAction::RetryAfter(Duration::from_millis(1)),
            Self::NetworkDown | Self::ConnectionReset | Self::NotConnected => {
                SocketRecoveryAction::ReconnectViaFallback
            }
            Self::BrokenPipe => SocketRecoveryAction::CloseGracefully,
            Self::Other(_) => SocketRecoveryAction::RetryAfter(Duration::from_millis(25)),
        }
    }
}

impl std::fmt::Display for DataPlaneError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::WouldBlock => "socket would block",
            Self::Interrupted => "socket operation interrupted",
            Self::NetworkDown => "network interface unavailable",
            Self::ConnectionReset => "socket connection reset",
            Self::BrokenPipe => "socket broken pipe",
            Self::NotConnected => "socket is not connected",
            Self::Other(_) => "other socket I/O failure",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DataPlaneError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_linux_socket_errors() {
        let cases = [
            (11, DataPlaneError::WouldBlock, SocketRecoveryAction::RegisterWritable),
            (4, DataPlaneError::Interrupted, SocketRecoveryAction::RetryAfter(Duration::from_millis(1))),
            (100, DataPlaneError::NetworkDown, SocketRecoveryAction::ReconnectViaFallback),
            (104, DataPlaneError::ConnectionReset, SocketRecoveryAction::ReconnectViaFallback),
            (32, DataPlaneError::BrokenPipe, SocketRecoveryAction::CloseGracefully),
            (107, DataPlaneError::NotConnected, SocketRecoveryAction::ReconnectViaFallback),
        ];

        for (code, expected_error, expected_action) in cases {
            let error = io::Error::from_raw_os_error(code);
            let classified = DataPlaneError::from_io(&error);
            assert_eq!(classified, expected_error);
            assert_eq!(classified.recovery_action(), expected_action);
        }
    }

    #[test]
    fn unknown_error_uses_bounded_retry() {
        let error = io::Error::new(io::ErrorKind::TimedOut, "fixture");
        let classified = DataPlaneError::from_io(&error);
        assert_eq!(classified, DataPlaneError::Other(io::ErrorKind::TimedOut));
        assert_eq!(
            classified.recovery_action(),
            SocketRecoveryAction::RetryAfter(Duration::from_millis(25))
        );
    }
}
