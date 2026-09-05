//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, SocketAddr};

use holo_utils::capabilities;
use tracing::{error, warn};

use crate::network::PacketInfo;
use crate::packet::{DecodeError, PacketFlags};
use crate::session::SessionId;

// BFD errors.
#[derive(Debug)]
pub enum Error {
    // I/O errors
    IoError(IoError),
    // Inter-task communication
    SessionIdNotFound(SessionId),
    // Packet input
    UdpInvalidSourceAddr(IpAddr),
    UdpPacketDecodeError(DecodeError),
    SessionNoMatch(PacketInfo, u32),
    InvalidFlags(PacketFlags),
    InvalidYourDiscriminator(u32),
    AuthError,
}

// BFD I/O errors.
#[derive(Debug)]
pub enum IoError {
    UdpSocketError(std::io::Error),
    UdpRecvError(std::io::Error),
    UdpSendError(std::io::Error),
    UdpRecvMissingSourceAddr,
    UdpRecvMissingAncillaryData,
}

// ===== impl Error =====

impl Error {
    pub(crate) fn log(&self) {
        match self {
            Error::IoError(error) => {
                error.log();
            }
            Error::SessionIdNotFound(sess_id) => {
                warn!(?sess_id, "{}", self);
            }
            Error::UdpInvalidSourceAddr(addr) => {
                warn!(address = %addr, "{}", self);
            }
            Error::UdpPacketDecodeError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            Error::SessionNoMatch(packet_info, your_discr) => {
                warn!(?packet_info, %your_discr, "{}", self);
            }
            Error::InvalidFlags(flags) => {
                warn!(?flags, "{}", self);
            }
            Error::InvalidYourDiscriminator(discr) => {
                warn!(%discr, "{}", self);
            }
            Error::AuthError => {
                warn!("{}", self);
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(error) => error.fmt(f),
            Error::SessionIdNotFound(..) => {
                write!(f, "session ID not found")
            }
            Error::UdpInvalidSourceAddr(..) => {
                write!(f, "invalid source address")
            }
            Error::UdpPacketDecodeError(..) => {
                write!(f, "failed to decode packet")
            }
            Error::SessionNoMatch(..) => {
                write!(f, "failed to find session")
            }
            Error::InvalidFlags(..) => {
                write!(f, "received invalid flags")
            }
            Error::InvalidYourDiscriminator(..) => {
                write!(f, "received invalid Your Discriminator")
            }
            Error::AuthError => {
                write!(f, "failed to authenticate packet")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(error) => Some(error),
            Error::UdpPacketDecodeError(error) => Some(error),
            _ => None,
        }
    }
}

impl From<IoError> for Error {
    fn from(error: IoError) -> Error {
        Error::IoError(error)
    }
}

// ===== impl IoError =====

impl IoError {
    pub(crate) fn log(&self) {
        match self {
            IoError::UdpSocketError(error)
            | IoError::UdpRecvError(error)
            | IoError::UdpSendError(error) => {
                warn!(error = %with_source(error), "{}", self);
            }
            IoError::UdpRecvMissingSourceAddr
            | IoError::UdpRecvMissingAncillaryData => {
                warn!("{}", self);
            }
        }
    }
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::UdpSocketError(..) => {
                write!(f, "failed to create UDP socket")
            }
            IoError::UdpRecvError(..) => {
                write!(f, "failed to receive UDP packet")
            }
            IoError::UdpSendError(..) => {
                write!(f, "failed to send UDP packet")
            }
            IoError::UdpRecvMissingSourceAddr => {
                write!(
                    f,
                    "failed to retrieve source address from received packet"
                )
            }
            IoError::UdpRecvMissingAncillaryData => {
                write!(
                    f,
                    "failed to retrieve ancillary data from received packet"
                )
            }
        }
    }
}

impl std::error::Error for IoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IoError::UdpSocketError(error)
            | IoError::UdpRecvError(error)
            | IoError::UdpSendError(error) => Some(error),
            _ => None,
        }
    }
}

// ===== global functions =====

// Reports a failed BFD Rx socket bind and terminates the process.
//
// Without an Rx socket the daemon transmits BFD control packets that no one
// answers into a session that can never come up, and it detects no failure at
// all: a liveness protocol that reports nothing is worse than an absent one.
// There is no recovery path either, since the address is held by someone else.
// So this is fatal, and the message names the port and, on EADDRINUSE, the
// process the kernel gave it to, since only that process can release it.
pub(crate) fn rx_bind_fatal(sockaddr: SocketAddr, error: std::io::Error) -> ! {
    let reason = if error.kind() == std::io::ErrorKind::AddrInUse {
        // Reading another process's /proc/<pid>/fd is a ptrace-mode access:
        // the kernel grants it only to a reader whose EFFECTIVE capabilities
        // cover the holder's permitted set, and holo runs its threads with an
        // empty effective set. Without this the scan sees only our own fds.
        let holder =
            capabilities::raise(|| crate::network::udp_port_holder(&sockaddr));
        match holder {
            Some(holder) => format!("address in use (held by {holder})"),
            None => "address in use (holder unknown)".to_owned(),
        }
    } else {
        error.to_string()
    };
    error!("bfd: cannot bind udp {sockaddr}: {reason}");
    std::process::exit(1)
}

fn with_source<E: std::error::Error>(error: E) -> String {
    if let Some(source) = error.source() {
        format!("{} ({})", error, with_source(source))
    } else {
        error.to_string()
    }
}
