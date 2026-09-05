//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::io::IoSliceMut;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU64};

use holo_utils::bfd::{BfdSocketPolicy, PathType};
use holo_utils::capabilities;
use holo_utils::ip::{AddressFamily, IpAddrExt};
use holo_utils::socket::{SocketExt, TTL_MAX, UdpSocket, UdpSocketExt};
use nix::sys::socket::{self, ControlMessageOwned};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::SendError;

use crate::error::{Error, IoError};
use crate::packet::Packet;
use crate::tasks::messages::input::UdpRxPacketMsg;

// The single-hop (RFC 5881) and multihop (RFC 5883) destination ports live in
// `BfdSocketPolicy`, whose default is 3784/4784.
pub const PORT_DST_ECHO: u16 = 3785;
pub const PORT_SRC_RANGE: std::ops::RangeInclusive<u16> = 49152..=65535;

// Ancillary data about a received packet.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub enum PacketInfo {
    IpSingleHop { src: SocketAddr },
    IpMultihop { src: IpAddr, dst: IpAddr, ttl: u8 },
}

// The wildcard address the Rx socket for this path type and address family is
// bound to.
pub(crate) fn rx_sockaddr(
    path_type: PathType,
    af: AddressFamily,
    policy: &BfdSocketPolicy,
) -> SocketAddr {
    SocketAddr::from((IpAddr::unspecified(af), policy.port(path_type)))
}

pub(crate) fn socket_rx(
    path_type: PathType,
    af: AddressFamily,
    policy: &BfdSocketPolicy,
) -> Result<UdpSocket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create socket.
        let sockaddr = rx_sockaddr(path_type, af, policy);
        // No SO_REUSEADDR: the Rx socket must never be shared. Another BFD
        // implementation binding the same wildcard address with SO_REUSEADDR
        // would otherwise succeed and take every packet, silently, whichever
        // of the two bound last.
        let socket =
            capabilities::raise(|| UdpSocket::bind_exclusive(sockaddr))?;

        // Set socket options.
        match path_type {
            PathType::IpSingleHop => match af {
                AddressFamily::Ipv4 => {
                    socket.set_ipv4_pktinfo(true)?;
                    socket.set_ipv4_minttl(TTL_MAX)?;
                }
                AddressFamily::Ipv6 => {
                    socket.set_ipv6_pktinfo(true)?;
                    socket.set_ipv6_min_hopcount(TTL_MAX)?;
                }
            },
            PathType::IpMultihop => {
                // NOTE: since the same Rx socket is used for all multihop
                // sessions, incoming TTL checking should be done in the
                // userspace given that different peers might have different TTL
                // settings.
                match af {
                    AddressFamily::Ipv4 => {
                        socket.set_ipv4_pktinfo(true)?;
                    }
                    AddressFamily::Ipv6 => {
                        socket.set_ipv6_pktinfo(true)?;
                    }
                }
            }
        }

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        let _ = (path_type, af, policy);
        Ok(UdpSocket {})
    }
}

pub(crate) fn socket_tx(
    ifname: Option<&str>,
    af: AddressFamily,
    addr: IpAddr,
    ttl: u8,
) -> Result<UdpSocket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        // Create socket.
        //
        // RFC 5881 says the following:
        // "The source port MUST be in the range 49152 through 65535.  The same
        // UDP source port number MUST be used for all BFD Control packets
        // associated with a particular session.  The source port number SHOULD
        // be unique among all BFD sessions on the system".
        //
        // Take the first free port in the range. A fixed port is not enough:
        // another BFD implementation on the same host may hold it with a
        // wildcard bind and no SO_REUSEADDR (FRR bfdd binds 0.0.0.0:49152),
        // which makes every bind on that port fail with EADDRINUSE. Port
        // uniqueness across sessions is not required for protocol operation,
        // as the remote peer matches incoming BFD packets to sessions
        // regardless of the source port number.
        //
        // In any case, a separate Tx socket is required for each session since
        // they can be bound to different addresses.
        let socket = socket_tx_bind(addr)?;

        // Bind to interface.
        if let Some(ifname) = ifname {
            socket.bind_device(Some(ifname.as_bytes()))?;
        }

        // Set socket options.
        match af {
            AddressFamily::Ipv4 => {
                socket.set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)?;
                socket.set_ipv4_ttl(ttl)?;
            }
            AddressFamily::Ipv6 => {
                socket.set_ipv6_tclass(libc::IPTOS_PREC_INTERNETCONTROL)?;
                socket.set_ipv6_unicast_hops(ttl)?;
            }
        }

        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(UdpSocket {})
    }
}

// Binds a Tx socket to `addr` on the first free port of `PORT_SRC_RANGE`.
#[cfg(not(feature = "testing"))]
fn socket_tx_bind(addr: IpAddr) -> Result<UdpSocket, std::io::Error> {
    let mut last_error = None;
    for port in PORT_SRC_RANGE {
        let sockaddr = SocketAddr::from((addr, port));
        match capabilities::raise(|| UdpSocket::bind_reuseaddr(sockaddr)) {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }

    let error = last_error.expect("PORT_SRC_RANGE is non-empty");
    Err(std::io::Error::new(
        error.kind(),
        format!(
            "no free BFD source port for {} in {}-{}: {}",
            addr,
            PORT_SRC_RANGE.start(),
            PORT_SRC_RANGE.end(),
            error
        ),
    ))
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn send_packet(
    socket: Arc<UdpSocket>,
    sockaddr: SocketAddr,
    packet: Packet,
    tx_packet_count: Arc<AtomicU64>,
    tx_error_count: Arc<AtomicU64>,
) {
    // Encode packet.
    let buf = packet.encode();

    // Send packet.
    match socket.send_to(&buf, sockaddr).await {
        Ok(_) => {
            tx_packet_count.fetch_add(1, atomic::Ordering::Relaxed);
        }
        Err(error) => {
            IoError::UdpSendError(error).log();
            tx_error_count.fetch_add(1, atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(not(feature = "testing"))]
fn get_packet_src(sa: Option<&socket::SockaddrStorage>) -> Option<SocketAddr> {
    sa.and_then(|sa| {
        sa.as_sockaddr_in()
            .map(|sa| SocketAddrV4::from(*sa).into())
            .or_else(|| {
                sa.as_sockaddr_in6()
                    .map(|sa| SocketAddrV6::from(*sa).into())
            })
    })
}

#[cfg(not(feature = "testing"))]
fn get_packet_dst(cmsgs: socket::CmsgIterator<'_>) -> Option<IpAddr> {
    for cmsg in cmsgs {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                return Some(
                    Ipv4Addr::from(pktinfo.ipi_spec_dst.s_addr.to_be()).into(),
                );
            }
            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                return Some(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr).into());
            }
            _ => {}
        }
    }

    None
}

#[cfg(not(feature = "testing"))]
pub(crate) async fn read_loop(
    socket: Arc<UdpSocket>,
    path_type: PathType,
    udp_packet_rxp: Sender<UdpRxPacketMsg>,
) -> Result<(), SendError<UdpRxPacketMsg>> {
    let mut buf = [0; 1024];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo);

    loop {
        // Receive data from the network.
        match socket
            .async_io(tokio::io::Interest::READABLE, || {
                match socket::recvmsg::<socket::SockaddrStorage>(
                    socket.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                ) {
                    Ok(msg) => {
                        // Retrieve source and destination addresses.
                        let src = get_packet_src(msg.address.as_ref());
                        let dst = get_packet_dst(msg.cmsgs().unwrap());
                        Ok((src, dst, msg.bytes))
                    }
                    Err(errno) => Err(errno.into()),
                }
            })
            .await
        {
            Ok((src, dst, bytes)) => {
                let Some(src) = src else {
                    IoError::UdpRecvMissingSourceAddr.log();
                    return Ok(());
                };
                let Some(dst) = dst else {
                    IoError::UdpRecvMissingAncillaryData.log();
                    return Ok(());
                };

                // Validate packet's source address.
                if !src.ip().is_usable() {
                    Error::UdpInvalidSourceAddr(src.ip()).log();
                    continue;
                }

                // Decode packet, discarding malformed ones.
                let packet = match Packet::decode(&iov[0].deref()[0..bytes]) {
                    Ok(packet) => packet,
                    Err(_) => continue,
                };

                // Notify the BFD main task about the received packet.
                let packet_info = match path_type {
                    PathType::IpSingleHop => PacketInfo::IpSingleHop { src },
                    PathType::IpMultihop => {
                        let src = src.ip();
                        // TODO: get packet's TTL using IP_RECVTTL/IPV6_HOPLIMIT
                        let ttl = TTL_MAX;
                        PacketInfo::IpMultihop { src, dst, ttl }
                    }
                };
                let msg = UdpRxPacketMsg {
                    packet_info,
                    packet,
                };
                udp_packet_rxp.send(msg).await?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                // Retry if the syscall was interrupted (EINTR).
                continue;
            }
            Err(error) => {
                IoError::UdpRecvError(error).log();
            }
        }
    }
}

// Returns a description of the process holding `sockaddr`'s UDP port, e.g.
// "bfdd pid 1234", or None when it cannot be determined.
//
// Only meaningful right after an EADDRINUSE: the holder is whoever the kernel
// just refused us in favor of. This is diagnostics, never a decision input —
// reading /proc is racy and may be blocked by permissions or a hidepid mount,
// in which case the caller says the holder is unknown.
pub(crate) fn udp_port_holder(sockaddr: &SocketAddr) -> Option<String> {
    let procfs = match sockaddr {
        SocketAddr::V4(_) => "/proc/net/udp",
        SocketAddr::V6(_) => "/proc/net/udp6",
    };
    let inode = udp_socket_inode(procfs, sockaddr.port())?;
    let (pid, comm) = pid_holding_inode(inode)?;
    Some(format!("{comm} pid {pid}"))
}

// Returns the inode of the first UDP socket bound to `port`, from /proc.
fn udp_socket_inode(procfs: &str, port: u16) -> Option<u64> {
    let contents = std::fs::read_to_string(procfs).ok()?;
    for line in contents.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        // sl local_address rem_address st tx_rx tr_when retrnsmt uid timeout
        // inode ...
        let (Some(local), Some(inode)) = (fields.get(1), fields.get(9)) else {
            continue;
        };
        let Some((_addr, local_port)) = local.rsplit_once(':') else {
            continue;
        };
        if u16::from_str_radix(local_port, 16).ok() != Some(port) {
            continue;
        }
        if let Ok(inode) = inode.parse::<u64>() {
            return Some(inode);
        }
    }
    None
}

// Returns the pid and command name of a process holding an open file
// descriptor for the given socket inode.
fn pid_holding_inode(inode: u64) -> Option<(u32, String)> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            // Another user's process, or one that exited under us.
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path())
                .is_ok_and(|link| link.to_string_lossy() == target)
            {
                let comm = std::fs::read_to_string(entry.path().join("comm"))
                    .map(|comm| comm.trim().to_owned())
                    .unwrap_or_else(|_| "?".to_owned());
                return Some((pid, comm));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // A /proc/net/udp excerpt: FRR bfdd's wildcard 0.0.0.0:3784 (0EC8) and its
    // Tx socket on 0.0.0.0:49152 (C000).
    const PROC_NET_UDP: &str = concat!(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
        " 3784: 00000000:0EC8 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 51423 2 0000000000000000 0\n",
        "49152: 00000000:C000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 51424 2 0000000000000000 0\n",
    );

    fn fixture(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn udp_socket_inode_finds_the_port() {
        let path = fixture("holo-bfd-proc-net-udp", PROC_NET_UDP);
        let path = path.to_str().unwrap();
        assert_eq!(udp_socket_inode(path, 3784), Some(51423));
        assert_eq!(udp_socket_inode(path, 49152), Some(51424));
        assert_eq!(udp_socket_inode(path, 4784), None);
    }

    #[test]
    fn udp_socket_inode_survives_garbage() {
        assert_eq!(udp_socket_inode("/proc/does/not/exist", 3784), None);
        let path =
            fixture("holo-bfd-proc-net-udp-garbage", "header\nnonsense\n");
        assert_eq!(udp_socket_inode(path.to_str().unwrap(), 3784), None);
    }

    #[test]
    fn rx_sockaddr_follows_the_policy() {
        let policy = BfdSocketPolicy {
            single_hop_port: 3785,
            ..Default::default()
        };
        assert_eq!(
            rx_sockaddr(PathType::IpSingleHop, AddressFamily::Ipv4, &policy)
                .to_string(),
            "0.0.0.0:3785"
        );
        assert_eq!(
            rx_sockaddr(PathType::IpMultihop, AddressFamily::Ipv6, &policy)
                .to_string(),
            "[::]:4784"
        );
    }
}
