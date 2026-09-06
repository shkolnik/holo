//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::raw::{c_int, c_ushort, c_void};
use std::os::unix::io::AsRawFd;

use libc::{in_addr, ip_mreqn, packet_mreq};
use nix::sys::socket::{LinkAddr, SockaddrLike};
use serde::{Deserialize, Serialize};
// Normal build: re-export standard socket types.
#[cfg(not(feature = "testing"))]
pub use {
    socket2::Socket,
    tokio::io::unix::AsyncFd,
    tokio::net::{
        TcpListener, TcpSocket, TcpStream, UdpSocket, tcp::OwnedReadHalf,
        tcp::OwnedWriteHalf,
    },
};

// TCP connection information.
#[derive(Debug)]
#[derive(Deserialize, Serialize)]
pub struct TcpConnInfo {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}

// FFI struct used to set the TCP_MD5SIG socket option.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct tcp_md5sig {
    pub tcpm_addr: nix::sys::socket::SockaddrStorage,
    pub tcpm_flags: u8,
    pub tcpm_prefixlen: u8,
    pub tcpm_keylen: u16,
    pub __tcpm_pad: u32,
    pub tcpm_key: [u8; 108],
}

// vifctl struct used for adding vifs
#[repr(C)]
pub union __vif_union {
    pub vifc_lcl_addr: in_addr,
    pub vifc_lcl_ifindex: std::os::raw::c_int,
}

#[repr(C)]
pub struct vifctl {
    pub vifc_vifi: std::os::raw::c_ushort,
    pub vifc_flags: std::os::raw::c_uchar,
    pub vifc_threshold: std::os::raw::c_uchar,
    pub vifc_rate_limit: std::os::raw::c_uint,
    pub addr_index_union: __vif_union,
    pub vifc_rmt_addr: in_addr,
}

use crate::ip::{AddressFamily, IpAddrKind};
// Test build: export mock sockets.
#[cfg(feature = "testing")]
pub use crate::socket::mock::{
    AsyncFd, OwnedReadHalf, OwnedWriteHalf, Socket, TcpListener, TcpSocket,
    TcpStream, UdpSocket,
};

// Maximum TTL for IPv4 or Hop Limit for IPv6.
pub const TTL_MAX: u8 = 255;

// MRT Options
pub const MRT_INIT: c_int = 200;
pub const MRT_ADD_VIF: c_int = MRT_INIT + 2;
// Flag for vifc to use ifindex
pub const VIFF_USE_IFINDEX: u8 = 8;

// Useful type definition.
type Result<T> = std::io::Result<T>;

// Extension methods for all socket types.
pub trait SocketExt: Sized + AsRawFd {
    // Marks this socket's egress as control-plane traffic: the IP precedence
    // or traffic class, and optionally the 802.1p priority a VLAN
    // sub-interface's egress-qos-map reads out of sk_priority.
    //
    // The order is the whole point of this method, and the reason no caller
    // sets the two options itself: the kernel resets sk_priority
    // (rt_tos2priority) whenever the IP_TOS value changes, so a priority set
    // first is silently lost. Priorities above 6 require CAP_NET_ADMIN, which
    // is dropped by the time sockets are created, hence the raise around that
    // one call.
    fn set_control_marks(
        &self,
        af: AddressFamily,
        tos: u8,
        priority: Option<u32>,
    ) -> Result<()> {
        match af {
            AddressFamily::Ipv4 => self.set_ipv4_tos(tos)?,
            AddressFamily::Ipv6 => self.set_ipv6_tclass(tos)?,
        }
        if let Some(priority) = priority {
            crate::capabilities::raise(|| self.set_priority(priority))?;
        }
        Ok(())
    }

    // Sets the value of the SO_PRIORITY option for this socket, which the
    // kernel maps to the 802.1p priority of the VLAN sub-interface the packet
    // leaves through. Control sockets go through set_control_marks instead,
    // which owns the ordering against IP_TOS.
    fn set_priority(&self, priority: u32) -> Result<()> {
        let optval = priority as c_int;

        setsockopt(
            self,
            libc::SOL_SOCKET,
            libc::SO_PRIORITY,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IP_TOS option for this socket.
    fn set_ipv4_tos(&self, tos: u8) -> Result<()> {
        let optval = tos as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_TOS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IP_MINTTL option for this socket.
    fn set_ipv4_minttl(&self, ttl: u8) -> Result<()> {
        let optval = ttl as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_MINTTL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IP_TTL option for this socket.
    fn set_ipv4_ttl(&self, ttl: u8) -> Result<()> {
        let optval = ttl as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IP_MULTICAST_IF option for this socket.
    fn set_multicast_ifindex_v4(&self, ifindex: u32) -> Result<()> {
        let optval = ip_mreqn {
            imr_multiaddr: libc::in_addr { s_addr: 0 },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: ifindex as i32,
        };

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<ip_mreqn>() as libc::socklen_t,
        )
    }

    // Sets the value of the IPV6_TCLASS option for this socket.
    fn set_ipv6_tclass(&self, dscp: u8) -> Result<()> {
        let optval = dscp as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IPV6_MINHOPCOUNT option for this socket.
    fn set_ipv6_min_hopcount(&self, hopcount: u8) -> Result<()> {
        let optval = hopcount as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_MINHOPCOUNT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IPV6_UNICAST_HOPS option for this socket.
    fn set_ipv6_unicast_hops(&self, hops: u8) -> Result<()> {
        let optval = hops as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IPV6_MULTICAST_IF option for this socket.
    fn set_multicast_ifindex_v6(&self, ifindex: u32) -> Result<()> {
        let optval = ifindex as i32;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Executes an operation of the IP_ADD_MEMBERSHIP type.
    fn join_multicast_ifindex_v4(
        &self,
        multiaddr: &Ipv4Addr,
        ifindex: u32,
    ) -> Result<()> {
        let multiaddr: u32 = (*multiaddr).into();

        let optval = ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: multiaddr.to_be(),
            },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: ifindex as c_int,
        };

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_ADD_MEMBERSHIP,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<ip_mreqn>() as libc::socklen_t,
        )
    }

    // Executes an operation of the IP_DROP_MEMBERSHIP type.
    fn leave_multicast_ifindex_v4(
        &self,
        multiaddr: &Ipv4Addr,
        ifindex: u32,
    ) -> Result<()> {
        let multiaddr: u32 = (*multiaddr).into();

        let optval = ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: multiaddr.to_be(),
            },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: ifindex as c_int,
        };

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_DROP_MEMBERSHIP,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<ip_mreqn>() as libc::socklen_t,
        )
    }

    // Executes an operation of the PACKET_ADD_MEMBERSHIP type.
    fn join_packet_multicast(&self, addr: [u8; 6], ifindex: u32) -> Result<()> {
        let mut optval = packet_mreq {
            mr_ifindex: ifindex as c_int,
            mr_type: libc::PACKET_MR_MULTICAST as c_ushort,
            mr_alen: 6,
            mr_address: [0; 8],
        };
        optval.mr_address[..6].copy_from_slice(&addr);

        setsockopt(
            self,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<packet_mreq>() as libc::socklen_t,
        )
    }

    // Executes an operation of the PACKET_DROP_MEMBERSHIP type.
    fn leave_packet_multicast(
        &self,
        addr: [u8; 6],
        ifindex: u32,
    ) -> Result<()> {
        let mut optval = packet_mreq {
            mr_ifindex: ifindex as c_int,
            mr_type: libc::PACKET_MR_MULTICAST as c_ushort,
            mr_alen: 6,
            mr_address: [0; 8],
        };
        optval.mr_address[..6].copy_from_slice(&addr);

        setsockopt(
            self,
            libc::SOL_PACKET,
            libc::PACKET_DROP_MEMBERSHIP,
            &optval as *const _ as *const c_void,
            std::mem::size_of::<packet_mreq>() as libc::socklen_t,
        )
    }
}

// Extension methods for UdpSocket.
pub trait UdpSocketExt: SocketExt {
    // Creates a UDP socket not bound to any address.
    #[allow(clippy::new_ret_no_self)]
    fn new(af: AddressFamily) -> Result<UdpSocket>;

    // Creates a UDP socket from the given address.
    //
    // This is the same as [`UdpSocket::bind`], except that the `SO_REUSEADDR`
    // option is set before binding.
    fn bind_reuseaddr(addr: SocketAddr) -> Result<UdpSocket>;

    // Creates a UDP socket bound to the given address, without `SO_REUSEADDR`.
    //
    // The bind is then also the availability check: the kernel lets two UDP
    // sockets share an address only when both set `SO_REUSEADDR`, so without it
    // a second binder gets EADDRINUSE instead of silently stealing the traffic.
    //
    // An IPv6 address is bound `IPV6_V6ONLY`: with `net.ipv6.bindv6only=0` (the
    // default) a `[::]` bind also covers IPv4, so without it the caller's own
    // `0.0.0.0` socket on the same port is what the second bind collides with.
    fn bind_exclusive(addr: SocketAddr) -> Result<UdpSocket>;

    // Sets the value of the IPV6_MULTICAST_HOPS option for this socket.
    fn set_ipv6_multicast_hopcount(&self, hopcount: u8) -> Result<()> {
        let optval = hopcount as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IP_PKTINFO option for this socket.
    fn set_ipv4_pktinfo(&self, value: bool) -> Result<()> {
        let optval = value as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the IPV6_RECVPKTINFO option for this socket.
    fn set_ipv6_pktinfo(&self, value: bool) -> Result<()> {
        let optval = value as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }
}

// Extension methods for TcpSocket, TcpListener and TcpStream.
pub trait TcpSocketExt: SocketExt {
    // Sets the value of the IPV6_V6ONLY option for this socket.
    fn set_ipv6_only(&self, enable: bool) -> Result<()> {
        let optval = enable as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    // Sets the value of the TCP_MD5SIG option for this socket.
    fn set_md5sig(&self, dst: &IpAddr, password: Option<&str>) -> Result<()> {
        let dst = SocketAddr::from((*dst, 0));
        let mut optval = tcp_md5sig {
            tcpm_addr: dst.into(),
            tcpm_flags: 0,
            tcpm_prefixlen: 0,
            tcpm_keylen: 0,
            __tcpm_pad: 0,
            tcpm_key: [0; 108],
        };
        if let Some(password) = password {
            optval.tcpm_keylen = password.len() as u16;
            optval.tcpm_key[..password.len()]
                .copy_from_slice(password.as_bytes());
        }

        setsockopt(
            self,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<tcp_md5sig>() as libc::socklen_t,
        )
    }

    // Sets the value of the TCP_MAXSEG option on this socket.
    fn set_mss(&self, mss: u32) -> Result<()> {
        let optval = mss as c_int;

        setsockopt(
            self,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }
}

// Extension methods for TcpStream.
pub trait TcpStreamExt: TcpSocketExt {
    // Returns address and port information about the TCP connection.
    fn conn_info(&self) -> Result<TcpConnInfo>;
}

// Extension methods for Socket.
pub trait RawSocketExt: SocketExt {
    // Sets the value of the IP_PKTINFO option for this socket.
    fn set_ipv4_pktinfo(&self, value: bool) -> Result<()>;

    // Sets the value of the IPV6_CHECKSUM option for this socket.
    fn set_ipv6_checksum(&self, offset: i32) -> Result<()>;

    // Sets the value of the IPV6_RECVPKTINFO option for this socket.
    fn set_ipv6_pktinfo(&self, value: bool) -> Result<()>;

    // Sets the value of the MRT_INIT option for this socket.
    fn set_mrt_init(&self, value: bool) -> Result<()>;

    // Tell the kernel to create a vif for this ifindex.
    fn start_vif(&self, ifindex: u32, vifid: u16) -> Result<()>;
}

// Extension methods for LinkAddr.
pub trait LinkAddrExt {
    // Creates a new `LinkAddr` using the given protocol number, interface
    // index, and an optional MAC address.
    fn new(protocol: u16, ifindex: u32, addr: Option<[u8; 6]>) -> Self;
}

// ===== impl UdpSocket =====

#[cfg(not(feature = "testing"))]
impl SocketExt for UdpSocket {}

#[cfg(not(feature = "testing"))]
impl UdpSocketExt for UdpSocket {
    fn new(af: AddressFamily) -> Result<UdpSocket> {
        use socket2::{Domain, Type};

        let domain = match af {
            AddressFamily::Ipv4 => Domain::IPV4,
            AddressFamily::Ipv6 => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        UdpSocket::from_std(socket.into())
    }

    fn bind_reuseaddr(addr: SocketAddr) -> Result<UdpSocket> {
        use socket2::{Domain, Type};

        let domain = match addr.ip().address_family() {
            AddressFamily::Ipv4 => Domain::IPV4,
            AddressFamily::Ipv6 => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.bind(&addr.into())?;
        UdpSocket::from_std(socket.into())
    }

    fn bind_exclusive(addr: SocketAddr) -> Result<UdpSocket> {
        use socket2::{Domain, Type};

        let af = addr.ip().address_family();
        let domain = match af {
            AddressFamily::Ipv4 => Domain::IPV4,
            AddressFamily::Ipv6 => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        if af == AddressFamily::Ipv6 {
            socket.set_only_v6(true)?;
        }
        socket.bind(&addr.into())?;
        UdpSocket::from_std(socket.into())
    }
}

// ===== impl TcpSocket =====

#[cfg(not(feature = "testing"))]
impl SocketExt for TcpSocket {}

#[cfg(not(feature = "testing"))]
impl TcpSocketExt for TcpSocket {}

// ===== impl TcpStream =====

#[cfg(not(feature = "testing"))]
impl SocketExt for TcpStream {}

#[cfg(not(feature = "testing"))]
impl TcpSocketExt for TcpStream {}

#[cfg(not(feature = "testing"))]
impl TcpStreamExt for TcpStream {
    fn conn_info(&self) -> Result<TcpConnInfo> {
        let local_addr = self.local_addr()?;
        let remote_addr = self.peer_addr()?;

        Ok(TcpConnInfo {
            local_addr: local_addr.ip(),
            local_port: local_addr.port(),
            remote_addr: remote_addr.ip(),
            remote_port: remote_addr.port(),
        })
    }
}

// ===== impl TcpListener =====

#[cfg(not(feature = "testing"))]
impl SocketExt for TcpListener {}

#[cfg(not(feature = "testing"))]
impl TcpSocketExt for TcpListener {}

// ===== impl LinkAddr =====

impl LinkAddrExt for LinkAddr {
    fn new(protocol: u16, ifindex: u32, addr: Option<[u8; 6]>) -> Self {
        let mut sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: protocol.to_be(),
            sll_ifindex: ifindex as _,
            sll_halen: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_addr: [0; 8],
        };
        if let Some(addr) = addr {
            sll.sll_halen = 6;
            sll.sll_addr[..6].copy_from_slice(&addr);
        }
        let sll_len = size_of_val(&sll) as libc::socklen_t;
        unsafe {
            LinkAddr::from_raw(&sll as *const _ as *const _, Some(sll_len))
        }
        .unwrap()
    }
}

// ===== impl Socket =====

#[cfg(not(feature = "testing"))]
impl SocketExt for Socket {}

#[cfg(not(feature = "testing"))]
impl RawSocketExt for Socket {
    fn set_ipv4_pktinfo(&self, value: bool) -> Result<()> {
        let optval = value as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_checksum(&self, offset: i32) -> Result<()> {
        let optval = offset as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_CHECKSUM,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_ipv6_pktinfo(&self, value: bool) -> Result<()> {
        let optval = value as c_int;

        setsockopt(
            self,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn set_mrt_init(&self, value: bool) -> Result<()> {
        let optval = value as c_int;
        setsockopt(
            self,
            libc::IPPROTO_IP,
            MRT_INIT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    }

    fn start_vif(&self, ifindex: u32, vifid: u16) -> Result<()> {
        let vif = vifctl {
            vifc_vifi: vifid,
            vifc_flags: VIFF_USE_IFINDEX,
            vifc_threshold: 0,
            vifc_rate_limit: 0,
            addr_index_union: __vif_union {
                vifc_lcl_ifindex: ifindex as i32,
            },
            vifc_rmt_addr: libc::in_addr { s_addr: 0 },
        };

        setsockopt(
            self,
            libc::IPPROTO_IP,
            MRT_ADD_VIF,
            &vif as *const _ as *const libc::c_void,
            std::mem::size_of_val(&vif) as libc::socklen_t,
        )
    }
}

// ===== Mock sockets for unit testing =====

pub mod mock {
    #[derive(Debug, Default)]
    pub struct AsyncFd<T>(T);

    #[derive(Debug, Default)]
    pub struct Socket();

    #[derive(Debug, Default)]
    pub struct UdpSocket();

    #[derive(Debug, Default)]
    pub struct TcpSocket();

    #[derive(Debug, Default)]
    pub struct TcpListener();

    #[derive(Debug, Default)]
    pub struct TcpStream();

    #[derive(Debug, Default)]
    pub struct OwnedReadHalf();

    #[derive(Debug, Default)]
    pub struct OwnedWriteHalf();

    impl<T> AsyncFd<T> {
        pub fn new(inner: T) -> std::io::Result<Self> {
            Ok(Self(inner))
        }

        pub fn get_ref(&self) -> &T {
            &self.0
        }
    }

    impl TcpStream {
        pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
            (OwnedReadHalf(), OwnedWriteHalf())
        }
    }
}

// ===== global functions =====

fn setsockopt<F: AsRawFd>(
    sock: &F,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: libc::socklen_t,
) -> Result<()> {
    let ret = unsafe {
        libc::setsockopt(sock.as_raw_fd(), level, optname, optval, optlen)
    };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::RawFd;

    use super::*;

    // A real kernel socket carrying the trait's default methods. Not
    // `socket::Socket`: that name is the mock under the `testing` feature,
    // which the whole workspace test run enables.
    struct TestSocket(socket2::Socket);

    // Internetwork control precedence, what every holo control socket sets.
    const CS6: u8 = libc::IPTOS_PREC_INTERNETCONTROL;

    impl AsRawFd for TestSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    impl SocketExt for TestSocket {}

    impl TestSocket {
        fn udp() -> Self {
            TestSocket(
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    None,
                )
                .unwrap(),
            )
        }

        fn udp6() -> Self {
            TestSocket(
                socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    None,
                )
                .unwrap(),
            )
        }

        // Reads an integer socket option back from the kernel.
        fn getsockopt(&self, level: c_int, optname: c_int) -> u32 {
            let mut optval: c_int = 0;
            let mut optlen = std::mem::size_of::<c_int>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(
                    self.as_raw_fd(),
                    level,
                    optname,
                    &mut optval as *mut _ as *mut c_void,
                    &mut optlen,
                )
            };
            assert_ne!(ret, -1, "{}", std::io::Error::last_os_error());
            optval as u32
        }

        fn priority(&self) -> u32 {
            self.getsockopt(libc::SOL_SOCKET, libc::SO_PRIORITY)
        }

        fn tos(&self) -> u32 {
            self.getsockopt(libc::IPPROTO_IP, libc::IP_TOS)
        }

        fn tclass(&self) -> u32 {
            self.getsockopt(libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
        }
    }

    #[test]
    fn set_priority_reaches_the_kernel() {
        let socket = TestSocket::udp();
        assert_eq!(socket.priority(), 0);
        socket.set_priority(6).unwrap();
        assert_eq!(socket.priority(), 6);
    }

    // The order every control socket depends on, held down here so no call
    // site can get it wrong: the marks survive together.
    #[test]
    fn control_marks_keep_the_priority_v4() {
        let socket = TestSocket::udp();
        socket
            .set_control_marks(AddressFamily::Ipv4, CS6, Some(6))
            .unwrap();
        assert_eq!(socket.tos(), CS6 as u32);
        assert_eq!(socket.priority(), 6);
    }

    #[test]
    fn control_marks_keep_the_priority_v6() {
        let socket = TestSocket::udp6();
        socket
            .set_control_marks(AddressFamily::Ipv6, CS6, Some(6))
            .unwrap();
        assert_eq!(socket.tclass(), CS6 as u32);
        assert_eq!(socket.priority(), 6);
    }

    // No priority asked for, no setsockopt issued: an embedder that sets
    // nothing gets the socket it had before this method existed.
    #[test]
    fn control_marks_without_a_priority_leave_it_untouched() {
        let socket = TestSocket::udp();
        socket.set_priority(3).unwrap();
        socket
            .set_control_marks(AddressFamily::Ipv4, CS6, None)
            .unwrap();
        assert_eq!(socket.tos(), CS6 as u32);
        // 3 survives only because nothing wrote the option; IP_TOS itself
        // resets it, so this also proves no priority was written back.
        assert_eq!(socket.priority(), 0);
    }

    // The ordering the control marking rests on, asserted against the running
    // kernel: IP_TOS resets sk_priority, so a priority set before it is lost
    // and only "TOS then priority" survives.
    #[test]
    fn ip_tos_resets_priority_so_order_matters() {
        let socket = TestSocket::udp();
        socket
            .set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)
            .unwrap();
        socket.set_priority(6).unwrap();
        assert_eq!(socket.priority(), 6, "tos then priority must keep 6");

        let socket = TestSocket::udp();
        socket.set_priority(6).unwrap();
        socket
            .set_ipv4_tos(libc::IPTOS_PREC_INTERNETCONTROL)
            .unwrap();
        assert_eq!(socket.priority(), 0, "priority then tos must lose it");
    }
}
