//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::net::IpAddr;

use derive_new::new;
use enum_as_inner::EnumAsInner;
use holo_yang::ToYang;
use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::ip::AddressFamily;
use crate::protocol::Protocol;

// BFD path type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum PathType {
    IpSingleHop,
    IpMultihop,
}

// BFD session key.
#[derive(Clone, Debug, EnumAsInner, Eq, new, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum SessionKey {
    IpSingleHop { ifname: String, dst: IpAddr },
    IpMultihop { src: IpAddr, dst: IpAddr },
}

// BFD session state.
#[derive(Clone, Copy, Debug, Eq, FromPrimitive, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum State {
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

// BFD client ID.
#[derive(Clone, Debug, Eq, Hash, PartialEq, new)]
#[derive(Deserialize, Serialize)]
pub struct ClientId {
    pub protocol: Protocol,
    pub name: String,
}

// BFD client configuration.
#[derive(Clone, Copy, Debug)]
#[derive(Deserialize, Serialize)]
pub struct ClientCfg {
    pub local_multiplier: u8,
    pub min_tx: u32,
    pub min_rx: u32,
}

// ===== impl PathType =====

impl ToYang for PathType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            PathType::IpSingleHop => "ietf-bfd-types:path-ip-sh".into(),
            PathType::IpMultihop => "ietf-bfd-types:path-ip-mh".into(),
        }
    }
}

// ===== impl SessionKey =====

impl SessionKey {
    pub fn dst(&self) -> &IpAddr {
        match self {
            SessionKey::IpSingleHop { dst, .. }
            | SessionKey::IpMultihop { dst, .. } => dst,
        }
    }

    pub fn path_type(&self) -> PathType {
        match self {
            SessionKey::IpSingleHop { .. } => PathType::IpSingleHop,
            SessionKey::IpMultihop { .. } => PathType::IpMultihop,
        }
    }
}

// ===== impl State =====

impl ToYang for State {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            State::AdminDown => "adminDown".into(),
            State::Down => "down".into(),
            State::Init => "init".into(),
            State::Up => "up".into(),
        }
    }
}

// ===== impl ClientCfg =====

impl Default for ClientCfg {
    fn default() -> ClientCfg {
        // TODO: how to fetch default values from a YANG grouping?
        ClientCfg {
            local_multiplier: 3,
            min_tx: 1000000,
            min_rx: 1000000,
        }
    }
}

// ===== BfdSocketPolicy =====

/// BFD Rx socket policy supplied by the embedder (holod leaves it default).
///
/// The default is RFC 5881/5883 behavior on both address families, which is what
/// holod binds today. An embedder that only runs IPv4 single-hop sessions asks for
/// exactly that, so no socket is bound for a path type or address family it will
/// never use — every extra wildcard bind is a collision surface with any other BFD
/// implementation on the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BfdSocketPolicy {
    /// UDP port for IP single-hop sessions (RFC 5881: 3784).
    pub single_hop_port: u16,
    /// UDP port for IP multihop sessions (RFC 5883: 4784).
    pub multihop_port: u16,
    /// Bind an IPv4 Rx socket.
    pub ipv4: bool,
    /// Bind an IPv6 Rx socket.
    pub ipv6: bool,
}

impl BfdSocketPolicy {
    /// The Rx/Tx destination port for the given path type.
    pub fn port(&self, path_type: PathType) -> u16 {
        match path_type {
            PathType::IpSingleHop => self.single_hop_port,
            PathType::IpMultihop => self.multihop_port,
        }
    }

    /// Whether an Rx socket should be bound for the given address family.
    pub fn binds_af(&self, af: AddressFamily) -> bool {
        match af {
            AddressFamily::Ipv4 => self.ipv4,
            AddressFamily::Ipv6 => self.ipv6,
        }
    }
}

impl Default for BfdSocketPolicy {
    fn default() -> BfdSocketPolicy {
        BfdSocketPolicy {
            single_hop_port: 3784,
            multihop_port: 4784,
            ipv4: true,
            ipv6: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfd_socket_policy_default_is_todays_behavior() {
        let policy = BfdSocketPolicy::default();
        assert_eq!(policy.port(PathType::IpSingleHop), 3784);
        assert_eq!(policy.port(PathType::IpMultihop), 4784);
        assert!(policy.binds_af(AddressFamily::Ipv4));
        assert!(policy.binds_af(AddressFamily::Ipv6));
    }

    #[test]
    fn bfd_socket_policy_embedder_single_socket() {
        let policy = BfdSocketPolicy {
            single_hop_port: 3785,
            ipv6: false,
            ..Default::default()
        };
        assert_eq!(policy.port(PathType::IpSingleHop), 3785);
        assert!(policy.binds_af(AddressFamily::Ipv4));
        assert!(!policy.binds_af(AddressFamily::Ipv6));
    }
}
