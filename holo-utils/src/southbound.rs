//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::IpAddr;

use bitflags::bitflags;
use enum_as_inner::EnumAsInner;
use holo_yang::ToYang;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::bier::{BfrId, BierInfo, Bsl, SubDomainId};
use crate::mac_addr::MacAddr;
use crate::mpls::Label;
use crate::protocol::Protocol;
use crate::sr::MsdType;

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct InterfaceFlags: u8 {
        const LOOPBACK = 0x01;
        const OPERATIVE = 0x02;
        const BROADCAST = 0x04;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct AddressFlags: u8 {
        const UNNUMBERED = 0x01;
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum Nexthop {
    Address {
        ifindex: u32,
        addr: IpAddr,
        labels: Box<[Label]>,
    },
    Interface {
        ifindex: u32,
    },
    Recursive {
        addr: IpAddr,
        labels: Box<[Label]>,
        resolved: Box<[Nexthop]>,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[derive(Deserialize, Serialize)]
pub enum RouteKind {
    #[default]
    Unicast,
    Blackhole,
    Unreachable,
    Prohibit,
}

// Route opaque attributes.
#[derive(Clone, Copy, Debug, Default)]
#[derive(Deserialize, Serialize)]
#[derive(EnumAsInner)]
pub enum RouteOpaqueAttrs {
    #[default]
    None,
    Ospf {
        route_type: OspfRouteType,
    },
    Isis {
        route_type: IsisRouteType,
    },
}

// OSPF route types in decreasing order of preference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum OspfRouteType {
    IntraArea,
    InterArea,
    Type1External,
    Type2External,
}

// IS-IS route types.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[derive(Deserialize, Serialize)]
pub enum IsisRouteType {
    L2IntraArea,
    L1IntraArea,
    L2External,
    L1External,
    L1InterArea,
    L1InterAreaExternal,
}

// ===== Ibus messages =====

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct InterfaceUpdateMsg {
    pub ifname: String,
    pub ifindex: u32,
    pub mtu: u32,
    pub flags: InterfaceFlags,
    #[serde(default)]
    pub mac_address: MacAddr,
    #[serde(default)]
    pub msd: BTreeMap<MsdType, u8>,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct AddressMsg {
    pub ifname: String,
    pub addr: IpNetwork,
    pub flags: AddressFlags,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct RouteMsg {
    pub protocol: Protocol,
    #[serde(skip)]
    pub kind: RouteKind,
    pub prefix: IpNetwork,
    pub distance: u32,
    pub metric: u32,
    pub tag: Option<u32>,
    #[serde(skip)]
    pub opaque_attrs: RouteOpaqueAttrs,
    pub nexthops: Vec<Nexthop>,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct RouteKeyMsg {
    pub protocol: Protocol,
    pub prefix: IpNetwork,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BierNbrInstallMsg {
    pub bier_info: BierInfo,
    pub nexthops: Vec<Nexthop>,
    pub prefix: IpNetwork,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct BierNbrUninstallMsg {
    pub sd_id: SubDomainId,
    pub bfr_id: BfrId,
    pub bsl: Bsl,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct LabelInstallMsg {
    pub protocol: Protocol,
    pub label: Label,
    pub nexthops: Vec<Nexthop>,
    pub route: Option<(Protocol, IpNetwork)>,
    pub replace: bool,
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct LabelUninstallMsg {
    pub protocol: Protocol,
    pub label: Label,
    pub nexthops: Vec<Nexthop>,
    pub route: Option<(Protocol, IpNetwork)>,
}

// ===== impl Nexthop =====

impl Nexthop {
    // Compares two `Nexthop` instances for equality.
    pub fn matches(&self, other: &Nexthop) -> bool {
        self == other
    }

    // Compares two `Nexthop` instances for equality, excluding the `labels`
    // field in the `Address` variant.
    pub fn matches_no_labels(&self, other: &Nexthop) -> bool {
        match (self, other) {
            (
                Nexthop::Address {
                    ifindex: ifindex1,
                    addr: addr1,
                    ..
                },
                Nexthop::Address {
                    ifindex: ifindex2,
                    addr: addr2,
                    ..
                },
            ) => ifindex1 == ifindex2 && addr1 == addr2,
            (
                Nexthop::Interface { ifindex: ifindex1 },
                Nexthop::Interface { ifindex: ifindex2 },
            ) => ifindex1 == ifindex2,
            _ => false,
        }
    }

    // Removes all labels from a `Nexthop::Address` variant.
    pub fn remove_labels(&mut self) {
        if let Nexthop::Address { labels, .. } = self {
            *labels = Default::default();
        }
    }

    // Copies the `labels` field from another `Nexthop` instance to this one.
    pub fn copy_labels(&mut self, other: &Nexthop) {
        if let (
            Nexthop::Address {
                labels: labels1, ..
            },
            Nexthop::Address {
                labels: labels2, ..
            },
        ) = (self, other)
        {
            labels1.clone_from(labels2)
        }
    }
}

// ===== impl OspfRouteType =====

impl ToYang for OspfRouteType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            OspfRouteType::IntraArea => "intra-area".into(),
            OspfRouteType::InterArea => "inter-area".into(),
            OspfRouteType::Type1External => "external-1".into(),
            OspfRouteType::Type2External => "external-2".into(),
        }
    }
}

// ===== impl IsisRouteType =====

impl ToYang for IsisRouteType {
    fn to_yang(&self) -> Cow<'static, str> {
        match self {
            IsisRouteType::L2IntraArea => "l2-intra-area".into(),
            IsisRouteType::L1IntraArea => "l1-intra-area".into(),
            IsisRouteType::L2External => "l2-external".into(),
            IsisRouteType::L1External => "l1-external".into(),
            IsisRouteType::L1InterArea => "l1-inter-area".into(),
            IsisRouteType::L1InterAreaExternal => {
                "l1-inter-area-external".into()
            }
        }
    }
}

/// FIB install policy supplied by the embedder (holod leaves it default).
#[derive(Clone, Debug, Default)]
pub struct FibPolicy {
    /// When set, routes are installed with kernel protocol id `base + k` (k: 0 = OSPF,
    /// 1 = static, 2 = BGP; every other protocol → `base + 3`) instead of the well-known
    /// ids, and startup purge / shutdown uninstall touch ONLY that range.
    pub proto_base: Option<u8>,
}

// ===== impl FibPolicy =====

impl FibPolicy {
    /// The kernel protocol id for `protocol` under this policy, or None = holo's default mapping.
    pub fn proto_id(&self, protocol: Protocol) -> Option<u8> {
        let base = self.proto_base?;
        Some(match protocol {
            Protocol::OSPFV2 | Protocol::OSPFV3 => base,
            Protocol::STATIC => base + 1,
            Protocol::BGP => base + 2,
            _ => base + 3,
        })
    }

    /// The kernel protocol id range this policy owns, or None when unset.
    pub fn proto_range(&self) -> Option<std::ops::RangeInclusive<u8>> {
        self.proto_base.map(|b| b..=b + 3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fib_policy_proto_id_unset() {
        let policy = FibPolicy::default();
        assert_eq!(policy.proto_id(Protocol::OSPFV2), None);
        assert_eq!(policy.proto_id(Protocol::STATIC), None);
        assert_eq!(policy.proto_id(Protocol::BGP), None);
        assert_eq!(policy.proto_range(), None);
    }

    #[test]
    fn fib_policy_proto_id_base() {
        let policy = FibPolicy {
            proto_base: Some(201),
            ..Default::default()
        };
        assert_eq!(policy.proto_id(Protocol::OSPFV2), Some(201));
        assert_eq!(policy.proto_id(Protocol::OSPFV3), Some(201));
        assert_eq!(policy.proto_id(Protocol::STATIC), Some(202));
        assert_eq!(policy.proto_id(Protocol::BGP), Some(203));
        assert_eq!(policy.proto_id(Protocol::ISIS), Some(204));
        assert_eq!(policy.proto_id(Protocol::RIPV2), Some(204));
    }

    #[test]
    fn fib_policy_proto_range() {
        let policy = FibPolicy {
            proto_base: Some(201),
            ..Default::default()
        };
        let range = policy.proto_range().unwrap();
        assert_eq!(range, 201..=204);
        assert!(range.contains(&201));
        assert!(range.contains(&204));
        assert!(!range.contains(&200));
        assert!(!range.contains(&205));
    }
}
