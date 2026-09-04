//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use enum_as_inner::EnumAsInner;
use holo_utils::ip::{AddressFamily, Ipv4NetworkExt};
use holo_utils::sr::IgpAlgoType;
use ipnetwork::Ipv4Network;

use crate::area::Area;
use crate::collections::{Arena, Lsdb};
use crate::error::Error;
use crate::interface::{Interface, InterfaceType};
use crate::lsdb::LsaEntry;
use crate::neighbor::Neighbor;
use crate::ospfv2::packet::iana::{
    LsaRouterFlags, LsaRouterLinkType, LsaTypeCode, Options,
};
use crate::ospfv2::packet::lsa::{
    LsaAsExternalFlags, LsaBody, LsaRouterLink, LsaType,
};
use crate::ospfv2::packet::lsa_opaque::{
    ExtPrefixRouteType, LsaOpaque, PrefixSid,
};
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::route::{Nexthop, NexthopKey, Nexthops};
use crate::spf::{
    SpfComputation, SpfExternalNetwork, SpfInterAreaNetwork,
    SpfInterAreaRouter, SpfIntraAreaNetwork, SpfLink, SpfPartialComputation,
    SpfRouterInfo, SpfTriggerLsa, SpfVersion, Vertex, VertexIdVersion,
    VertexLsaVersion,
};
use crate::version::Ospfv2;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VertexId {
    Network { dr_addr: Ipv4Addr },
    Router { router_id: Ipv4Addr },
}

#[derive(Debug, Eq, PartialEq, EnumAsInner)]
pub enum VertexLsa {
    Network(Arc<Lsa<Ospfv2>>),
    Router(Arc<Lsa<Ospfv2>>),
}

// ===== impl VertexId =====

impl VertexIdVersion for VertexId {
    fn new_root(router_id: Ipv4Addr) -> Self {
        VertexId::Router { router_id }
    }
}

// ===== impl VertexLsa =====

impl VertexLsaVersion<Ospfv2> for VertexLsa {
    fn is_router(&self) -> bool {
        matches!(self, VertexLsa::Router(_))
    }

    fn router_id(&self) -> Ipv4Addr {
        let lsa = self.as_router().unwrap();
        lsa.hdr.adv_rtr
    }

    fn router_options(&self) -> Options {
        let lsa = self.as_router().unwrap();
        lsa.hdr.options
    }

    fn router_flags(&self) -> LsaRouterFlags {
        let lsa = self.as_router().unwrap();
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.flags
    }

    fn origin(&self) -> LsaKey<LsaType> {
        let lsa = match self {
            VertexLsa::Network(lsa) => lsa,
            VertexLsa::Router(lsa) => lsa,
        };
        lsa.hdr.key()
    }
}

// ===== impl Ospfv2 =====

impl SpfVersion<Self> for Ospfv2 {
    type VertexId = VertexId;
    type VertexLsa = VertexLsa;

    fn spf_computation_type(
        trigger_lsas: &[SpfTriggerLsa<Self>],
    ) -> SpfComputation<Self> {
        // Router-LSA and Network-LSA changes represent topological changes,
        // hence a full SPF run is required to recompute the SPT.
        //
        // Certain Opaque-LSA changes don't strictly require a full SPF run, but
        // doing so greatly simplify things (e.g. no need to keep track of which
        // routes are affected by which SRGBs).
        if trigger_lsas.iter().map(|tlsa| &tlsa.new).any(|lsa| {
            matches!(
                lsa.body,
                LsaBody::Router(_)
                    | LsaBody::Network(_)
                    | LsaBody::OpaqueArea(
                        LsaOpaque::RouterInfo(_)
                            | LsaOpaque::ExtPrefix(_)
                            | LsaOpaque::ExtLink(_)
                    )
                    | LsaBody::OpaqueAs(LsaOpaque::ExtPrefix(_))
            )
        }) {
            return SpfComputation::Full;
        }

        // In OSPFv2 intra-area information is embedded in Router-LSAs and
        // Network-LSAs.
        let intra = Default::default();

        // Check Type-3 Summary LSA changes.
        let inter_network = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| {
                lsa.body
                    .as_summary_network()
                    .map(move |lsa_body| (lsa.hdr, lsa_body))
            })
            .filter_map(|(lsa_hdr, lsa_body)| {
                Ipv4Network::with_netmask(lsa_hdr.lsa_id, lsa_body.mask).ok()
            })
            .collect();

        // Check Type-4 Summary LSA changes.
        let inter_router = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| lsa.body.as_summary_router().map(|_| lsa.hdr))
            .map(|lsa_hdr| lsa_hdr.lsa_id)
            .collect::<BTreeSet<_>>();

        // Check AS-External LSA changes.
        let external = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| {
                lsa.body
                    .as_as_external()
                    .map(move |lsa_body| (lsa.hdr, lsa_body))
            })
            .filter_map(|(lsa_hdr, lsa_body)| {
                Ipv4Network::with_netmask(lsa_hdr.lsa_id, lsa_body.mask).ok()
            })
            .collect();

        SpfComputation::Partial(SpfPartialComputation {
            intra,
            inter_network,
            inter_router,
            external,
        })
    }

    fn calc_nexthops(
        area: &Area<Self>,
        parent: &Vertex<Self>,
        parent_link: Option<(usize, &LsaRouterLink)>,
        dest_id: VertexId,
        dest_lsa: &VertexLsa,
        interfaces: &Arena<Interface<Self>>,
        neighbors: &Arena<Neighbor<Self>>,
        _extended_lsa: bool,
        _lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Result<Nexthops<Ipv4Addr>, Error<Self>> {
        let mut nexthops = Nexthops::new();

        match &parent.lsa {
            // The parent vertex is the root.
            VertexLsa::Router(_parent_lsa) => {
                // The destination is either a directly connected network or
                // directly connected router.
                let (_parent_link_pos, parent_link) = parent_link.unwrap();

                // Get the nexthop interface from the identity the link carries
                // (RFC 2328 A.4.2), not from its position in the link list.
                // The two orderings are built from different predicates and
                // drift apart whenever an adjacency is still forming, a
                // multipoint interface has several neighbors, or the LSA is
                // stale because MinLSInterval is holding its re-origination.
                let (iface_idx, iface) = area
                    .interfaces
                    .indexes()
                    .map(|iface_idx| (iface_idx, &interfaces[iface_idx]))
                    .find(|(_, iface)| iface_matches_link(iface, parent_link))
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?;

                // If the interface is a virtual link, do not resolve the
                // nexthop here. Virtual link nexthops are handled later,
                // as specified in RFC 2328 section 16.3.
                if iface.is_virtual_link() {
                    return Ok(nexthops);
                }

                match dest_lsa {
                    VertexLsa::Router(dest_lsa) => {
                        // Add nexthop(s).
                        match iface.config.if_type {
                            InterfaceType::PointToPoint
                            | InterfaceType::VirtualLink => {
                                // RFC 2328 assumes that routes using
                                // point-to-point interfaces don't need a
                                // nexthop address. In practice, however, it's
                                // common to use the point-to-point mode on
                                // multi-access links such as Ethernet, so a
                                // nexthop address is required.
                                //
                                // To determine the nexthop address, we use the
                                // neighbor's source address. Examining the
                                // destination's Router-LSA to find the link
                                // pointing back to the calculating router
                                // wouldn't work for unnumbered interfaces.
                                let nbr_router_id = dest_lsa.hdr.adv_rtr;
                                let (_, nbr) = iface
                                    .state
                                    .neighbors
                                    .get_by_router_id(neighbors, nbr_router_id)
                                    .ok_or(Error::SpfNexthopCalcError(
                                        dest_id,
                                    ))?;
                                let nexthop_addr = nbr.src;

                                nexthops.insert(
                                    NexthopKey::new(
                                        iface_idx,
                                        Some(nexthop_addr),
                                    ),
                                    Nexthop::new(
                                        iface_idx,
                                        Some(nexthop_addr),
                                        Some(nbr_router_id),
                                    ),
                                );
                            }
                            InterfaceType::PointToMultipoint => {
                                // If the destination is a router which connects
                                // to the calculating router via a
                                // Point-to-MultiPoint network, the
                                // destination's next hop IP address(es) can be
                                // determined by examining the destination's
                                // router-LSA: each link pointing back to the
                                // calculating router and having a Link Data
                                // field belonging to the Point-to-MultiPoint
                                // network provides an IP address of the next
                                // hop router.
                                nexthops.extend(
                                    dest_lsa
                                        .body
                                        .as_router()
                                        .unwrap()
                                        .links
                                        .iter()
                                        .filter(|link| {
                                            iface
                                                .system
                                                .contains_addr(&link.link_data)
                                        })
                                        .map(|link| {
                                            let nexthop_addr = link.link_data;
                                            let nbr_router_id =
                                                dest_lsa.hdr.adv_rtr;
                                            (
                                                NexthopKey::new(
                                                    iface_idx,
                                                    Some(nexthop_addr),
                                                ),
                                                Nexthop::new(
                                                    iface_idx,
                                                    Some(nexthop_addr),
                                                    Some(nbr_router_id),
                                                ),
                                            )
                                        }),
                                );
                            }
                            _ => {}
                        }
                        if nexthops.is_empty() {
                            return Err(Error::SpfNexthopCalcError(dest_id));
                        }
                    }
                    VertexLsa::Network(_lsa) => {
                        // Add nexthop.
                        nexthops.insert(
                            NexthopKey::new(iface_idx, None),
                            Nexthop::new(iface_idx, None, None),
                        );
                    }
                }
            }
            // The parent vertex is a network that directly connects the
            // calculating router to the destination router.
            VertexLsa::Network(parent_lsa) => {
                // The list of next hops is then determined by examining the
                // destination's router-LSA. For each link in the router-LSA
                // that points back to the parent network, the link's Link
                // Data field provides the IP address of a next hop router.
                let lsa_body = parent_lsa.body.as_network().unwrap();
                let parent_network = Ipv4Network::with_netmask(
                    parent_lsa.hdr.lsa_id,
                    lsa_body.mask,
                )
                .map_err(|_| Error::SpfNexthopCalcError(dest_id))?;
                let dest_lsa = dest_lsa.as_router().unwrap();
                let dest_link = dest_lsa
                    .body
                    .as_router()
                    .unwrap()
                    .links
                    .iter()
                    .find(|link| parent_network.contains(link.link_data))
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?;

                // Inherit outgoing interface from the parent network.
                let iface_idx = parent
                    .nexthops
                    .values()
                    .next()
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?
                    .iface_idx;

                // Get nexthop address.
                let nbr_router_id = dest_lsa.hdr.adv_rtr;
                let nexthop_addr = dest_link.link_data;

                // Add nexthop.
                nexthops.insert(
                    NexthopKey::new(iface_idx, Some(nexthop_addr)),
                    Nexthop::new(
                        iface_idx,
                        Some(nexthop_addr),
                        Some(nbr_router_id),
                    ),
                );
            }
        }

        Ok(nexthops)
    }

    fn vertex_lsa_find(
        _af: AddressFamily,
        id: VertexId,
        area: &Area<Self>,
        _extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Option<VertexLsa> {
        match id {
            VertexId::Network { dr_addr } => {
                // For OSPFv2, SPF needs to find a Network-LSA knowing only its
                // LS-ID but not its advertising router.
                area.state
                    .lsdb
                    .iter_by_type(lsa_entries, LsaTypeCode::Network.into())
                    .map(|(_, lse)| &lse.data)
                    .find(|lsa| lsa.hdr.lsa_id == dr_addr)
                    .filter(|lsa| !lsa.hdr.is_maxage())
                    .map(|lsa| VertexLsa::Network(lsa.clone()))
            }
            VertexId::Router { router_id } => {
                let lsa_key = LsaKey::new(
                    LsaTypeCode::Router.into(),
                    router_id,
                    router_id,
                );
                area.state
                    .lsdb
                    .get(lsa_entries, &lsa_key)
                    .filter(|(_, lse)| !lse.data.hdr.is_maxage())
                    .map(|(_, lse)| VertexLsa::Router(lse.data.clone()))
            }
        }
    }

    fn vertex_lsa_links<'a>(
        vertex_lsa: &'a VertexLsa,
        af: AddressFamily,
        area: &'a Area<Ospfv2>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Ospfv2>>,
    ) -> Box<dyn Iterator<Item = SpfLink<'a, Ospfv2>> + 'a> {
        match vertex_lsa {
            VertexLsa::Network(lsa) => {
                let lsa_body = lsa.body.as_network().unwrap();
                let iter = lsa_body.attached_rtrs.iter().filter_map(
                    move |router_id| {
                        let link_vid = VertexId::Router {
                            router_id: *router_id,
                        };
                        Ospfv2::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            false,
                            lsa_entries,
                        )
                        .map(|link_vlsa| {
                            SpfLink::new(None, link_vid, link_vlsa, 0)
                        })
                    },
                );
                Box::new(iter)
            }
            VertexLsa::Router(lsa) => {
                let lsa_body = lsa.body.as_router().unwrap();
                let iter = lsa_body
                    .links
                    .iter()
                    .filter_map(|link| match link.link_type {
                        LsaRouterLinkType::PointToPoint
                        | LsaRouterLinkType::VirtualLink => {
                            let link_vid = VertexId::Router {
                                router_id: link.link_id,
                            };
                            Some((link, link_vid, link.metric))
                        }
                        LsaRouterLinkType::TransitNetwork => {
                            let link_vid = VertexId::Network {
                                dr_addr: link.link_id,
                            };
                            Some((link, link_vid, link.metric))
                        }
                        LsaRouterLinkType::StubNetwork => None,
                    })
                    .enumerate()
                    .filter_map(move |(link_pos, (link, link_vid, cost))| {
                        Ospfv2::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            false,
                            lsa_entries,
                        )
                        .map(|link_vlsa| {
                            SpfLink::new(
                                Some((link_pos, link)),
                                link_vid,
                                link_vlsa,
                                cost,
                            )
                        })
                    });
                Box::new(iter)
            }
        }
    }

    fn intra_area_networks<'a>(
        area: &'a Area<Self>,
        _extended_lsa: bool,
        _lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfIntraAreaNetwork<'a, Self>> + 'a {
        let mut stubs = vec![];

        for vertex in area.state.spt.values() {
            match &vertex.lsa {
                VertexLsa::Network(lsa) => {
                    let lsa_body = lsa.body.as_network().unwrap();
                    let Some(prefix) = Ipv4Network::with_netmask(
                        lsa.hdr.lsa_id,
                        lsa_body.mask,
                    )
                    .ok() else {
                        continue;
                    };
                    let prefix = prefix.apply_mask();
                    let prefix_sids = route_prefix_sids(
                        area,
                        lsa.hdr.adv_rtr,
                        &prefix,
                        ExtPrefixRouteType::IntraArea,
                    );

                    stubs.push(SpfIntraAreaNetwork {
                        vertex,
                        prefix,
                        prefix_options: Default::default(),
                        metric: 0,
                        prefix_sids,
                        // FIXME: BIER not supported yet for OSPFv2
                        bier: Default::default(),
                    });
                }
                VertexLsa::Router(lsa) => {
                    let lsa_body = lsa.body.as_router().unwrap();
                    stubs.extend(
                        lsa_body
                            .links
                            .iter()
                            .filter(|link| {
                                link.link_type == LsaRouterLinkType::StubNetwork
                            })
                            .filter_map(|link| {
                                let prefix = Ipv4Network::with_netmask(
                                    link.link_id,
                                    link.link_data,
                                )
                                .ok()?;
                                let prefix = prefix.apply_mask();
                                let metric = link.metric;
                                let prefix_sids = route_prefix_sids(
                                    area,
                                    lsa.hdr.adv_rtr,
                                    &prefix,
                                    ExtPrefixRouteType::IntraArea,
                                );

                                Some(SpfIntraAreaNetwork {
                                    vertex,
                                    prefix,
                                    prefix_options: Default::default(),
                                    metric,
                                    prefix_sids,
                                    // FIXME: BIER not supported yet for OSPFv2
                                    bier: Default::default(),
                                })
                            }),
                    )
                }
            }
        }

        stubs.into_iter()
    }

    fn inter_area_networks<'a>(
        area: &'a Area<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfInterAreaNetwork<Self>> + 'a {
        area.state
            .lsdb
            .iter_by_type(lsa_entries, LsaTypeCode::SummaryNetwork.into())
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(|lsa| {
                let lsa_body = lsa.body.as_summary_network().unwrap();
                let prefix =
                    Ipv4Network::with_netmask(lsa.hdr.lsa_id, lsa_body.mask)
                        .ok()?;
                let prefix_sids = route_prefix_sids(
                    area,
                    lsa.hdr.adv_rtr,
                    &prefix,
                    ExtPrefixRouteType::InterArea,
                );

                Some(SpfInterAreaNetwork {
                    adv_rtr: lsa.hdr.adv_rtr,
                    prefix,
                    prefix_options: Default::default(),
                    metric: lsa_body.metric,
                    prefix_sids,
                })
            })
    }

    fn inter_area_routers<'a>(
        lsdb: &'a Lsdb<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfInterAreaRouter<Self>> + 'a {
        lsdb.iter_by_type(lsa_entries, LsaTypeCode::SummaryRouter.into())
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .map(|lsa| {
                let lsa_body = lsa.body.as_summary_router().unwrap();
                SpfInterAreaRouter {
                    adv_rtr: lsa.hdr.adv_rtr,
                    router_id: lsa.hdr.lsa_id,
                    options: lsa.hdr.options,
                    flags: LsaRouterFlags::E,
                    metric: lsa_body.metric,
                }
            })
    }

    fn external_networks<'a>(
        lsdb: &'a Lsdb<Self>,
        _extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfExternalNetwork<Self>> + 'a {
        lsdb.iter_by_type(lsa_entries, LsaTypeCode::AsExternal.into())
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(|lsa| {
                let lsa_body = lsa.body.as_as_external().unwrap();
                let prefix =
                    Ipv4Network::with_netmask(lsa.hdr.lsa_id, lsa_body.mask)
                        .ok()?;

                Some(SpfExternalNetwork {
                    adv_rtr: lsa.hdr.adv_rtr,
                    e_bit: lsa_body.flags.contains(LsaAsExternalFlags::E),
                    prefix,
                    prefix_options: Default::default(),
                    metric: lsa_body.metric,
                    fwd_addr: lsa_body.fwd_addr,
                    tag: Some(lsa_body.tag),
                })
            })
    }

    fn area_router_information<'a>(
        lsdb: &'a Lsdb<Self>,
        router_id: Ipv4Addr,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> SpfRouterInfo<'a> {
        let mut ri_agg = SpfRouterInfo::default();

        for ri_lsa in lsdb
            .iter_by_type_advrtr(
                lsa_entries,
                LsaTypeCode::OpaqueArea.into(),
                router_id,
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .map(|lsa| lsa.body.as_opaque_area().unwrap())
            .filter_map(|lsa_body| lsa_body.as_router_info())
        {
            if let Some(sr_algo) = &ri_lsa.sr_algo {
                // When multiple SR-Algorithm TLVs are received from a given
                // router, the receiver MUST use the first occurrence of the TLV
                // in the Router Information Opaque LSA.
                //
                // If the SR-Algorithm TLV appears in multiple RI Opaque LSAs
                // that have the same flooding scope, the SR-Algorithm TLV in RI
                // Opaque LSA with the numerically smallest Instance ID MUST be
                // used and subsequent instances of the SR-Algorithm TLV MUST be
                // ignored.
                ri_agg.sr_algo.get_or_insert(sr_algo);
            }

            // Multiple occurrences of the SID/Label Range TLV MAY be advertised
            // in order to advertise multiple ranges.
            ri_agg.srgb.extend(&ri_lsa.srgb);
        }

        ri_agg
    }

    fn area_opaque_data_compile(
        area: &mut Area<Self>,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) {
        area.state.version.ext_prefix_db.clear();

        for (adv_rtr, lsa_body) in area
            .state
            .lsdb
            .iter_by_type(lsa_entries, LsaTypeCode::OpaqueArea.into())
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .map(|lsa| (lsa.hdr.adv_rtr, lsa.body.as_opaque_area().unwrap()))
        {
            if let Some(lsa_body) = lsa_body.as_ext_prefix() {
                // If this TLV is advertised multiple times for the same prefix
                // in different OSPFv2 Extended Prefix Opaque LSAs originated by
                // the same OSPFv2 router, the OSPFv2 advertising router is
                // re-originating OSPFv2 Extended Prefix Opaque LSAs for
                // multiple prefixes and is most likely repacking
                // Extended-Prefix-TLVs in OSPFv2 Extended Prefix Opaque LSAs.
                // In this case, the Extended-Prefix-TLV in the OSPFv2 Extended
                // Prefix Opaque LSA with the smallest Opaque ID is used by
                // receiving OSPFv2 routers.
                for (prefix, tlv) in &lsa_body.prefixes {
                    area.state
                        .version
                        .ext_prefix_db
                        .entry((adv_rtr, *prefix))
                        .or_insert_with(|| tlv.clone());
                }
            }
        }
    }
}

// ===== helper functions =====

fn route_prefix_sids(
    area: &Area<Ospfv2>,
    adv_rtr: Ipv4Addr,
    prefix: &Ipv4Network,
    route_type: ExtPrefixRouteType,
) -> BTreeMap<IgpAlgoType, PrefixSid> {
    let mut prefix_sids = BTreeMap::new();

    if let Some(prefix_sid) = area
        .state
        .version
        .ext_prefix_db
        .get(&(adv_rtr, *prefix))
        .filter(|tlv| {
            route_type == tlv.route_type
                || route_type == ExtPrefixRouteType::Unspecified
        })
        .and_then(|tlv| tlv.prefix_sids.get(&IgpAlgoType::Spf))
    {
        prefix_sids.insert(IgpAlgoType::Spf, *prefix_sid);
    }

    prefix_sids
}

// ===== helpers =====

// The `Link Data` an interface advertises for its own Router-LSA links
// (RFC 2328 A.4.2): its address, except that an unnumbered point-to-point link
// carries the ifindex and a virtual link carries the source address chosen for
// it. This is the Router-LSA emitter's rule read back, so it has to stay in
// step with `ospfv2/lsdb.rs`.
fn iface_link_data(
    link_type: LsaRouterLinkType,
    unnumbered: bool,
    ifindex: Option<u32>,
    primary_addr: Option<Ipv4Addr>,
    vlink_src_addr: Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    match link_type {
        LsaRouterLinkType::VirtualLink => vlink_src_addr,
        LsaRouterLinkType::PointToPoint if unnumbered => {
            ifindex.map(Ipv4Addr::from)
        }
        LsaRouterLinkType::PointToPoint | LsaRouterLinkType::TransitNetwork => {
            primary_addr
        }
        // A stub link names a prefix, not an interface.
        LsaRouterLinkType::StubNetwork => None,
    }
}

// Whether `iface` is the interface that originated `link`.
fn iface_matches_link(iface: &Interface<Ospfv2>, link: &LsaRouterLink) -> bool {
    iface_link_data(
        link.link_type,
        iface.system.unnumbered,
        iface.system.ifindex,
        iface.system.primary_addr.map(|addr| addr.ip()),
        iface.state.src_addr,
    ) == Some(link.link_data)
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use const_addrs::ip4;

    use super::*;

    // The two facts resolution needs from an interface, plus the neighbor
    // count the superseded positional rule filtered on.
    struct Iface {
        name: &'static str,
        link_type: LsaRouterLinkType,
        unnumbered: bool,
        ifindex: Option<u32>,
        primary_addr: Option<Ipv4Addr>,
        vlink_src_addr: Option<Ipv4Addr>,
        neighbors: usize,
    }

    fn broadcast(
        name: &'static str,
        primary_addr: Ipv4Addr,
        neighbors: usize,
    ) -> Iface {
        Iface {
            name,
            link_type: LsaRouterLinkType::TransitNetwork,
            unnumbered: false,
            ifindex: None,
            primary_addr: Some(primary_addr),
            vlink_src_addr: None,
            neighbors,
        }
    }

    // Resolution as it now is: by the identity the link carries.
    fn by_identity(
        ifaces: &[Iface],
        link_type: LsaRouterLinkType,
        link_data: Ipv4Addr,
    ) -> Option<&'static str> {
        ifaces
            .iter()
            .find(|iface| {
                iface_link_data(
                    link_type,
                    iface.unnumbered,
                    iface.ifindex,
                    iface.primary_addr,
                    iface.vlink_src_addr,
                ) == Some(link_data)
            })
            .map(|iface| iface.name)
    }

    // Resolution as it was: by position among the interfaces that have any
    // neighbor, counted against the link's position in the Router-LSA.
    fn by_position(ifaces: &[Iface], link_pos: usize) -> Option<&'static str> {
        ifaces
            .iter()
            .filter(|iface| iface.neighbors > 0)
            .nth(link_pos)
            .map(|iface| iface.name)
    }

    // RFC 2328 A.4.2, one case per link type. A mistake here is invisible at
    // runtime, because the wrong answer is another live interface.
    #[test]
    fn link_data_follows_the_emitter() {
        let addr = ip4!("10.199.3.1");
        let src = ip4!("10.0.0.1");

        assert_eq!(
            iface_link_data(
                LsaRouterLinkType::TransitNetwork,
                false,
                Some(7),
                Some(addr),
                None
            ),
            Some(addr)
        );
        assert_eq!(
            iface_link_data(
                LsaRouterLinkType::PointToPoint,
                false,
                Some(7),
                Some(addr),
                None
            ),
            Some(addr)
        );
        // Unnumbered point-to-point links carry the ifindex, not an address.
        assert_eq!(
            iface_link_data(
                LsaRouterLinkType::PointToPoint,
                true,
                Some(7),
                Some(addr),
                None
            ),
            Some(Ipv4Addr::from(7u32))
        );
        assert_eq!(
            iface_link_data(
                LsaRouterLinkType::VirtualLink,
                false,
                Some(7),
                Some(addr),
                Some(src)
            ),
            Some(src)
        );
        // A stub link names a prefix; no interface answers for it.
        assert_eq!(
            iface_link_data(
                LsaRouterLinkType::StubNetwork,
                false,
                Some(7),
                Some(addr),
                None
            ),
            None
        );
    }

    // A rate-limited Router-LSA still lists a link whose interface is down, so
    // every surviving link after it sits at a position no live interface
    // occupies. Measured on hardware as a multi-second blackhole: the lookup
    // ran off the end and the whole subtree was dropped.
    #[test]
    fn stale_lsa_does_not_shift_the_survivor() {
        // Name order is what decides the positions; these are cfab's.
        let ifaces = [
            broadcast("cfab-cl", ip4!("10.199.1.1"), 0), // died, still in LSA
            broadcast("cfab-cl-b2", ip4!("10.199.3.1"), 1),
        ];

        // The stale LSA lists cfab-cl at 0 and the survivor at 1.
        assert_eq!(
            by_identity(
                &ifaces,
                LsaRouterLinkType::TransitNetwork,
                ip4!("10.199.3.1")
            ),
            Some("cfab-cl-b2")
        );
        // Positionally the survivor is unreachable: one live interface, and
        // the link sits at index 1.
        assert_eq!(by_position(&ifaces, 1), None);
    }

    // The other direction of the same desync, and the dangerous one. An
    // adjacency that is not yet Full contributes stub links, which hold no
    // position, but the interface still has a neighbor. Positions then run
    // short and the lookup returns a live interface -- the wrong one, with no
    // error and nothing logged.
    #[test]
    fn forming_adjacency_does_not_silently_pick_the_wrong_interface() {
        let ifaces = [
            broadcast("eth0", ip4!("10.0.1.1"), 1), // neighbor in 2-Way: stub
            broadcast("eth1", ip4!("10.0.2.1"), 1), // Full: transit at pos 0
        ];

        assert_eq!(
            by_identity(
                &ifaces,
                LsaRouterLinkType::TransitNetwork,
                ip4!("10.0.2.1")
            ),
            Some("eth1")
        );
        assert_eq!(by_position(&ifaces, 0), Some("eth0"));
    }

    // A point-to-multipoint interface contributes one link per fully adjacent
    // neighbor, so positions outrun the interface list with nothing stale and
    // no adjacency forming.
    #[test]
    fn multipoint_interface_answers_for_each_of_its_links() {
        let ifaces = [Iface {
            link_type: LsaRouterLinkType::PointToPoint,
            ..broadcast("eth0", ip4!("10.0.1.1"), 2)
        }];

        for _ in 0..2 {
            assert_eq!(
                by_identity(
                    &ifaces,
                    LsaRouterLinkType::PointToPoint,
                    ip4!("10.0.1.1")
                ),
                Some("eth0")
            );
        }
        assert_eq!(by_position(&ifaces, 1), None);
    }
}
