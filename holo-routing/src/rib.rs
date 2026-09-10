//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap, btree_map, hash_map};
use std::net::IpAddr;

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use derive_new::new;
use holo_utils::ibus::{IbusClient, IbusClientId, IbusSender};
use holo_utils::ip::{AddressFamily, IpAddrExt};
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    FibPolicy, LabelInstallMsg, LabelUninstallMsg, Nexthop, RouteKeyMsg,
    RouteKind, RouteMsg, RouteOpaqueAttrs,
};
use ipnetwork::IpNetwork;
use prefix_trie::joint::map::JointPrefixMap;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};

use crate::interface::Interfaces;
use crate::netlink::NetlinkRequest;
use crate::{ibus, netlink};

#[derive(Debug)]
pub struct Rib {
    pub ip: JointPrefixMap<IpNetwork, Vec<Route>>,
    pub mpls: BTreeMap<Label, Route>,
    pub nht: HashMap<IpAddr, NhtEntry>,
    pub ip_update_queue: BTreeSet<IpNetwork>,
    pub mpls_update_queue: BTreeSet<Label>,
    pub update_queue_tx: UnboundedSender<()>,
    pub subscriptions: HashMap<usize, RedistributeSub>,
}

#[derive(Clone, Debug, new)]
pub struct Route {
    pub protocol: Protocol,
    pub owner: IbusClientId,
    pub kind: RouteKind,
    pub distance: u32,
    pub metric: u32,
    pub tag: Option<u32>,
    pub opaque_attrs: RouteOpaqueAttrs,
    pub nexthops: Box<[Nexthop]>,
    pub last_updated: DateTime<Utc>,
    pub flags: RouteFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct RouteFlags: u8 {
        const ACTIVE = 0x01;
        const REMOVED = 0x02;
    }
}

#[derive(Clone, Debug, Default)]
pub struct NhtEntry {
    pub metric: Option<u32>,
    pub subscriptions: HashMap<usize, IbusSender>,
}

#[derive(Debug)]
#[derive(new)]
pub struct RedistributeSub {
    pub protocols: BTreeSet<(AddressFamily, Protocol)>,
    pub tx: IbusSender,
}

// ===== impl Rib =====

impl Rib {
    pub(crate) fn new(update_queue_tx: UnboundedSender<()>) -> Self {
        Self {
            ip: Default::default(),
            mpls: Default::default(),
            nht: Default::default(),
            ip_update_queue: Default::default(),
            mpls_update_queue: Default::default(),
            update_queue_tx,
            subscriptions: Default::default(),
        }
    }

    // Adds IP route to the RIB.
    pub(crate) fn ip_route_add(&mut self, msg: RouteMsg, owner: IbusClientId) {
        let nexthops = self.resolve_nexthops(msg.nexthops);
        let rib_prefix = self.prefix_entry(msg.prefix);
        // A prefix holds one entry per (distance, protocol). Keying on the
        // distance alone would let two protocols that happen to share one
        // collapse into a single entry carrying the first protocol's label and
        // the second's nexthops, after which `ip_route_del` deletes the wrong
        // one. The list stays sorted by distance so the best route is at index
        // 0; among equal distances the protocol only breaks the tie
        // deterministically.
        match rib_prefix
            .binary_search_by_key(&(msg.distance, msg.protocol), |route| {
                (route.distance, route.protocol)
            }) {
            Ok(idx) => {
                // Update the existing IP route with the new information.
                let route = &mut rib_prefix[idx];
                route.owner = owner;
                route.kind = msg.kind;
                route.metric = msg.metric;
                route.tag = msg.tag;
                route.opaque_attrs = msg.opaque_attrs;
                route.nexthops = nexthops;
                route.last_updated = Utc::now();
                route.flags.remove(RouteFlags::REMOVED);
            }
            Err(idx) => {
                // If the IP route does not exist, create a new entry,
                // keeping the list sorted by distance.
                rib_prefix.insert(
                    idx,
                    Route::new(
                        msg.protocol,
                        owner,
                        msg.kind,
                        msg.distance,
                        msg.metric,
                        msg.tag,
                        msg.opaque_attrs,
                        nexthops,
                        Utc::now(),
                        RouteFlags::empty(),
                    ),
                );
            }
        }

        // Add IP route to the update queue.
        self.ip_update_queue_add(msg.prefix);
    }

    // Removes IP route from the RIB.
    pub(crate) fn ip_route_del(&mut self, msg: RouteKeyMsg) {
        let rib_prefix = self.prefix_entry(msg.prefix);

        // Mark every entry advertised by that protocol as removed. The
        // withdrawal carries no distance, so it withdraws all of the
        // protocol's entries for the prefix, not just the first one.
        let mut found = false;
        for route in rib_prefix
            .iter_mut()
            .filter(|route| route.protocol == msg.protocol)
        {
            route.flags.insert(RouteFlags::REMOVED);
            found = true;
        }

        if found {
            // Add IP route to the update queue.
            self.ip_update_queue_add(msg.prefix);
        }
    }

    // Adds MPLS route to the RIB.
    pub(crate) fn mpls_route_add(
        &mut self,
        msg: LabelInstallMsg,
        owner: IbusClientId,
    ) {
        let nexthops = self.resolve_nexthops(msg.nexthops);
        match self.mpls.entry(msg.label) {
            btree_map::Entry::Vacant(v) => {
                // If the MPLS route does not exist, create a new entry.
                v.insert(Route::new(
                    msg.protocol,
                    owner,
                    RouteKind::Unicast,
                    0,
                    0,
                    None,
                    RouteOpaqueAttrs::None,
                    nexthops.clone(),
                    Utc::now(),
                    RouteFlags::empty(),
                ));
            }
            btree_map::Entry::Occupied(o) => {
                let route = o.into_mut();

                // Update the existing MPLS route with the new information.
                route.owner = owner;
                route.protocol = msg.protocol;
                if msg.replace {
                    route.replace_nexthops(&nexthops);
                } else {
                    route.merge_nexthops(&nexthops);
                }
                route.last_updated = Utc::now();
                route.flags.remove(RouteFlags::REMOVED);
            }
        }

        // Add MPLS route to the update queue.
        self.mpls_update_queue_add(msg.label);

        // Check for the associated IP route.
        if let Some((protocol, prefix)) = msg.route {
            let rib_prefix = self.prefix_entry(prefix);
            if let Some(route) = rib_prefix
                .iter_mut()
                .find(|route| route.protocol == protocol)
            {
                // Update route's nexthop labels.
                if msg.replace {
                    route.replace_nexthops_labels(&nexthops);
                } else {
                    route.merge_nexthops_labels(&nexthops);
                }

                // Add IP route to the update queue.
                self.ip_update_queue_add(prefix);
            }
        }
    }

    // Removes MPLS route from the RIB.
    pub(crate) fn mpls_route_del(&mut self, msg: LabelUninstallMsg) {
        // Find MPLS route entry.
        let btree_map::Entry::Occupied(mut o) = self.mpls.entry(msg.label)
        else {
            return;
        };
        let route = o.get_mut();
        if route.protocol != msg.protocol {
            return;
        }

        if msg.nexthops.is_empty() {
            // Mark MPLS route as removed.
            route.flags.insert(RouteFlags::REMOVED);

            // Add MPLS route to the update queue.
            self.mpls_update_queue_add(msg.label);

            // Check for the associated IP route.
            if let Some((protocol, prefix)) = msg.route {
                let rib_prefix = self.prefix_entry(prefix);
                if let Some(route) = rib_prefix
                    .iter_mut()
                    .find(|route| route.protocol == protocol)
                {
                    // Remove route's nexthop labels.
                    route.remove_nexthops_labels();

                    // Add IP route to the update queue.
                    self.ip_update_queue_add(prefix);
                }
            }
        } else {
            // Remove nexthops from the MPLS route.
            for route_nh in route.nexthops.iter_mut() {
                if msg.nexthops.iter().any(|msg_nh| route_nh.matches(msg_nh)) {
                    route_nh.remove_labels();
                }
            }

            // Add MPLS route to the update queue.
            self.mpls_update_queue_add(msg.label);

            // Check for the associated IP route.
            if let Some((protocol, prefix)) = msg.route {
                let rib_prefix = self.prefix_entry(prefix);
                if let Some(route) = rib_prefix
                    .iter_mut()
                    .find(|route| route.protocol == protocol)
                {
                    // Remove nexthop labels from the IP route.
                    for route_nh in route.nexthops.iter_mut() {
                        if msg
                            .nexthops
                            .iter()
                            .any(|msg_nh| route_nh.matches(msg_nh))
                        {
                            route_nh.remove_labels();
                        }
                    }
                }

                // Add IP route to the update queue.
                self.ip_update_queue_add(prefix);
            }
        }
    }

    // Nexthop tracking registration.
    pub(crate) fn nht_add(&mut self, client: IbusClient, addr: IpAddr) {
        debug!(%addr, "nexthop tracking add");
        let metric = self.nht_evaluate(&addr);
        let nhte = self.nht.entry(addr).or_default();
        nhte.metric = metric;
        nhte.subscriptions.insert(client.id, client.tx);
        ibus::notify_nht_update(addr, nhte);
    }

    // Nexthop tracking unregistration.
    pub(crate) fn nht_del(&mut self, id: IbusClientId, addr: IpAddr) {
        debug!(%addr, "nexthop tracking delete");
        if let hash_map::Entry::Occupied(mut o) = self.nht.entry(addr) {
            let nhte = o.get_mut();
            nhte.subscriptions.remove(&id);
            if nhte.subscriptions.is_empty() {
                o.remove();
            }
        }
    }

    // Evaluates the reachability of the given nexthop address and returns
    // the metric of the route used to reach it.
    fn nht_evaluate(&self, addr: &IpAddr) -> Option<u32> {
        self.prefix_longest_match(addr).map(|route| route.metric)
    }

    // Processes routes present in the update queue.
    pub(crate) fn process_rib_update_queue(
        &mut self,
        interfaces: &Interfaces,
        netlink_tx: &UnboundedSender<NetlinkRequest>,
        policy: &FibPolicy,
    ) {
        // Process IP update queue.
        while let Some(prefix) = self.ip_update_queue.pop_first() {
            let rib_prefix = self.ip.entry(prefix).or_default();

            // Find the protocol and administrative distance of the old best
            // route, if one exists. The distance is the kernel priority the
            // route was installed with, so it is needed to delete it.
            let old_best = rib_prefix
                .iter()
                .find(|route| route.flags.contains(RouteFlags::ACTIVE))
                .map(|route| (route.protocol, route.distance));

            // Remove routes marked with the REMOVED flag.
            rib_prefix
                .retain(|route| !route.flags.contains(RouteFlags::REMOVED));

            // Select and (re)install the best route for this prefix.
            let mut new_best = None;
            for (idx, route) in rib_prefix.iter_mut().enumerate() {
                if idx == 0 {
                    // Mark the route as the preferred one.
                    route.flags.insert(RouteFlags::ACTIVE);
                    new_best = Some((route.protocol, route.distance));

                    // Install the route using the netlink handle.
                    if route.protocol != Protocol::DIRECT {
                        netlink::ip_route_install(
                            netlink_tx, &prefix, route, interfaces, policy,
                        );
                    }

                    // Notify protocol instances about the updated route.
                    for sub in self.subscriptions.values() {
                        ibus::notify_redistribute_add(sub, prefix, route);
                    }
                } else {
                    // Remove the preferred flag for other routes.
                    route.flags.remove(RouteFlags::ACTIVE);
                }
            }

            match (old_best, new_best) {
                (
                    Some((old_protocol, old_distance)),
                    Some((new_protocol, new_distance)),
                ) => {
                    if old_distance != new_distance
                        && old_protocol != Protocol::DIRECT
                    {
                        // The new best route was installed at a different
                        // kernel priority, so NLM_F_REPLACE did not overwrite
                        // the old one: it has to be deleted explicitly. Done
                        // after the install so the prefix is never
                        // unreachable.
                        netlink::ip_route_uninstall(
                            netlink_tx,
                            &prefix,
                            old_protocol,
                            old_distance,
                            policy,
                        );
                    }

                    if old_protocol != new_protocol {
                        // The prefix changed hands. Subscribers that
                        // redistribute the old protocol but not the new one
                        // get no add above, so without this delete they keep
                        // advertising the prefix indefinitely.
                        //
                        // Sent after the add: the delete is qualified by
                        // protocol, so a subscriber that redistributes both
                        // protocols ignores it and keeps the entry the add
                        // just installed. Sending it first would make every
                        // change of protocol a withdraw followed by a
                        // readvertisement.
                        for sub in self.subscriptions.values() {
                            ibus::notify_redistribute_del(
                                sub,
                                prefix,
                                old_protocol,
                            );
                        }
                    }
                }
                (Some((old_protocol, old_distance)), None) => {
                    // Uninstall the old best route using the netlink handle.
                    if old_protocol != Protocol::DIRECT {
                        netlink::ip_route_uninstall(
                            netlink_tx,
                            &prefix,
                            old_protocol,
                            old_distance,
                            policy,
                        );
                    }

                    // Notify protocol instances about the deleted route.
                    for sub in self.subscriptions.values() {
                        ibus::notify_redistribute_del(
                            sub,
                            prefix,
                            old_protocol,
                        );
                    }
                }
                _ => {}
            }

            // Check if there are no routes left for this prefix.
            if rib_prefix.is_empty() {
                // Remove prefix entry from the RIB.
                self.ip.remove(&prefix);
            }
        }

        // Process MPLS update queue.
        while let Some(label) = self.mpls_update_queue.pop_first() {
            let Some(route) = self.mpls.get_mut(&label) else {
                continue;
            };

            // Check if the route was marked for removal.
            if route.flags.contains(RouteFlags::REMOVED) {
                // Uninstall the MPLS route using the netlink handle.
                netlink::mpls_route_uninstall(
                    netlink_tx,
                    label,
                    route.protocol,
                    policy,
                );

                // Effectively remove the MPLS route.
                self.mpls.remove(&label);
                continue;
            }

            // Install the route using the netlink handle.
            netlink::mpls_route_install(
                netlink_tx, label, route, interfaces, policy,
            );
        }

        // Reevaluate all registered nexthops.
        let mut nht = std::mem::take(&mut self.nht);
        for (addr, nhte) in &mut nht {
            let new_metric = self.nht_evaluate(addr);
            if new_metric != nhte.metric {
                debug!(
                    %addr, old_metric = ?nhte.metric, ?new_metric,
                    "nexthop tracking update"
                );
                nhte.metric = new_metric;
                ibus::notify_nht_update(*addr, nhte);
            }
        }
        self.nht = nht;
    }

    // Returns RIB entry associated to the given IP prefix.
    //
    // The returned list of routes is sorted by administrative distance.
    fn prefix_entry(&mut self, prefix: IpNetwork) -> &mut Vec<Route> {
        self.ip.entry(prefix).or_default()
    }

    // Returns the longest matching route for the given IP address.
    fn prefix_longest_match(&self, addr: &IpAddr) -> Option<&Route> {
        let (_, lpm) = self.ip.get_lpm(&addr.to_host_prefix())?;
        lpm.first()
            .filter(|route| route.flags.contains(RouteFlags::ACTIVE))
            .filter(|route| !route.flags.contains(RouteFlags::REMOVED))
    }

    // Resolves the recursive next-hops in the provided set of next-hops.
    //
    // Note that only one level of recursion is resolved. If the resolved
    // next-hops contain recursive next-hops themselves, those will not be
    // resolved further.
    fn resolve_nexthops(&self, nexthops: Vec<Nexthop>) -> Box<[Nexthop]> {
        nexthops
            .into_iter()
            .map(|mut nexthop| {
                if let Nexthop::Recursive {
                    addr,
                    resolved,
                    labels,
                } = &mut nexthop
                {
                    if let Some(route) = self.prefix_longest_match(addr) {
                        if route.protocol == Protocol::DIRECT
                            && let Some(Nexthop::Interface { ifindex }) =
                                route.nexthops.first()
                        {
                            // When recursing over connected routes, preserve
                            // the original next-hop address.
                            *resolved = [Nexthop::Address {
                                ifindex: *ifindex,
                                addr: *addr,
                                labels: labels.clone(),
                            }]
                            .into();
                        } else {
                            // Copy next-hops of the resolving route.
                            resolved.clone_from(&route.nexthops);
                        }
                    } else {
                        warn!(%addr, "failed to resolve recursive nexthop");
                    }
                }
                nexthop
            })
            .collect()
    }

    // Adds IP route to the update queue.
    fn ip_update_queue_add(&mut self, prefix: IpNetwork) {
        self.ip_update_queue.insert(prefix);
        let _ = self.update_queue_tx.send(());
    }

    // Adds MPLS label to the update queue.
    fn mpls_update_queue_add(&mut self, label: Label) {
        self.mpls_update_queue.insert(label);
        let _ = self.update_queue_tx.send(());
    }

    // Removes all IP and MPLS routes installed by the given client.
    pub(crate) fn route_remove_all_by_owner(&mut self, owner: IbusClientId) {
        for (prefix, rib_prefix) in self.ip.iter_mut() {
            for route in rib_prefix.iter_mut() {
                if route.owner == owner {
                    route.flags.insert(RouteFlags::REMOVED);
                    self.ip_update_queue.insert(prefix);
                }
            }
        }
        for (label, route) in &mut self.mpls {
            if route.owner == owner {
                route.flags.insert(RouteFlags::REMOVED);
                self.mpls_update_queue.insert(*label);
            }
        }
        let _ = self.update_queue_tx.send(());
    }

    // Uninstall all routes.
    pub(crate) fn route_uninstall_all(
        &mut self,
        netlink_tx: &UnboundedSender<NetlinkRequest>,
        policy: &FibPolicy,
    ) {
        for (prefix, rib_prefix) in &self.ip {
            if let Some(route) = rib_prefix
                .iter()
                .find(|route| route.flags.contains(RouteFlags::ACTIVE))
            {
                netlink::ip_route_uninstall(
                    netlink_tx,
                    &prefix,
                    route.protocol,
                    route.distance,
                    policy,
                );
            }
        }
        for (label, route) in &self.mpls {
            netlink::mpls_route_uninstall(
                netlink_tx,
                *label,
                route.protocol,
                policy,
            );
        }
    }
}

// ===== impl Route =====

impl Route {
    // Merges the provided set of nexthops into this route.
    //
    // If a matching nexthop is found, its labels are copied. Otherwise, the
    // nexthop is added.
    fn merge_nexthops(&mut self, other_nhs: &[Nexthop]) {
        let mut nhs = std::mem::take(&mut self.nexthops).into_vec();
        for other_nh in other_nhs.iter() {
            if let Some(nh) =
                nhs.iter_mut().find(|nh| nh.matches_no_labels(other_nh))
            {
                nh.copy_labels(other_nh);
            } else {
                nhs.push(other_nh.clone());
            }
        }
        self.nexthops = nhs.into();
    }

    // Merges the provided nexthop labels from another set into this route.
    //
    // If a matching nexthop is found, its labels are copied. Otherwise, the
    // nexthop is ignored.
    fn merge_nexthops_labels(&mut self, other_nhs: &[Nexthop]) {
        for nh in self.nexthops.iter_mut() {
            if let Some(other_nh) = other_nhs
                .iter()
                .find(|other_nh| nh.matches_no_labels(other_nh))
            {
                nh.copy_labels(other_nh);
            }
        }
    }

    // Replaces the nexthops in this route with the provided set of nexthops.
    fn replace_nexthops(&mut self, other_nhs: &[Nexthop]) {
        self.nexthops = other_nhs.into();
    }

    // Replaces the provided next hop labels from another set into this route.
    //
    // It matches and copies labels for existing nexthops and removes labels
    // for unmatched nexthops.
    fn replace_nexthops_labels(&mut self, other_nhs: &[Nexthop]) {
        for nh in self.nexthops.iter_mut() {
            if let Some(other_nh) = other_nhs
                .iter()
                .find(|other_nh| nh.matches_no_labels(other_nh))
            {
                nh.copy_labels(other_nh);
            } else {
                nh.remove_labels();
            }
        }
    }

    // Removes labels from all nexthops of the route.
    fn remove_nexthops_labels(&mut self) {
        for nh in self.nexthops.iter_mut() {
            nh.remove_labels();
        }
    }
}

#[cfg(test)]
mod tests {
    use holo_utils::ibus::IbusMsg;
    use holo_utils::southbound::RouteOpaqueAttrs;
    use netlink_packet_route::route::RouteAttribute;
    use tokio::sync::mpsc;

    use super::*;
    use crate::netlink::NetlinkRequest;

    const PREFIX: &str = "10.0.1.0/24";

    // A netlink request, reduced to what these tests assert on.
    #[derive(Debug, Eq, PartialEq)]
    enum Req {
        Install(u32),
        Delete(u32),
    }

    // A redistribution notification, reduced to what these tests assert on.
    #[derive(Debug, Eq, PartialEq)]
    enum Redist {
        Add(Protocol),
        Del(Protocol),
    }

    fn prefix() -> IpNetwork {
        PREFIX.parse().unwrap()
    }

    fn route_msg(protocol: Protocol, distance: u32, ifindex: u32) -> RouteMsg {
        RouteMsg {
            protocol,
            kind: RouteKind::Unicast,
            prefix: prefix(),
            distance,
            metric: 0,
            tag: None,
            opaque_attrs: RouteOpaqueAttrs::None,
            nexthops: vec![Nexthop::Interface { ifindex }],
        }
    }

    fn priority_of(msg: &netlink_packet_route::route::RouteMessage) -> u32 {
        msg.attributes
            .iter()
            .find_map(|attr| match attr {
                RouteAttribute::Priority(priority) => Some(*priority),
                _ => None,
            })
            .expect("netlink request carries no RTA_PRIORITY")
    }

    // Drives the update queue and returns the netlink requests it emitted, in
    // the order they were enqueued.
    fn drain(
        rib: &mut Rib,
        netlink_rx: &mut mpsc::UnboundedReceiver<NetlinkRequest>,
        netlink_tx: &UnboundedSender<NetlinkRequest>,
    ) -> Vec<Req> {
        rib.process_rib_update_queue(
            &Interfaces::default(),
            netlink_tx,
            &FibPolicy::default(),
        );
        let mut reqs = vec![];
        while let Ok(req) = netlink_rx.try_recv() {
            match req {
                NetlinkRequest::RouteAdd(msg) => {
                    reqs.push(Req::Install(priority_of(&msg)))
                }
                NetlinkRequest::RouteDel(msg) => {
                    reqs.push(Req::Delete(priority_of(&msg)))
                }
            }
        }
        reqs
    }

    // Registers a redistribution subscription for the given IPv4 protocols
    // and returns the receiving end of its ibus channel.
    fn subscribe(
        rib: &mut Rib,
        protocols: &[Protocol],
    ) -> mpsc::UnboundedReceiver<IbusMsg> {
        let (ibus_tx, ibus_rx) = mpsc::unbounded_channel();
        let protocols = protocols
            .iter()
            .map(|protocol| (AddressFamily::Ipv4, *protocol))
            .collect();
        rib.subscriptions
            .insert(0, RedistributeSub::new(protocols, ibus_tx));
        ibus_rx
    }

    // Returns the redistribution notifications sent to a subscription, in the
    // order they were sent.
    fn drain_ibus(
        ibus_rx: &mut mpsc::UnboundedReceiver<IbusMsg>,
    ) -> Vec<Redist> {
        let mut msgs = vec![];
        while let Ok(msg) = ibus_rx.try_recv() {
            match msg {
                IbusMsg::RouteRedistributeAdd(msg) => {
                    msgs.push(Redist::Add(msg.protocol))
                }
                IbusMsg::RouteRedistributeDel(msg) => {
                    msgs.push(Redist::Del(msg.protocol))
                }
                _ => {}
            }
        }
        msgs
    }

    fn test_rib() -> (
        Rib,
        mpsc::UnboundedSender<NetlinkRequest>,
        mpsc::UnboundedReceiver<NetlinkRequest>,
    ) {
        let (update_queue_tx, _update_queue_rx) = mpsc::unbounded_channel();
        let (netlink_tx, netlink_rx) = mpsc::unbounded_channel();
        (Rib::new(update_queue_tx), netlink_tx, netlink_rx)
    }

    // A better route taking over must be installed before the old one is
    // deleted: the two occupy different kernel priorities, so a delete-first
    // order would leave the prefix unreachable in between.
    #[test]
    fn rib_update_installs_new_best_before_deleting_old() {
        let (mut rib, netlink_tx, mut netlink_rx) = test_rib();

        rib.ip_route_add(route_msg(Protocol::OSPFV2, 110, 2), 0);
        assert_eq!(
            drain(&mut rib, &mut netlink_rx, &netlink_tx),
            vec![Req::Install(110)]
        );

        rib.ip_route_add(route_msg(Protocol::STATIC, 1, 3), 0);
        assert_eq!(
            drain(&mut rib, &mut netlink_rx, &netlink_tx),
            vec![Req::Install(1), Req::Delete(110)]
        );
    }

    // Two protocols at the same distance replace each other in the kernel
    // through NLM_F_REPLACE, so the newly installed route must not be deleted
    // right after being installed.
    #[test]
    fn rib_update_same_distance_does_not_delete_new_best() {
        let (mut rib, netlink_tx, mut netlink_rx) = test_rib();

        rib.ip_route_add(route_msg(Protocol::OSPFV2, 110, 2), 0);
        assert_eq!(
            drain(&mut rib, &mut netlink_rx, &netlink_tx),
            vec![Req::Install(110)]
        );

        // ISIS sorts before OSPFv2 at an equal distance, so it becomes the
        // new best route.
        rib.ip_route_add(route_msg(Protocol::ISIS, 110, 3), 0);
        assert_eq!(
            drain(&mut rib, &mut netlink_rx, &netlink_tx),
            vec![Req::Install(110)]
        );
    }

    // The delete must carry the priority the route was installed with, not the
    // priority of whatever replaced it: RTM_DELROUTE matches on it.
    #[test]
    fn rib_update_delete_carries_installed_priority() {
        let (mut rib, netlink_tx, mut netlink_rx) = test_rib();

        rib.ip_route_add(route_msg(Protocol::OSPFV2, 110, 2), 0);
        assert_eq!(
            drain(&mut rib, &mut netlink_rx, &netlink_tx),
            vec![Req::Install(110)]
        );

        rib.ip_route_del(RouteKeyMsg {
            protocol: Protocol::OSPFV2,
            prefix: prefix(),
        });
        assert_eq!(
            drain(&mut rib, &mut netlink_rx, &netlink_tx),
            vec![Req::Delete(110)]
        );
    }

    // Two protocols advertising one prefix at the same administrative distance
    // are distinct RIB entries: keying on the distance alone made the second
    // one overwrite the first's nexthops while keeping its protocol label, and
    // withdrawing either then removed the wrong route.
    #[test]
    fn rib_two_protocols_at_one_distance_are_distinct_entries() {
        let (mut rib, netlink_tx, mut netlink_rx) = test_rib();

        rib.ip_route_add(route_msg(Protocol::ISIS, 110, 2), 0);
        rib.ip_route_add(route_msg(Protocol::OSPFV2, 110, 3), 0);
        drain(&mut rib, &mut netlink_rx, &netlink_tx);

        let entries = rib.ip.get(&prefix()).expect("prefix missing from RIB");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol, Protocol::ISIS);
        assert_eq!(entries[0].nexthops[0], Nexthop::Interface { ifindex: 2 });
        assert_eq!(entries[1].protocol, Protocol::OSPFV2);
        assert_eq!(entries[1].nexthops[0], Nexthop::Interface { ifindex: 3 });

        // Withdrawing IS-IS must leave the OSPFv2 route behind.
        rib.ip_route_del(RouteKeyMsg {
            protocol: Protocol::ISIS,
            prefix: prefix(),
        });
        drain(&mut rib, &mut netlink_rx, &netlink_tx);

        let entries = rib.ip.get(&prefix()).expect("prefix missing from RIB");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, Protocol::OSPFV2);
        assert_eq!(entries[0].nexthops[0], Nexthop::Interface { ifindex: 3 });
        assert!(entries[0].flags.contains(RouteFlags::ACTIVE));
    }

    // A subscriber that redistributes only the old best route's protocol gets
    // nothing when the new best route belongs to another protocol, so without
    // an explicit delete it keeps advertising the prefix forever. Observed on
    // the rack: a static route redistributed into OSPFv2 stayed as a type-5
    // LSA after the static route was deleted, because another router was
    // advertising the same prefix and became the new best route.
    #[test]
    fn rib_update_protocol_change_withdraws_old_protocol() {
        let (mut rib, netlink_tx, mut netlink_rx) = test_rib();
        let mut ibus_rx = subscribe(&mut rib, &[Protocol::STATIC]);

        rib.ip_route_add(route_msg(Protocol::OSPFV2, 110, 2), 0);
        rib.ip_route_add(route_msg(Protocol::STATIC, 1, 3), 0);
        drain(&mut rib, &mut netlink_rx, &netlink_tx);
        assert_eq!(
            drain_ibus(&mut ibus_rx),
            vec![Redist::Add(Protocol::STATIC)]
        );

        // The OSPFv2 route takes over as the best route.
        rib.ip_route_del(RouteKeyMsg {
            protocol: Protocol::STATIC,
            prefix: prefix(),
        });
        drain(&mut rib, &mut netlink_rx, &netlink_tx);
        assert_eq!(
            drain_ibus(&mut ibus_rx),
            vec![Redist::Del(Protocol::STATIC)]
        );
    }

    // A subscriber that redistributes both protocols must see the add for the
    // new best route before the delete for the old one, so that it never
    // withdraws the prefix in between.
    #[test]
    fn rib_update_protocol_change_adds_before_deleting() {
        let (mut rib, netlink_tx, mut netlink_rx) = test_rib();
        let mut ibus_rx =
            subscribe(&mut rib, &[Protocol::STATIC, Protocol::OSPFV2]);

        rib.ip_route_add(route_msg(Protocol::OSPFV2, 110, 2), 0);
        rib.ip_route_add(route_msg(Protocol::STATIC, 1, 3), 0);
        drain(&mut rib, &mut netlink_rx, &netlink_tx);
        drain_ibus(&mut ibus_rx);

        rib.ip_route_del(RouteKeyMsg {
            protocol: Protocol::STATIC,
            prefix: prefix(),
        });
        drain(&mut rib, &mut netlink_rx, &netlink_tx);
        assert_eq!(
            drain_ibus(&mut ibus_rx),
            vec![Redist::Add(Protocol::OSPFV2), Redist::Del(Protocol::STATIC)]
        );
    }

    // A best route replaced by one of the same protocol is a plain update: no
    // delete may follow it, or the subscriber would drop the prefix.
    #[test]
    fn rib_update_same_protocol_is_an_add_only() {
        let (mut rib, netlink_tx, mut netlink_rx) = test_rib();
        let mut ibus_rx = subscribe(&mut rib, &[Protocol::STATIC]);

        rib.ip_route_add(route_msg(Protocol::STATIC, 1, 2), 0);
        drain(&mut rib, &mut netlink_rx, &netlink_tx);
        drain_ibus(&mut ibus_rx);

        rib.ip_route_add(route_msg(Protocol::STATIC, 1, 3), 0);
        drain(&mut rib, &mut netlink_rx, &netlink_tx);
        assert_eq!(
            drain_ibus(&mut ibus_rx),
            vec![Redist::Add(Protocol::STATIC)]
        );
    }
}
