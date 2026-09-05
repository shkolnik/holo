//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use derive_new::new;
use holo_utils::bgp::{AfiSafi, RouteType};
use holo_utils::ip::IpNetworkKind;
use holo_utils::policy::{
    BgpNexthop, BgpPolicyAction, BgpPolicyCondition, BgpSetCommMethod,
    BgpSetCommOptions, BgpSetMed, DefaultPolicyType, MatchSets,
    MetricModification, Policy, PolicyAction, PolicyCondition, PolicyResult,
    PolicyType,
};
use holo_utils::southbound::RouteOpaqueAttrs;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use tokio::sync::mpsc::UnboundedSender;

use crate::packet::attribute::{Attrs, CommList, CommType};
use crate::rib::RouteOrigin;
use crate::tasks::messages::input::PolicyResultMsg;

// Maximum number of prefixes carried by a single policy apply message.
pub(crate) const POLICY_APPLY_BATCH_SIZE_MAX: usize = 4096;

// Represents a simplified version of `Route`, containing only information
// relevant for the application of routing policies.
#[derive(Clone, Debug)]
#[derive(new)]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct RoutePolicyInfo {
    pub origin: RouteOrigin,
    pub route_type: RouteType,
    pub tag: Option<u32>,
    pub opaque_attrs: Option<RouteOpaqueAttrs>,
    // Metric of the IGP route this route was redistributed from, if any.
    pub igp_metric: Option<u32>,
    pub attrs: Attrs,
}

// ===== global functions =====

// Applies neighbor import or export routing policies to a list of prefixes
// sharing the same attributes and sends the resulting policy decisions to
// the specified channel.
pub(crate) fn neighbor_apply(
    policy_type: PolicyType,
    nbr_addr: IpAddr,
    afi_safi: AfiSafi,
    prefixes: Vec<IpNetwork>,
    rpinfo: RoutePolicyInfo,
    policies: &[Arc<Policy>],
    match_sets: &MatchSets,
    default_policy: DefaultPolicyType,
    policy_resultp: &UnboundedSender<PolicyResultMsg>,
) {
    // Process policies for each prefix and collect the results, keeping
    // prefixes with the same result grouped so their shared attribute set is
    // carried only once.
    let mut results = vec![];
    let mut accepted = vec![];
    let mut rejected = vec![];
    let mut modified: BTreeMap<Attrs, Vec<IpNetwork>> = BTreeMap::new();
    for prefix in prefixes {
        match process_policies(
            policy_type,
            afi_safi,
            prefix,
            &rpinfo,
            policies,
            match_sets,
            default_policy,
        ) {
            PolicyResult::Accept(Cow::Borrowed(_)) => {
                accepted.push(prefix);
            }
            PolicyResult::Accept(Cow::Owned(rpinfo)) => {
                modified.entry(rpinfo.attrs).or_default().push(prefix);
            }
            PolicyResult::Reject => rejected.push(prefix),
        }
    }

    // Routes accepted with modified attributes, one group per distinct set.
    results.extend(modified.into_iter().map(|(attrs, prefixes)| {
        let rpinfo = RoutePolicyInfo::new(
            rpinfo.origin,
            rpinfo.route_type,
            rpinfo.tag,
            rpinfo.opaque_attrs,
            rpinfo.igp_metric,
            attrs,
        );
        (PolicyResult::Accept(rpinfo), prefixes)
    }));

    // Routes accepted with unmodified attributes.
    if !accepted.is_empty() {
        results.push((PolicyResult::Accept(rpinfo), accepted));
    }

    // Rejected routes.
    if !rejected.is_empty() {
        results.push((PolicyResult::Reject, rejected));
    }

    // Send the resulting policy decisions to the specified channel.
    let _ = policy_resultp.send(PolicyResultMsg::Neighbor {
        policy_type,
        nbr_addr,
        afi_safi,
        routes: results,
    });
}

// Applies redistribution import routing policies to the provided route and
// sends the resulting policy decision to the specified channel.
pub(crate) fn redistribute_apply(
    afi_safi: AfiSafi,
    prefix: IpNetwork,
    rpinfo: RoutePolicyInfo,
    policies: &[Arc<Policy>],
    match_sets: &MatchSets,
    default_policy: DefaultPolicyType,
    policy_resultp: &UnboundedSender<PolicyResultMsg>,
) {
    // Process routing policies.
    let result = process_policies(
        PolicyType::Import,
        afi_safi,
        prefix,
        &rpinfo,
        policies,
        match_sets,
        default_policy,
    )
    .map(Cow::into_owned);

    // Send the resulting policy decision to the specified channel.
    let _ = policy_resultp.send(PolicyResultMsg::Redistribute {
        afi_safi,
        prefix,
        result,
    });
}

// ===== helper functions =====

// Processes routing policies for a specific route and returns the policy
// result.
//
// The route policy info is cloned only when a policy action modifies it; the
// borrowed variant of the returned copy-on-write value means the route was
// accepted unmodified.
fn process_policies<'a>(
    policy_type: PolicyType,
    afi_safi: AfiSafi,
    prefix: IpNetwork,
    rpinfo: &'a RoutePolicyInfo,
    policies: &[Arc<Policy>],
    match_sets: &MatchSets,
    default_policy: DefaultPolicyType,
) -> PolicyResult<Cow<'a, RoutePolicyInfo>> {
    let igp_metric = rpinfo.igp_metric;
    let mut rpinfo = Cow::Borrowed(rpinfo);

    for stmt in policies.iter().flat_map(|policy| policy.stmts.values()) {
        // Check if all conditions in the policy statement are satisfied.
        if !stmt.conditions.values().all(|condition| {
            process_stmt_condition(
                afi_safi, &prefix, &rpinfo, condition, match_sets,
            )
        }) {
            continue;
        }

        // Process actions defined in the policy statement.
        let mut accept = false;
        for action in stmt.actions.values() {
            // The "policy-result" action doesn't modify the route, so
            // handle it here to keep the route policy info borrowed.
            if let PolicyAction::Accept(value) = action {
                if !*value {
                    return PolicyResult::Reject;
                }
                accept = true;
                continue;
            }

            process_stmt_action(
                &mut rpinfo.to_mut().attrs,
                action,
                policy_type,
                match_sets,
                igp_metric,
            );
        }

        // An "accept-route" action terminates the evaluation of the policy
        // chain.
        if accept {
            return PolicyResult::Accept(rpinfo);
        }
    }

    // Apply the default policy once the end of the policy chain is reached
    // without a final route disposition.
    if default_policy == DefaultPolicyType::RejectRoute {
        return PolicyResult::Reject;
    }

    PolicyResult::Accept(rpinfo)
}

// Processes a single condition statement within a routing policy.
//
// Returns a boolean value indicating whether the condition is met.
fn process_stmt_condition(
    afi_safi: AfiSafi,
    prefix: &IpNetwork,
    rpinfo: &RoutePolicyInfo,
    condition: &PolicyCondition,
    match_sets: &MatchSets,
) -> bool {
    let attrs = &rpinfo.attrs;
    match condition {
        // "source-protocol"
        PolicyCondition::SrcProtocol(value) => {
            let RouteOrigin::Protocol(protocol) = &rpinfo.origin else {
                return true;
            };

            protocol == value
        }
        // "match-interface"
        PolicyCondition::MatchInterface(_value) => {
            // TODO
            true
        }
        // "match-prefix-set"
        PolicyCondition::MatchPrefixSet(value) => {
            let af = prefix.address_family();
            match match_sets.prefixes.get(&(value.clone(), af)) {
                Some(set) => set.matches(prefix),
                None => false,
            }
        }
        // "match-neighbor-set"
        PolicyCondition::MatchNeighborSet(value) => {
            let RouteOrigin::Neighbor { remote_addr, .. } = &rpinfo.origin
            else {
                return true;
            };

            match match_sets.neighbors.get(value) {
                Some(set) => set.addrs.contains(remote_addr),
                None => false,
            }
        }
        // "match-tag-set"
        PolicyCondition::MatchTagSet(value) => {
            if let Some(tag) = &rpinfo.tag
                && let Some(set) = match_sets.tags.get(value)
            {
                set.tags.contains(tag)
            } else {
                false
            }
        }
        // "match-route-type"
        PolicyCondition::MatchRouteType(_value) => {
            let Some(_opaque_attrs) = &rpinfo.opaque_attrs else {
                return true;
            };

            // TODO
            true
        }
        // "bgp-conditions"
        PolicyCondition::Bgp(condition) => {
            let RouteOrigin::Neighbor { remote_addr, .. } = &rpinfo.origin
            else {
                return true;
            };

            match condition {
                // "local-pref"
                BgpPolicyCondition::LocalPref { value, op } => {
                    match attrs.base.local_pref {
                        Some(local_pref) => op.compare(value, &local_pref),
                        None => false,
                    }
                }
                // "med"
                BgpPolicyCondition::Med { value, op } => match attrs.base.med {
                    Some(med) => op.compare(value, &med),
                    None => false,
                },
                // "origin-eq"
                BgpPolicyCondition::Origin(origin) => {
                    attrs.base.origin == *origin
                }
                // "match-afi-safi"
                BgpPolicyCondition::MatchAfiSafi { values, match_type } => {
                    match_type.compare(values, &afi_safi)
                }
                // "match-neighbor"
                BgpPolicyCondition::MatchNeighbor { value, match_type } => {
                    match_type.compare(value, remote_addr)
                }
                // "route-type"
                BgpPolicyCondition::RouteType(value) => {
                    rpinfo.route_type == *value
                }
                // "community-count"
                BgpPolicyCondition::CommCount { value, op } => {
                    match &attrs.comm {
                        Some(comm) => op.compare(value, &(comm.0.len() as u32)),
                        None => false,
                    }
                }
                // "as-path-length"
                BgpPolicyCondition::AsPathLen { value, op } => {
                    op.compare(value, &(attrs.base.as_path.path_length()))
                }
                // "match-community-set"
                BgpPolicyCondition::MatchCommSet { value, match_type } => {
                    if let Some(comm) = &attrs.comm {
                        let set = match_sets.bgp.comms.get(value).unwrap();
                        match_type.compare(set, &comm.0)
                    } else {
                        false
                    }
                }
                // "match-ext-community-set"
                BgpPolicyCondition::MatchExtCommSet { value, match_type } => {
                    if let Some(ext_comm) = &attrs.ext_comm {
                        let set = match_sets.bgp.ext_comms.get(value).unwrap();
                        match_type.compare(set, &ext_comm.0)
                    } else {
                        false
                    }
                }
                // "match-ipv6-ext-community-set"
                BgpPolicyCondition::MatchExtv6CommSet { value, match_type } => {
                    if let Some(extv6_comm) = &attrs.extv6_comm {
                        let set =
                            match_sets.bgp.extv6_comms.get(value).unwrap();
                        match_type.compare(set, &extv6_comm.0)
                    } else {
                        false
                    }
                }
                // "match-large-community-set"
                BgpPolicyCondition::MatchLargeCommSet { value, match_type } => {
                    if let Some(large_comm) = &attrs.large_comm {
                        let set =
                            match_sets.bgp.large_comms.get(value).unwrap();
                        match_type.compare(set, &large_comm.0)
                    } else {
                        false
                    }
                }
                // "match-as-path-set"
                BgpPolicyCondition::MatchAsPathSet { value, match_type } => {
                    let set = match_sets.bgp.as_paths.get(value).unwrap();
                    let asns = attrs.base.as_path.iter().collect();
                    match_type.compare(set, &asns)
                }
                // "match-next-hop-set"
                BgpPolicyCondition::MatchNexthopSet { value, match_type } => {
                    let nexthop = match attrs.base.nexthop {
                        Some(nexthop) => BgpNexthop::Addr(nexthop),
                        None => BgpNexthop::NexthopSelf,
                    };
                    let set = match_sets.bgp.nexthops.get(value).unwrap();
                    match_type.compare(set, &nexthop)
                }
            }
        }
        // Ignore unsupported conditions.
        _ => true,
    }
}

// Processes a single action statement within a routing policy, updating the
// route's attributes accordingly.
fn process_stmt_action(
    attrs: &mut Attrs,
    action: &PolicyAction,
    policy_type: PolicyType,
    match_sets: &MatchSets,
    igp_metric: Option<u32>,
) {
    match action {
        // "set-metric"
        PolicyAction::SetMetric { value, mod_type } => match mod_type {
            MetricModification::Set => {
                attrs.base.med = Some(*value);
            }
            MetricModification::Add => {
                if let Some(med) = &mut attrs.base.med {
                    *med = med.saturating_add(*value);
                }
            }
            MetricModification::Subtract => {
                if let Some(med) = &mut attrs.base.med {
                    *med = med.saturating_sub(*value);
                }
            }
        },
        // "bgp-actions"
        PolicyAction::Bgp(action) => match action {
            // "set-route-origin"
            BgpPolicyAction::SetRouteOrigin(origin) => {
                attrs.base.origin = *origin
            }
            // "set-local-pref"
            BgpPolicyAction::SetLocalPref(local_pref) => {
                attrs.base.local_pref = Some(*local_pref);
            }
            // "set-next-hop"
            BgpPolicyAction::SetNexthop(set_nexthop) => {
                match set_nexthop {
                    BgpNexthop::Addr(addr) => {
                        attrs.base.nexthop = Some(*addr);
                    }
                    BgpNexthop::NexthopSelf => {
                        // Ignore the action in the import direction, as it
                        // would install a route with a local address as next
                        // hop.
                        if policy_type == PolicyType::Import {
                            return;
                        }

                        // Unsetting the next hop leaves it to be resolved to
                        // the source address of the session at transmission
                        // time.
                        attrs.base.nexthop = None;
                    }
                }

                // The link-local next hop identifies the router that
                // advertised the route, which is no longer the requested
                // next hop.
                attrs.base.ll_nexthop = None;
            }
            // "set-med"
            BgpPolicyAction::SetMed(set_med) => match set_med {
                BgpSetMed::Add(value) => {
                    if let Some(med) = &mut attrs.base.med {
                        *med = med.saturating_add(*value);
                    }
                }
                BgpSetMed::Subtract(value) => {
                    if let Some(med) = &mut attrs.base.med {
                        *med = med.saturating_sub(*value);
                    }
                }
                BgpSetMed::Set(value) => {
                    attrs.base.med = Some(*value);
                }
                BgpSetMed::Igp => {
                    // The IGP metric is known only for routes redistributed
                    // from an IGP; leave the MED alone for all others.
                    if let Some(igp_metric) = igp_metric {
                        attrs.base.med = Some(igp_metric);
                    }
                }
                BgpSetMed::MedPlusIgp => {
                    if let Some(igp_metric) = igp_metric {
                        attrs.base.med = Some(
                            attrs
                                .base
                                .med
                                .unwrap_or(0)
                                .saturating_add(igp_metric),
                        );
                    }
                }
            },
            // "set-as-path-prepend"
            BgpPolicyAction::SetAsPathPrepent { asn, repeat } => {
                for _ in 0..repeat.unwrap_or(1) {
                    attrs.base.as_path.prepend(*asn);
                }
            }
            // "set-community"
            BgpPolicyAction::SetComm { options, method } => {
                action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.comms,
                    &mut attrs.comm,
                );
            }
            // "set-ext-community"
            BgpPolicyAction::SetExtComm { options, method } => {
                action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.ext_comms,
                    &mut attrs.ext_comm,
                );
            }
            // "set-ipv6-ext-community"
            BgpPolicyAction::SetExtv6Comm { options, method } => {
                action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.extv6_comms,
                    &mut attrs.extv6_comm,
                );
            }
            // "set-large-community"
            BgpPolicyAction::SetLargeComm { options, method } => {
                action_set_comm(
                    options,
                    method,
                    &match_sets.bgp.large_comms,
                    &mut attrs.large_comm,
                );
            }
        },
        // Ignore unsupported actions.
        _ => {}
    }
}

// Modifies the list of communities based on the specified method and options.
fn action_set_comm<T>(
    options: &BgpSetCommOptions,
    method: &BgpSetCommMethod<T>,
    comm_sets: &BTreeMap<String, BTreeSet<T>>,
    comm_list: &mut Option<CommList<T>>,
) where
    T: CommType,
{
    // Get list of communities.
    let comms = match method {
        BgpSetCommMethod::Inline(comms) => comms,
        BgpSetCommMethod::Reference(set) => comm_sets.get(set).unwrap(),
    };

    // Add, remove or replace communities.
    match options {
        BgpSetCommOptions::Add => {
            if let Some(comm_list) = comm_list {
                comm_list.0.extend(comms.clone());
            } else {
                *comm_list = Some(CommList(comms.clone()));
            }
        }
        BgpSetCommOptions::Remove => {
            if let Some(comm_list) = comm_list {
                comm_list.0.retain(|c| !comms.contains(c))
            }
        }
        BgpSetCommOptions::Replace => {
            *comm_list = Some(CommList(comms.clone()));
        }
    }

    // Remove the community list if it exists and is empty.
    if let Some(list) = comm_list.as_ref()
        && list.0.is_empty()
    {
        *comm_list = None;
    }
}

#[cfg(test)]
mod tests {
    use const_addrs::net;
    use holo_utils::policy::{
        BgpPolicyActionType, MatchSetRestrictedType, MatchSetType,
        PolicyActionType, PolicyStmt,
    };
    use holo_utils::protocol::Protocol;

    use super::*;
    use crate::rib::AttrSetsCxt;

    // Builds a single-statement policy that unconditionally applies the given
    // BGP actions and accepts the route.
    fn policy_with(
        actions: impl IntoIterator<Item = (PolicyActionType, PolicyAction)>,
    ) -> Vec<Arc<Policy>> {
        let mut actions: BTreeMap<PolicyActionType, PolicyAction> =
            actions.into_iter().collect();
        actions.insert(PolicyActionType::Accept, PolicyAction::Accept(true));

        let stmt = PolicyStmt {
            name: "1".to_owned(),
            prefix_set_match_type: MatchSetRestrictedType::Any,
            tag_set_match_type: MatchSetType::Any,
            conditions: BTreeMap::new(),
            actions,
        };
        let policy = Policy {
            name: "TEST".to_owned(),
            stmts: [("1".to_owned(), stmt)].into(),
        };
        vec![Arc::new(policy)]
    }

    fn set_med(set_med: BgpSetMed) -> (PolicyActionType, PolicyAction) {
        (
            PolicyActionType::Bgp(BgpPolicyActionType::SetMed),
            PolicyAction::Bgp(BgpPolicyAction::SetMed(set_med)),
        )
    }

    // Builds the route policy info of a route redistributed from an IGP with
    // the given metric and MED.
    fn redistributed(
        igp_metric: Option<u32>,
        med: Option<u32>,
    ) -> RoutePolicyInfo {
        let mut attrs = Attrs::default();
        attrs.base.med = med;
        RoutePolicyInfo::new(
            RouteOrigin::Protocol(Protocol::OSPFV2),
            RouteType::Internal,
            None,
            None,
            igp_metric,
            attrs,
        )
    }

    // Applies an import policy chain to a redistributed route and returns the
    // resulting route policy info.
    fn import(
        rpinfo: &RoutePolicyInfo,
        policies: &[Arc<Policy>],
    ) -> RoutePolicyInfo {
        let match_sets = MatchSets::default();
        match process_policies(
            PolicyType::Import,
            AfiSafi::Ipv4Unicast,
            net!("10.0.1.0/24").into(),
            rpinfo,
            policies,
            &match_sets,
            DefaultPolicyType::AcceptRoute,
        ) {
            PolicyResult::Accept(rpinfo) => rpinfo.into_owned(),
            PolicyResult::Reject => panic!("route unexpectedly rejected"),
        }
    }

    #[test]
    fn set_med_igp_uses_the_igp_metric() {
        let rpinfo = redistributed(Some(20), None);
        let policies = policy_with([set_med(BgpSetMed::Igp)]);
        assert_eq!(import(&rpinfo, &policies).attrs.base.med, Some(20));
    }

    #[test]
    fn redistribution_without_the_action_leaves_the_med_unset() {
        let rpinfo = redistributed(Some(20), None);
        let policies = policy_with([]);
        assert_eq!(import(&rpinfo, &policies).attrs.base.med, None);
    }

    #[test]
    fn set_med_igp_without_a_metric_leaves_the_med_untouched() {
        let rpinfo = redistributed(None, Some(5));
        let policies = policy_with([set_med(BgpSetMed::Igp)]);
        assert_eq!(import(&rpinfo, &policies).attrs.base.med, Some(5));
    }

    #[test]
    fn med_plus_igp_adds_the_igp_metric_to_the_med() {
        let rpinfo = redistributed(Some(20), Some(5));
        let policies = policy_with([set_med(BgpSetMed::MedPlusIgp)]);
        assert_eq!(import(&rpinfo, &policies).attrs.base.med, Some(25));
    }

    #[test]
    fn med_plus_igp_treats_an_unset_med_as_zero() {
        let rpinfo = redistributed(Some(20), None);
        let policies = policy_with([set_med(BgpSetMed::MedPlusIgp)]);
        assert_eq!(import(&rpinfo, &policies).attrs.base.med, Some(20));
    }

    #[test]
    fn med_plus_igp_saturates_instead_of_overflowing() {
        let rpinfo = redistributed(Some(20), Some(u32::MAX));
        let policies = policy_with([set_med(BgpSetMed::MedPlusIgp)]);
        assert_eq!(import(&rpinfo, &policies).attrs.base.med, Some(u32::MAX));
    }

    // The export stage rebuilds the route policy info from the attribute sets
    // interned by the RIB, dropping the IGP metric. The MED set at import must
    // survive that round trip, since that is what the export policies and the
    // advertised UPDATE see.
    #[test]
    fn med_from_the_igp_metric_survives_interning() {
        let rpinfo = redistributed(Some(20), None);
        let policies = policy_with([set_med(BgpSetMed::Igp)]);
        let rpinfo = import(&rpinfo, &policies);

        let mut attr_sets = AttrSetsCxt::default();
        let route_attrs = attr_sets.get_route_attr_sets(&rpinfo.attrs);
        let exported = RoutePolicyInfo::new(
            rpinfo.origin,
            rpinfo.route_type,
            None,
            None,
            None,
            route_attrs.get(),
        );
        assert_eq!(exported.attrs.base.med, Some(20));
    }
}
