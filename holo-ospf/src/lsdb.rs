//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cmp::Ordering;
use std::collections::{btree_map, hash_map};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use bitflags::bitflags;
use chrono::Utc;
use derive_new::new;
use holo_utils::bier::BierCfgEvent;
use holo_utils::sr::SrCfgEvent;
use holo_utils::task::TimeoutTask;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

use crate::area::{Area, AreaType, BACKBONE_AREA_ID};
use crate::collections::{
    AreaId, AreaIndex, Areas, Arena, InterfaceId, InterfaceIndex, LsaEntryId,
    LsaEntryIndex, LsdbId, LsdbIndex, lsdb_index_mut,
};
use crate::debug::{Debug, LsaFlushReason};
use crate::error::Error;
use crate::flood::flood;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, InterfaceType};
use crate::neighbor::nsm;
use crate::packet::lsa::{
    Lsa, LsaBodyVersion, LsaHdrVersion, LsaKey, LsaTypeVersion,
};
use crate::route::{SummaryNet, SummaryRtr};
use crate::spf::SpfTriggerLsa;
use crate::tasks::messages::input::LsaFlushMsg;
use crate::version::Version;
use crate::{gr, spf, tasks};

// Architectural Constants.
pub const LSA_REFRESH_TIME: u16 = 1800;
pub const LSA_MAX_AGE: u16 = 3600;
pub const LSA_MAX_AGE_DIFF: u16 = 900;
pub const LSA_INFINITY: u32 = 0x00ffffff;
pub const LSA_INIT_SEQ_NO: u32 = 0x80000001;
pub const LSA_MAX_SEQ_NO: u32 = 0x7fffffff;
pub const LSA_RESERVED_SEQ_NO: u32 = 0x80000000;
pub const LSA_MIN_INTERVAL: u64 = 5;
pub const LSA_MIN_ARRIVAL: u64 = 1;
pub const MAX_LINK_METRIC: u16 = 0xffff;

// Maximum size of the LSA log record.
const LSA_LOG_MAX_SIZE: usize = 64;

#[derive(Debug)]
pub struct LsaEntry<V: Version> {
    // LSA ID.
    pub id: LsaEntryId,
    // LSA data.
    pub data: Arc<Lsa<V>>,
    // Expiry timer that triggers when the LSA age reaches MaxAge.
    pub expiry_timer: Option<TimeoutTask>,
    // Refresh interval that triggers every LSA_REFRESH_TIME seconds.
    pub refresh_timer: Option<TimeoutTask>,
    // LSA entry flags.
    pub flags: LsaEntryFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct LsaEntryFlags: u8 {
        const RECEIVED = 0x01;
        const SELF_ORIGINATED = 0x02;
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum LsaOriginateEvent {
    AreaStart {
        area_id: AreaId,
    },
    InterfaceStateChange {
        area_id: AreaId,
        iface_id: InterfaceId,
    },
    InterfaceDrChange {
        area_id: AreaId,
        iface_id: InterfaceId,
    },
    InterfaceAddrAddDel {
        area_id: AreaId,
        iface_id: InterfaceId,
    },
    InterfaceCostChange {
        area_id: AreaId,
    },
    InterfaceFlagChange {
        area_id: AreaId,
    },
    NeighborToFromFull {
        area_id: AreaId,
        iface_id: InterfaceId,
    },
    NeighborTwoWayOrHigherChange {
        area_id: AreaId,
        iface_id: InterfaceId,
    },
    NeighborInterfaceIdChange {
        area_id: AreaId,
        iface_id: InterfaceId,
    },
    VirtualLinkChange,
    LinkLsaRcvd {
        area_id: AreaId,
        iface_id: InterfaceId,
    },
    SelfOriginatedLsaRcvd {
        lsdb_id: LsdbId,
        lse_id: LsaEntryId,
    },
    StubRouterChange,
    SrEnableChange,
    SrCfgChange {
        change: SrCfgEvent,
    },
    GrHelperChange,
    GrHelperExit {
        area_id: AreaId,
        iface_id: InterfaceId,
    },
    BierEnableChange,
    BierCfgChange {
        change: BierCfgEvent,
    },
    HostnameChange,
    NodeTagsChange,
}

#[derive(Debug)]
pub struct LsaDelayedOrig<V: Version> {
    pub data: Lsa<V>,
    pub timeout: TimeoutTask,
}

#[derive(Debug, new)]
pub struct LsaLogEntry<V: Version> {
    pub id: u32,
    pub lsa: LsaLogId<V>,
    pub rcvd_time: Option<Instant>,
    pub reason: LsaLogReason,
}

#[derive(Clone, Debug)]
pub struct LsaLogId<V: Version> {
    pub area_id: Option<Ipv4Addr>,
    pub lsa_type: V::LsaType,
    pub lsa_id: Ipv4Addr,
    pub adv_rtr: Ipv4Addr,
    pub seq_no: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum LsaLogReason {
    Refresh,
    ContentChange,
    Purge,
}

// Operand of an LSA recency comparison: an LSA header paired with the LS age
// that must be used for it.
//
// The age stored in an LSA header is frozen at the time the LSA is created or
// received; only `Lsa::base_time` tracks how much the copy has aged since. RFC
// 2328, Section 13.1, requires comparing the *current* LS age of each copy, so
// locally held LSAs must be wrapped with `LsaCmp::local()`; `LsaCmp::wire()`
// is only for headers taken straight off the network.
pub(crate) struct LsaCmp<'a, V: Version> {
    hdr: &'a V::LsaHdr,
    age: u16,
}

// OSPF version-specific code.
pub trait LsdbVersion<V: Version> {
    // Check if the provided area and/or neighbor can accept the given LSA type.
    fn lsa_type_is_valid(
        area_type: Option<AreaType>,
        if_type: Option<InterfaceType>,
        nbr_options: Option<V::PacketOptions>,
        lsa_type: V::LsaType,
    ) -> bool;

    // Check whether the LSA is self-originated.
    fn lsa_is_self_originated(
        lsa: &Lsa<V>,
        router_id: Ipv4Addr,
        interfaces: &Arena<Interface<V>>,
    ) -> bool;

    // Originate or flush the required LSAs in response to an LSA origination
    // event.
    fn lsa_orig_event(
        instance: &InstanceUpView<'_, V>,
        arenas: &InstanceArenas<V>,
        event: LsaOriginateEvent,
    ) -> Result<(), Error<V>>;

    // Originate Type-3 Summary LSA (OSPFv2) or Inter-Area-Network-LSA (OSPFv3).
    fn lsa_orig_inter_area_network(
        area: &mut Area<V>,
        instance: &InstanceUpView<'_, V>,
        prefix: V::IpNetwork,
        lsa_id: Option<u32>,
        summary: &SummaryNet<V>,
    ) -> u32;

    // Originate Type-4 Summary LSA (OSPFv2) or Inter-Area-Router-LSA (OSPFv3).
    fn lsa_orig_inter_area_router(
        area: &mut Area<V>,
        instance: &InstanceUpView<'_, V>,
        router_id: Ipv4Addr,
        lsa_id: Option<u32>,
        summary: &SummaryRtr<V>,
    ) -> u32;

    // Return the LSDB index corresponding to the provided LSA type.
    fn lsdb_get_by_lsa_type(
        iface_idx: InterfaceIndex,
        area_idx: AreaIndex,
        lsa_type: V::LsaType,
    ) -> LsdbIndex;

    // Custom LSA installation handling.
    fn lsdb_install(
        instance: &mut InstanceUpView<'_, V>,
        arenas: &mut InstanceArenas<V>,
        lsdb_idx: LsdbIndex,
        lsdb_id: LsdbId,
        lsa: &Lsa<V>,
    );
}

// ===== impl LsaEntry =====

impl<V> LsaEntry<V>
where
    V: Version,
{
    pub(crate) fn new(
        lsdb_id: LsdbId,
        id: LsaEntryId,
        data: Arc<Lsa<V>>,
        lsa_flushp: &UnboundedSender<LsaFlushMsg<V>>,
    ) -> LsaEntry<V> {
        let expiry_timer = (!data.hdr.is_maxage())
            .then_some(tasks::lsa_expiry_timer(lsdb_id, id, &data, lsa_flushp));

        LsaEntry {
            id,
            data,
            expiry_timer,
            refresh_timer: None,
            flags: Default::default(),
        }
    }
}

// ===== impl LsaLogId =====

impl<V> LsaLogId<V>
where
    V: Version,
{
    pub(crate) fn new(
        areas: &Areas<V>,
        lsdb_idx: LsdbIndex,
        lsa: &Lsa<V>,
    ) -> Self {
        // Get area ID from the LSA's LSDB.
        let area_id = match lsdb_idx {
            LsdbIndex::Link(area_idx, _) | LsdbIndex::Area(area_idx) => {
                let area = &areas[area_idx];
                Some(area.area_id)
            }
            LsdbIndex::As => None,
        };

        // Return new LSA log ID.
        LsaLogId {
            area_id,
            lsa_type: lsa.hdr.lsa_type(),
            lsa_id: lsa.hdr.lsa_id(),
            adv_rtr: lsa.hdr.adv_rtr(),
            seq_no: lsa.hdr.seq_no(),
        }
    }
}

// ===== impl LsaCmp =====

impl<'a, V> LsaCmp<'a, V>
where
    V: Version,
{
    // Operand for an LSA the router holds a copy of: an LSDB entry, a
    // retransmission list entry, a database summary list entry, or an LSA just
    // decoded from the network. Its age is taken from `Lsa::age()`, which
    // accounts for the time elapsed since the copy was created or received.
    pub(crate) fn local(lsa: &'a Lsa<V>) -> Self {
        LsaCmp {
            hdr: &lsa.hdr,
            age: lsa.age(),
        }
    }

    // Operand for a bare LSA header received from a neighbor (Database
    // Description, Link State Request or Link State Acknowledgment packet).
    // Such a header carries the sender's current age, and no local copy exists
    // to age it further.
    pub(crate) fn wire(hdr: &'a V::LsaHdr) -> Self {
        LsaCmp {
            hdr,
            age: hdr.age(),
        }
    }

    fn is_maxage(&self) -> bool {
        self.age == LSA_MAX_AGE
    }
}

// ===== global functions =====

// Compares which LSA is more recent according to the rules specified in Section
// 13.1 of RFC 2328.
//
// Returns:
// - Ordering::Greater when `a` is more recent
// - Ordering::Less when `b` is more recent
// - Ordering::Equal when the two LSAs are considered to be identical
pub(crate) fn lsa_compare<V>(a: LsaCmp<'_, V>, b: LsaCmp<'_, V>) -> Ordering
where
    V: Version,
{
    let a_seq_no = a.hdr.seq_no() as i32;
    let b_seq_no = b.hdr.seq_no() as i32;
    let cmp = a_seq_no.cmp(&b_seq_no);
    if cmp != Ordering::Equal {
        return cmp;
    }

    let cmp = a.hdr.cksum().cmp(&b.hdr.cksum());
    if cmp != Ordering::Equal {
        return cmp;
    }

    if a.is_maxage() && !b.is_maxage() {
        return Ordering::Greater;
    } else if !a.is_maxage() && b.is_maxage() {
        return Ordering::Less;
    }

    if a.age.abs_diff(b.age) > LSA_MAX_AGE_DIFF {
        return b.age.cmp(&a.age);
    }

    Ordering::Equal
}

// Compares two LSAs according to the rules specified in Section 13.2 of RFC
// 2328. Its purpose is to determine if the contents of the LSAs are identical.
fn lsa_same_contents<V>(a: &Lsa<V>, b: &Lsa<V>) -> bool
where
    V: Version,
{
    if a.hdr.options() != b.hdr.options() {
        return false;
    }

    if a.hdr.is_maxage() ^ b.hdr.is_maxage() {
        return false;
    }

    if a.hdr.length() != b.hdr.length() {
        return false;
    }

    let hdr_length = V::LsaHdr::LENGTH as usize;
    a.raw[hdr_length..] == b.raw[hdr_length..]
}

// Checks if the given LSA was received via flooding less than MinLSArrival
// seconds ago.
pub(crate) fn lsa_min_arrival_check<V>(lse: &LsaEntry<V>) -> bool
where
    V: Version,
{
    if !lse.flags.contains(LsaEntryFlags::RECEIVED) {
        return false;
    }

    #[cfg(feature = "deterministic")]
    {
        false
    }
    #[cfg(not(feature = "deterministic"))]
    {
        match lse.data.base_time {
            Some(lsa_base_time) => {
                lsa_base_time.elapsed().as_secs() < LSA_MIN_ARRIVAL
            }
            None => false,
        }
    }
}

// Checks if the given LSA was originated less than MinLSInterval seconds ago.
fn lsa_min_orig_interval_check<V>(lse: &LsaEntry<V>) -> bool
where
    V: Version,
{
    if lse.flags.contains(LsaEntryFlags::RECEIVED) {
        return false;
    }

    #[cfg(feature = "deterministic")]
    {
        false
    }
    #[cfg(not(feature = "deterministic"))]
    {
        match lse.data.base_time {
            Some(lsa_base_time) => {
                lsa_base_time.elapsed().as_secs() < LSA_MIN_INTERVAL
            }
            None => false,
        }
    }
}

// Installs the provided LSA to the specified LSDB.
pub(crate) fn install<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_idx: LsdbIndex,
    lsa: Arc<Lsa<V>>,
) -> LsaEntryIndex
where
    V: Version,
{
    if instance.config.trace_opts.lsdb {
        Debug::<V>::LsaInstall(&lsa.hdr).log();
    }

    // Remove old instance (if any) from all neighbors' Link state
    // retransmission lists.
    rxmt_lists_remove(arenas, lsdb_idx, &lsa);

    // Lookup LSDB.
    let (lsdb_id, lsdb) = lsdb_index_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        lsdb_idx,
    );

    // Remove old instance of the LSA.
    let old_lsa = match lsdb.get(&arenas.lsa_entries, &lsa.hdr.key()) {
        Some((old_lse_idx, old_lse)) => {
            let old_lsa = old_lse.data.clone();
            lsdb.delete(&mut arenas.lsa_entries, old_lse_idx);
            Some(old_lsa)
        }
        None => None,
    };

    // Add LSA entry to LSDB.
    let (lse_idx, lse) = lsdb.insert(
        &mut arenas.lsa_entries,
        lsdb_id,
        lsa.clone(),
        &instance.tx.protocol_input,
    );

    // Check if the LSA is self-originated and mark it as such.
    if V::lsa_is_self_originated(
        &lse.data,
        instance.state.router_id,
        &arenas.interfaces,
    ) {
        lse.flags.insert(LsaEntryFlags::SELF_ORIGINATED);
    }

    // RFC 2328 - Section 13.2:
    // "The contents of the new LSA should be compared to the old instance, if
    // present. If there is no difference, there is no need to recalculate the
    // routing table".
    //
    // Additionally, do not recalculate the routing table in the following
    // cases:
    // * The type of the new LSA is unknown
    // * The new LSA is a self-originated summary
    let mut content_change = true;
    if let Some(old_lsa) = &old_lsa
        && lsa_same_contents(old_lsa, &lsa)
    {
        content_change = false;
    }
    let lsa_type = lsa.hdr.lsa_type();
    let self_orig_summary = lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED)
        && (lsa_type == V::type3_summary(instance.config.extended_lsa)
            || lsa_type == V::type4_summary(instance.config.extended_lsa));
    let route_recalc =
        content_change && !lsa.body.is_unknown() && !self_orig_summary;

    // A network topology change forces the termination of a graceful restart.
    if content_change
        && lsa.hdr.lsa_type().is_gr_topology_info()
        && instance.state.gr_helper_count > 0
        && instance.config.gr.helper_strict_lsa_checking
    {
        gr::helper_process_topology_change(
            Some(lsa.hdr.lsa_type()),
            instance,
            arenas,
        );
    }

    // OSPF version-specific LSDB installation handling.
    V::lsdb_install(instance, arenas, lsdb_idx, lsdb_id, &lsa);

    // Add entry to LSA log.
    let lsa_log_id = LsaLogId::new(&arenas.areas, lsdb_idx, &lsa);
    let reason = if lsa.hdr.is_maxage() {
        LsaLogReason::Purge
    } else if content_change {
        LsaLogReason::ContentChange
    } else {
        LsaLogReason::Refresh
    };
    log_lsa(instance, lsa_log_id.clone(), lsa.base_time, reason);

    // Schedule SPF run if necessary.
    if route_recalc {
        // Update list of SPF-triggering LSAs.
        let trigger_lsa = SpfTriggerLsa::new(old_lsa, lsa, lsa_log_id);
        instance.state.spf_trigger_lsas.push(trigger_lsa);

        instance
            .state
            .spf_schedule_time
            .get_or_insert_with(Instant::now);
        instance
            .tx
            .protocol_input
            .spf_delay_event(spf::fsm::Event::Igp);
    }

    lse_idx
}

// Originates the provided LSA.
pub(crate) fn originate<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_idx: LsdbIndex,
    lsa: Lsa<V>,
) where
    V: Version,
{
    let (lsdb_id, lsdb) = lsdb_index_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        lsdb_idx,
    );

    // When an attempt is made to increment the sequence number past the
    // maximum value of MaxSequenceNumber, the current instance of the LSA
    // must first be flushed from the routing domain. This is done by
    // prematurely aging the LSA and reflooding it. As soon as this flood
    // has been acknowledged by all adjacent neighbors, a new instance can
    // be originated with sequence number of InitialSequenceNumber.
    let lsa_key = lsa.hdr.key();
    if let Some((old_lse_idx, _)) = lsdb.get(&arenas.lsa_entries, &lsa_key)
        && lsa.hdr.seq_no() == LSA_MAX_SEQ_NO + 1
    {
        // Record LSA that will be originated later and then flush the
        // existing instance.
        match lsdb.seqno_wrapping.entry(lsa_key) {
            hash_map::Entry::Occupied(mut o) => {
                *o.get_mut() = lsa;
            }
            hash_map::Entry::Vacant(v) => {
                v.insert(lsa);
            }
        }
        let reason = LsaFlushReason::PrematureAging;
        flush(instance, arenas, lsdb_idx, old_lse_idx, reason);
        return;
    }

    if instance.config.trace_opts.lsdb {
        Debug::<V>::LsaOriginate(&lsa.hdr).log();
    }

    let lse_idx = install(instance, arenas, lsdb_idx, Arc::new(lsa));

    let lse = &mut arenas.lsa_entries[lse_idx];
    flood(
        instance,
        &arenas.areas,
        &mut arenas.interfaces,
        &mut arenas.neighbors,
        lsdb_idx,
        &lse.data,
        None,
    );

    // Update statistics.
    instance.state.orig_lsa_count += 1;
    instance.state.discontinuity_time = Utc::now();

    // Schedule LSA refreshing.
    let refresh_timer = tasks::lsa_refresh_timer(
        lsdb_id,
        lse.id,
        &instance.tx.protocol_input.lsa_refresh,
    );
    lse.refresh_timer = Some(refresh_timer);
}

// Attempts to originate the provided LSA, but only if it passes a few checks.
pub(crate) fn originate_check<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_idx: LsdbIndex,
    options: Option<V::PacketOptions>,
    lsa_id: Ipv4Addr,
    lsa_body: V::LsaBody,
) where
    V: Version,
{
    let (lsdb_id, lsdb) = lsdb_index_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        lsdb_idx,
    );
    let adv_rtr = instance.state.router_id;
    let lsa_key = LsaKey::new(lsa_body.lsa_type(), adv_rtr, lsa_id);

    // Get next sequence number.
    let seq_no = lsdb
        .get(&arenas.lsa_entries, &lsa_key)
        .map(|(_, old_lse)| old_lse.data.hdr.seq_no() + 1)
        .unwrap_or(LSA_INIT_SEQ_NO);

    // Make new LSA.
    let lsa = Lsa::new(0, options, lsa_id, adv_rtr, seq_no, lsa_body);

    // Check if an instance of this LSA already exists in the LSDB.
    if let Some((_, old_lse)) = lsdb.get(&arenas.lsa_entries, &lsa_key) {
        // If an LSA with identical contents already exists in the LSDB, skip
        // originating a new one (as per section 12.4 of RFC 2328).
        //
        // However, if the database copy was received through flooding, proceed
        // to originate a new instance with an updated sequence number.
        if lsa_same_contents(&old_lse.data, &lsa)
            && !old_lse.flags.contains(LsaEntryFlags::RECEIVED)
        {
            return;
        }

        // Perform the MinLSInterval check.
        if lsdb.delayed_orig.contains_key(&lsa_key)
            || lsa_min_orig_interval_check(old_lse)
        {
            if instance.config.trace_opts.flooding {
                Debug::<V>::LsaOriginateMinInterval(&lsa.hdr).log();
            }

            match lsdb.delayed_orig.entry(lsa_key) {
                hash_map::Entry::Occupied(mut o) => {
                    // Update the LSA that will be originated, but keep the
                    // current timeout.
                    let ldo = o.get_mut();
                    ldo.data = lsa;
                }
                hash_map::Entry::Vacant(v) => {
                    // Start timer to postpone originating the LSA.
                    let timeout = tasks::lsa_orig_delayed_timer(
                        lsdb_id,
                        lsa_key,
                        old_lse.data.base_time,
                        &instance.tx.protocol_input.lsa_orig_delayed_timer,
                    );
                    v.insert(LsaDelayedOrig { data: lsa, timeout });
                }
            }
            return;
        }
    }

    // Effectively originate the LSA.
    originate(instance, arenas, lsdb_idx, lsa);
}

// Flushes LSA from the LSDB.
pub(crate) fn flush<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_idx: LsdbIndex,
    lse_idx: LsaEntryIndex,
    reason: LsaFlushReason,
) where
    V: Version,
{
    // Do not flush the same LSA more than once.
    let lse = &mut arenas.lsa_entries[lse_idx];
    if lse.data.hdr.is_maxage() {
        return;
    }

    if reason == LsaFlushReason::PrematureAging {
        assert!(lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED));
    }

    if instance.config.trace_opts.lsdb {
        Debug::<V>::LsaFlush(&lse.data.hdr, reason).log();
    }

    // Disarm timers.
    lse.expiry_timer = None;
    lse.refresh_timer = None;

    // Set the LSA age to MaxAge.
    let mut lsa = (*lse.data).clone();
    lsa.set_maxage();
    let lsa = Arc::new(lsa);

    // Install updated LSA to clear rxmt lists and rerun route calculations.
    let lse_idx = install(instance, arenas, lsdb_idx, lsa);

    // Reflood updated LSA.
    let lse = &arenas.lsa_entries[lse_idx];
    let _ = flood(
        instance,
        &arenas.areas,
        &mut arenas.interfaces,
        &mut arenas.neighbors,
        lsdb_idx,
        &lse.data,
        None,
    );

    // Get LSA's LSDB.
    let (_, lsdb) = lsdb_index_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        lsdb_idx,
    );
    let lsa_key = lse.data.hdr.key();

    // Remove pending LSA origination, if any.
    lsdb.delayed_orig.remove(&lsa_key);
}

// Flushes all self-originated LSAs from the LSDB.
pub(crate) fn flush_all_self_originated<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
) where
    V: Version,
{
    let reason = LsaFlushReason::PrematureAging;
    let mut idxs = vec![];

    // AS-scope LSAs.
    let lsdb_idx = LsdbIndex::As;
    idxs.extend(
        instance
            .state
            .lsdb
            .iter(&arenas.lsa_entries)
            .filter(|(_, lse)| {
                lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED)
            })
            .map(|(lse_idx, _)| (lsdb_idx, lse_idx)),
    );

    // Area-scope LSAs.
    for area_idx in arenas.areas.indexes() {
        let area = &arenas.areas[area_idx];
        let lsdb_idx = LsdbIndex::Area(area_idx);
        idxs.extend(
            area.state
                .lsdb
                .iter(&arenas.lsa_entries)
                .filter(|(_, lse)| {
                    lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED)
                })
                .map(|(lse_idx, _)| (lsdb_idx, lse_idx)),
        );

        // Link-scope LSAs.
        for iface_idx in area.interfaces.indexes() {
            let iface = &arenas.interfaces[iface_idx];
            let lsdb_idx = LsdbIndex::Link(area_idx, iface_idx);
            idxs.extend(
                iface
                    .state
                    .lsdb
                    .iter(&arenas.lsa_entries)
                    .filter(|(_, lse)| {
                        lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED)
                    })
                    .map(|(lse_idx, _)| (lsdb_idx, lse_idx)),
            );
        }
    }

    // Flush LSAs.
    for (lsdb_idx, lse_idx) in idxs {
        flush(instance, arenas, lsdb_idx, lse_idx, reason);
    }
}

// Removes old instance of the given LSA from all neighbors' Link state
// retransmission lists.
fn rxmt_lists_remove<V>(
    arenas: &mut InstanceArenas<V>,
    lsdb_idx: LsdbIndex,
    lsa: &Lsa<V>,
) where
    V: Version,
{
    for area_idx in arenas.areas.indexes() {
        let area = &arenas.areas[area_idx];

        // Filter by LSA area.
        match lsdb_idx {
            LsdbIndex::Link(lsdb_area_idx, _)
            | LsdbIndex::Area(lsdb_area_idx)
                if area_idx != lsdb_area_idx =>
            {
                continue;
            }
            _ => (),
        }

        for iface_idx in area.interfaces.indexes() {
            let iface = &arenas.interfaces[iface_idx];

            // Filter by LSA interface.
            if let LsdbIndex::Link(_, lsdb_iface_idx) = lsdb_idx
                && iface_idx != lsdb_iface_idx
            {
                continue;
            }

            // Iterate over all neighbors from this interface.
            for nbr_idx in iface.state.neighbors.indexes() {
                let nbr = &mut arenas.neighbors[nbr_idx];

                // Remove LSA from rxmt list as long as it's an older version.
                if let btree_map::Entry::Occupied(o) =
                    nbr.lists.ls_rxmt.entry(lsa.hdr.key())
                {
                    let old_lsa = o.get();
                    if lsa_compare(LsaCmp::local(old_lsa), LsaCmp::local(lsa))
                        == Ordering::Less
                    {
                        o.remove();
                        nbr.rxmt_lsupd_stop_check();
                    }
                }
            }
        }
    }
}

// Adds log entry for the newly installed LSA.
fn log_lsa<V>(
    instance: &mut InstanceUpView<'_, V>,
    lsa: LsaLogId<V>,
    rcvd_time: Option<Instant>,
    reason: LsaLogReason,
) where
    V: Version,
{
    // Get next log ID.
    let log_id = &mut instance.state.lsa_log_next_id;
    *log_id += 1;

    // Add new log entry.
    let log_entry = LsaLogEntry::new(*log_id, lsa, rcvd_time, reason);
    instance.state.lsa_log.push_front(log_entry);

    // Remove old entries if necessary.
    instance.state.lsa_log.truncate(LSA_LOG_MAX_SIZE);
}

// Determines whether the Router-LSA V-bit should be set for the given area.
pub(crate) fn router_lsa_v_bit<V>(
    area: &Area<V>,
    arenas: &InstanceArenas<V>,
) -> bool
where
    V: Version,
{
    // V-bit cannot be set for the backbone itself.
    if area.is_backbone() {
        return false;
    }

    // Look up the backbone area, which contains the virtual links.
    let Some((_, backbone)) = arenas.areas.get_by_area_id(BACKBONE_AREA_ID)
    else {
        return false;
    };

    // The V-bit is set if this area is the transit area for a virtual link
    // and that virtual link has a neighbor in the Full state.
    backbone.interfaces.iter(&arenas.interfaces).any(|iface| {
        iface
            .vlink_key
            .as_ref()
            .is_some_and(|vlink_key| vlink_key.transit_area_id == area.area_id)
            && iface
                .state
                .neighbors
                .iter(&arenas.neighbors)
                .next()
                .is_some_and(|nbr| nbr.state == nsm::State::Full)
    })
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use const_addrs::ip4;

    use super::*;
    use crate::ospfv2::packet::iana::{LsaRouterLinkType, Options};
    use crate::ospfv2::packet::lsa::{LsaBody, LsaRouter, LsaRouterLink};
    use crate::version::Ospfv2;

    // Builds a Router-LSA whose header carries the given age.
    fn router_lsa(age: u16, seq_no: u32) -> Lsa<Ospfv2> {
        let mut lsa = Lsa::<Ospfv2>::new(
            age,
            Some(Options::E),
            ip4!("1.1.1.1"),
            ip4!("1.1.1.1"),
            seq_no,
            LsaBody::Router(LsaRouter {
                flags: Default::default(),
                links: vec![LsaRouterLink {
                    link_type: LsaRouterLinkType::StubNetwork,
                    link_id: ip4!("10.0.1.0"),
                    link_data: ip4!("255.255.255.0"),
                    metric: 10,
                }],
            }),
        );
        // Age the copy explicitly in every test, never through the ambient
        // clock, so the results don't depend on the build's feature flags.
        lsa.base_time = None;
        lsa
    }

    // Marks an LSA as installed `secs` seconds ago.
    fn installed_secs_ago(lsa: &mut Lsa<Ospfv2>, secs: u64) {
        lsa.base_time = Some(
            Instant::now()
                .checked_sub(Duration::from_secs(secs))
                .expect("monotonic clock younger than the simulated LSA age"),
        );
    }

    // The database copy and the copy a neighbor floods back are the same LSA
    // instance; the neighbor stamps the current age on the wire, while the
    // header stored locally still holds the age at install time.
    //
    // Comparing the stored header field (what the code did before this fix)
    // makes each router judge its own copy more recent once the two ages drift
    // apart by more than MaxAgeDiff, on both sides at once.
    #[test]
    fn lsa_compare_same_instance_aged_copy() {
        let mut db_copy = router_lsa(1, LSA_INIT_SEQ_NO);
        installed_secs_ago(&mut db_copy, 1000);
        let rcvd = router_lsa(1001, LSA_INIT_SEQ_NO);

        // Same instance: only the age differs.
        assert_eq!(db_copy.hdr.seq_no(), rcvd.hdr.seq_no());
        assert_eq!(db_copy.hdr.cksum(), rcvd.hdr.cksum());
        assert_eq!(db_copy.age(), 1001);
        assert_eq!(rcvd.age(), 1001);

        // Old behavior, kept here as a regression witness: using the frozen
        // header of the database copy declares it more recent (Greater), which
        // triggers the RFC 2328 13-(8) "send the database copy back" reply on
        // every received packet.
        assert_eq!(
            lsa_compare::<Ospfv2>(
                LsaCmp::wire(&db_copy.hdr),
                LsaCmp::wire(&rcvd.hdr)
            ),
            Ordering::Greater
        );

        // New behavior: the database copy is compared with its current age, so
        // the two copies are recognized as the same instance.
        assert_eq!(
            lsa_compare::<Ospfv2>(
                LsaCmp::local(&db_copy),
                LsaCmp::local(&rcvd)
            ),
            Ordering::Equal
        );
    }

    // A real age difference larger than MaxAgeDiff must still order the two
    // copies, in both directions.
    #[test]
    fn lsa_compare_genuine_age_difference() {
        // Database copy installed 5 seconds ago, neighbor's copy is 1000
        // seconds old: the database copy is more recent.
        let mut db_copy = router_lsa(0, LSA_INIT_SEQ_NO);
        installed_secs_ago(&mut db_copy, 5);
        let rcvd = router_lsa(1000, LSA_INIT_SEQ_NO);
        assert_eq!(
            lsa_compare::<Ospfv2>(
                LsaCmp::local(&db_copy),
                LsaCmp::wire(&rcvd.hdr)
            ),
            Ordering::Greater
        );

        // The other way around: the database copy is 1500 seconds old and the
        // received copy is fresh.
        let mut db_copy = router_lsa(0, LSA_INIT_SEQ_NO);
        installed_secs_ago(&mut db_copy, 1500);
        let rcvd = router_lsa(1, LSA_INIT_SEQ_NO);
        assert_eq!(
            lsa_compare::<Ospfv2>(
                LsaCmp::local(&db_copy),
                LsaCmp::wire(&rcvd.hdr)
            ),
            Ordering::Less
        );
    }

    // MaxAge ordering is unchanged, and a database copy that has aged to
    // MaxAge in place is now recognized as MaxAge too.
    #[test]
    fn lsa_compare_maxage() {
        let db_copy = router_lsa(LSA_MAX_AGE, LSA_INIT_SEQ_NO);
        let rcvd = router_lsa(1, LSA_INIT_SEQ_NO);
        assert_eq!(
            lsa_compare::<Ospfv2>(
                LsaCmp::local(&db_copy),
                LsaCmp::wire(&rcvd.hdr)
            ),
            Ordering::Greater
        );

        let db_copy = router_lsa(1, LSA_INIT_SEQ_NO);
        let rcvd = router_lsa(LSA_MAX_AGE, LSA_INIT_SEQ_NO);
        assert_eq!(
            lsa_compare::<Ospfv2>(
                LsaCmp::local(&db_copy),
                LsaCmp::wire(&rcvd.hdr)
            ),
            Ordering::Less
        );

        // Aged in place past MaxAge: Lsa::age() saturates at MaxAge.
        let mut db_copy = router_lsa(1, LSA_INIT_SEQ_NO);
        installed_secs_ago(&mut db_copy, u64::from(LSA_MAX_AGE) + 400);
        let rcvd = router_lsa(1, LSA_INIT_SEQ_NO);
        assert_eq!(db_copy.age(), LSA_MAX_AGE);
        assert_eq!(
            lsa_compare::<Ospfv2>(
                LsaCmp::local(&db_copy),
                LsaCmp::wire(&rcvd.hdr)
            ),
            Ordering::Greater
        );
    }

    // The sequence number still takes precedence over any age difference.
    #[test]
    fn lsa_compare_seq_no_precedence() {
        let mut db_copy = router_lsa(1, LSA_INIT_SEQ_NO);
        installed_secs_ago(&mut db_copy, 3000);
        let rcvd = router_lsa(1, LSA_INIT_SEQ_NO + 1);
        assert_eq!(
            lsa_compare::<Ospfv2>(
                LsaCmp::local(&db_copy),
                LsaCmp::wire(&rcvd.hdr)
            ),
            Ordering::Less
        );
    }
}
