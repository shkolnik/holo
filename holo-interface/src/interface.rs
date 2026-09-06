//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use bitflags::bitflags;
use derive_new::new;
use generational_arena::{Arena, Index};
use holo_northbound::NbDaemonSender;
use holo_utils::ibus::IbusSender;
use holo_utils::ip::{AddressFamily, IpAddrKind, Ipv4NetworkExt};
use holo_utils::mac_addr::MacAddr;
use holo_utils::southbound::{AddressFlags, InterfaceFlags};
use ipnetwork::IpNetwork;
use tokio::sync::mpsc::UnboundedSender;

use crate::netlink::NetlinkRequest;
use crate::northbound::configuration::InterfaceCfg;
use crate::{ibus, netlink};

#[derive(Debug, Default)]
pub struct Interfaces {
    // Interface arena.
    arena: Arena<Interface>,
    // Interface binary tree keyed by name (1:1).
    name_tree: BTreeMap<String, Index>,
    // Interface hash table keyed by ifindex (1:1).
    ifindex_tree: HashMap<u32, Index>,
    // Auto-generated Router ID.
    router_id: Option<Ipv4Addr>,
    // Interface subscriptions.
    pub subscriptions: HashMap<usize, InterfaceSub>,
    // Router ID subscriptions.
    pub router_id_subscriptions: HashMap<usize, IbusSender>,
}

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub config: InterfaceCfg,
    pub ifindex: Option<u32>,
    pub mtu: Option<u32>,
    pub flags: InterfaceFlags,
    pub addresses: BTreeMap<IpNetwork, InterfaceAddress>,
    pub mac_address: MacAddr,
    pub owner: Owner,
    pub vrrp: Option<VrrpHandle>,
    pub subscriptions: HashMap<usize, InterfaceSub>,
}

#[derive(Debug)]
pub struct InterfaceAddress {
    pub addr: IpNetwork,
    pub flags: AddressFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Owner: u8 {
        const CONFIG = 0x01;
        const SYSTEM = 0x02;
    }
}

#[derive(Debug, new)]
pub struct VrrpHandle {
    pub nb_tx: NbDaemonSender,
    pub ibus_tx: IbusSender,
}

#[derive(Debug)]
#[derive(new)]
pub struct InterfaceSub {
    afs: BTreeSet<AddressFamily>,
    tx: IbusSender,
}

// ===== impl Interface =====

impl Interface {
    // Applies the interface configuration.
    //
    // This method should only be called after the interface has been created
    // at the OS-level.
    fn apply_config(
        &self,
        ifindex: u32,
        netlink_tx: &UnboundedSender<NetlinkRequest>,
        interfaces: &Interfaces,
    ) {
        // Set administrative status.
        netlink::admin_status_change(netlink_tx, ifindex, self.config.enabled);

        // Create VLAN subinterface.
        if let Some(vlan_id) = self.config.vlan_id
            && self.ifindex.is_none()
            && let Some(parent) = &self.config.parent
            && let Some(parent) = interfaces.get_by_name(parent)
            && let Some(parent_ifindex) = parent.ifindex
        {
            netlink::vlan_create(
                netlink_tx,
                self.name.clone(),
                parent_ifindex,
                vlan_id,
            );
        }

        // Set MTU.
        if let Some(mtu) = self.config.mtu {
            netlink::mtu_change(netlink_tx, ifindex, mtu);
        }

        // Install interface addresses.
        for (addr, plen) in &self.config.addr_list {
            let addr = IpNetwork::new(*addr, *plen).unwrap();
            netlink::addr_install(netlink_tx, ifindex, &addr);
        }
    }
}

// ===== impl Interfaces =====

impl Interfaces {
    // Adds an interface.
    pub(crate) fn add(&mut self, ifname: String) {
        if let Some(iface) = self.get_mut_by_name(&ifname) {
            iface.owner.insert(Owner::CONFIG);
            return;
        }

        // If the interface does not exist, create a new entry.
        let iface = Interface {
            name: ifname.clone(),
            config: Default::default(),
            ifindex: None,
            mtu: None,
            flags: InterfaceFlags::default(),
            addresses: Default::default(),
            mac_address: Default::default(),
            owner: Owner::CONFIG,
            vrrp: None,
            subscriptions: Default::default(),
        };

        let iface_idx = self.arena.insert(iface);
        self.name_tree.insert(ifname, iface_idx);
    }

    // Adds or updates the interface with the specified attributes.
    pub(crate) fn update(
        &mut self,
        ifname: String,
        ifindex: u32,
        mtu: u32,
        flags: InterfaceFlags,
        mac_address: MacAddr,
        netlink_tx: &UnboundedSender<NetlinkRequest>,
    ) {
        match self
            .ifindex_tree
            .get(&ifindex)
            .or_else(|| self.name_tree.get(&ifname))
            .copied()
        {
            Some(iface_idx) => {
                let iface = &mut self.arena[iface_idx];

                // The netdev might be a new one reusing the name of a netdev
                // that is gone (e.g. a re-enumerated USB NIC), in which case
                // the ifindex needs to be rebound.
                let ifindex_changed = iface.ifindex != Some(ifindex);

                // If nothing of interest has changed, return early.
                if !ifindex_changed
                    && iface.name == ifname
                    && iface.mtu == Some(mtu)
                    && iface.flags == flags
                    && iface.mac_address == mac_address
                {
                    return;
                }

                // Update the existing interface with the new information.
                if iface.name != ifname {
                    self.name_tree.remove(&iface.name);
                    iface.name.clone_from(&ifname);
                    self.name_tree.insert(ifname.clone(), iface_idx);
                }
                if ifindex_changed {
                    if let Some(old_ifindex) = iface.ifindex {
                        self.ifindex_tree.remove(&old_ifindex);
                    }
                    iface.ifindex = Some(ifindex);
                    self.ifindex_tree.insert(ifindex, iface_idx);
                }
                iface.owner.insert(Owner::SYSTEM);
                iface.mtu = Some(mtu);
                iface.flags = flags;
                iface.mac_address = mac_address;

                // Notify subscribers about the interface update.
                for sub in self
                    .subscriptions
                    .values()
                    .chain(iface.subscriptions.values())
                {
                    ibus::notify_interface_update(&sub.tx, iface);
                }

                // Whenever the interface is bound to a new ifindex, apply any
                // pre-existing configuration options to the new netdev.
                if ifindex_changed {
                    let iface = &self.arena[iface_idx];
                    iface.apply_config(ifindex, netlink_tx, self);
                }
            }
            None => {
                // If the interface does not exist, create a new entry.
                let iface = Interface {
                    name: ifname.clone(),
                    config: Default::default(),
                    ifindex: Some(ifindex),
                    mtu: Some(mtu),
                    flags,
                    addresses: Default::default(),
                    mac_address,
                    owner: Owner::SYSTEM,
                    vrrp: None,
                    subscriptions: Default::default(),
                };

                // Notify subscribers about the interface update.
                for sub in self
                    .subscriptions
                    .values()
                    .chain(iface.subscriptions.values())
                {
                    ibus::notify_interface_update(&sub.tx, &iface);
                }

                let iface_idx = self.arena.insert(iface);
                self.name_tree.insert(ifname.clone(), iface_idx);
                self.ifindex_tree.insert(ifindex, iface_idx);
            }
        }
    }

    // Removes the specified interface identified by its ifindex.
    pub(crate) fn remove(
        &mut self,
        ifname: &str,
        owner: Owner,
        netlink_tx: &UnboundedSender<NetlinkRequest>,
    ) {
        let Some(iface_idx) = self.name_tree.get(ifname).copied() else {
            return;
        };
        let iface = &mut self.arena[iface_idx];

        // When the interface is unconfigured, uninstall all configured
        // addresses associated with it.
        if owner == Owner::CONFIG
            && let Some(ifindex) = iface.ifindex
        {
            for (addr, plen) in &iface.config.addr_list {
                let addr = IpNetwork::new(*addr, *plen).unwrap();
                netlink::addr_uninstall(netlink_tx, ifindex, &addr);
            }
        }

        // Remove interface only when it's both not present in the configuration
        // and not available in the kernel.
        iface.owner.remove(owner);
        if !iface.owner.is_empty() {
            // The netdev is gone but the interface is still configured. Discard
            // all kernel-derived state, as a netdev created later with the same
            // name will have a different ifindex.
            if owner == Owner::SYSTEM {
                // Notify subscribers that the interface is no longer operative,
                // while it still holds its old ifindex, so the update is
                // indistinguishable from a link-down of a known interface.
                iface.flags = InterfaceFlags::default();
                for sub in self
                    .subscriptions
                    .values()
                    .chain(iface.subscriptions.values())
                {
                    ibus::notify_interface_update(&sub.tx, iface);
                }

                // Withdraw all addresses of the netdev that is gone.
                let ifname = iface.name.clone();
                for (addr, iface_addr) in std::mem::take(&mut iface.addresses) {
                    for sub in self
                        .subscriptions
                        .values()
                        .chain(iface.subscriptions.values())
                        .filter(|sub| {
                            sub.afs.contains(&addr.ip().address_family())
                        })
                    {
                        ibus::notify_addr_del(
                            &sub.tx,
                            ifname.clone(),
                            iface_addr.addr,
                            iface_addr.flags,
                        );
                    }
                }

                // Discard the remaining kernel-derived state, as a netdev
                // created later with the same name will have a different
                // ifindex.
                if let Some(ifindex) = iface.ifindex.take() {
                    self.ifindex_tree.remove(&ifindex);
                }
                iface.mtu = None;

                // Check if the Router ID needs to be updated.
                self.update_router_id();
            }
            return;
        }

        // Notify subscribers about the interface update.
        for sub in self
            .subscriptions
            .values()
            .chain(iface.subscriptions.values())
        {
            ibus::notify_interface_del(&sub.tx, iface.name.clone());
        }

        // Remove interface.
        self.name_tree.remove(&iface.name);
        if let Some(ifindex) = iface.ifindex {
            self.ifindex_tree.remove(&ifindex);
        }
        self.arena.remove(iface_idx);

        // Check if the Router ID needs to be updated.
        self.update_router_id();
    }

    // Adds the specified address to the interface identified by its ifindex.
    pub(crate) fn addr_add(&mut self, ifindex: u32, addr: IpNetwork) {
        // Ignore loopback addresses.
        if addr.ip().is_loopback() {
            return;
        }

        // Lookup interface.
        let Some(iface) = self.get_mut_by_ifindex(ifindex) else {
            return;
        };

        // Add address to the interface.
        let mut flags = AddressFlags::empty();
        if !iface.flags.contains(InterfaceFlags::LOOPBACK)
            && let IpNetwork::V4(addr) = addr
            && addr.is_host_prefix()
        {
            flags.insert(AddressFlags::UNNUMBERED);
        }
        let iface_addr = InterfaceAddress { addr, flags };
        iface.addresses.insert(addr, iface_addr);

        // Notify subscribers about the address addition.
        let iface = self.get_by_ifindex(ifindex).unwrap();
        for sub in self
            .subscriptions
            .values()
            .chain(iface.subscriptions.values())
            .filter(|sub| sub.afs.contains(&addr.ip().address_family()))
        {
            let ifname = iface.name.clone();
            ibus::notify_addr_add(&sub.tx, ifname, addr, flags);
        }

        // Check if the Router ID needs to be updated.
        self.update_router_id();
    }

    // Removes the specified address from the interface identified by its ifindex.
    pub(crate) fn addr_del(&mut self, ifindex: u32, addr: IpNetwork) {
        // Lookup interface.
        let Some(iface) = self.get_mut_by_ifindex(ifindex) else {
            return;
        };

        // Remove address from the interface.
        if let Some(iface_addr) = iface.addresses.remove(&addr) {
            // Notify subscribers about the address removal.
            let iface = self.get_by_ifindex(ifindex).unwrap();
            for sub in self
                .subscriptions
                .values()
                .chain(iface.subscriptions.values())
                .filter(|sub| sub.afs.contains(&addr.ip().address_family()))
            {
                let ifname = iface.name.clone();
                ibus::notify_addr_del(
                    &sub.tx,
                    ifname,
                    iface_addr.addr,
                    iface_addr.flags,
                );
            }

            // Check if the Router ID needs to be updated.
            self.update_router_id();
        }
    }

    // Returns the auto-generated Router ID.
    pub(crate) fn router_id(&self) -> Option<Ipv4Addr> {
        self.router_id
    }

    // Updates the auto-generated Router ID.
    fn update_router_id(&mut self) {
        let loopback_interfaces = self
            .iter()
            .filter(|iface| iface.flags.contains(InterfaceFlags::LOOPBACK));
        let non_loopback_interfaces = self
            .iter()
            .filter(|iface| !iface.flags.contains(InterfaceFlags::LOOPBACK));

        // Helper function to find the highest IPv4 address among a list of
        // interfaces.
        fn highest_ipv4_addr<'a>(
            interfaces: impl Iterator<Item = &'a Interface>,
        ) -> Option<Ipv4Addr> {
            interfaces
                .flat_map(|iface| iface.addresses.values())
                .filter_map(|addr| {
                    if let IpAddr::V4(addr) = addr.addr.ip() {
                        Some(addr)
                    } else {
                        None
                    }
                })
                .filter(|addr| !addr.is_loopback())
                .filter(|addr| !addr.is_link_local())
                .filter(|addr| !addr.is_multicast())
                .filter(|addr| !addr.is_broadcast())
                .max()
        }

        // First, check for the highest IPv4 address on loopback interfaces.
        // If none exist or lack IPv4 addresses, try the non-loopback interfaces.
        let router_id = highest_ipv4_addr(loopback_interfaces)
            .or_else(|| highest_ipv4_addr(non_loopback_interfaces));

        if self.router_id != router_id {
            // Update the Router ID with the new value.
            self.router_id = router_id;

            // Notify subscribers about the Router ID update.
            for ibus_tx in self.router_id_subscriptions.values() {
                ibus::notify_router_id_update(ibus_tx, self.router_id);
            }
        }
    }

    // Returns a reference to the interface corresponding to the given name.
    pub(crate) fn get_by_name(&self, ifname: &str) -> Option<&Interface> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(|iface_idx| &self.arena[iface_idx])
    }

    // Returns a mutable reference to the interface corresponding to the given
    // name.
    pub(crate) fn get_mut_by_name(
        &mut self,
        ifname: &str,
    ) -> Option<&mut Interface> {
        self.name_tree
            .get(ifname)
            .copied()
            .map(move |iface_idx| &mut self.arena[iface_idx])
    }

    // Returns a reference to the interface corresponding to the given ifindex.
    pub(crate) fn get_by_ifindex(&self, ifindex: u32) -> Option<&Interface> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(|iface_idx| &self.arena[iface_idx])
    }

    // Returns a mutable reference to the interface corresponding to the given
    // ifindex.
    pub(crate) fn get_mut_by_ifindex(
        &mut self,
        ifindex: u32,
    ) -> Option<&mut Interface> {
        self.ifindex_tree
            .get(&ifindex)
            .copied()
            .map(move |iface_idx| &mut self.arena[iface_idx])
    }

    // Returns an iterator visiting all interfaces.
    //
    // Interfaces are ordered by their names.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'_ Interface> + '_ {
        self.name_tree
            .values()
            .map(|iface_idx| &self.arena[*iface_idx])
    }

    // Returns an iterator visiting all interfaces with mutable references.
    //
    // Order of iteration is not defined.
    pub(crate) fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = &'_ mut Interface> + '_ {
        self.arena.iter_mut().map(|(_, iface)| iface)
    }
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use holo_utils::ibus::IbusMsg;
    use tokio::sync::mpsc::{self, UnboundedReceiver};

    use super::*;

    // Returns a set of interfaces holding a single configured interface, along
    // with the receiving ends of the ibus and netlink channels.
    fn setup(
        ifname: &str,
    ) -> (
        Interfaces,
        UnboundedReceiver<IbusMsg>,
        UnboundedSender<NetlinkRequest>,
        UnboundedReceiver<NetlinkRequest>,
    ) {
        let (ibus_tx, ibus_rx) = mpsc::unbounded_channel();
        let (netlink_tx, netlink_rx) = mpsc::unbounded_channel();

        let mut interfaces = Interfaces::default();
        let afs = [AddressFamily::Ipv4, AddressFamily::Ipv6]
            .into_iter()
            .collect();
        interfaces
            .subscriptions
            .insert(0, InterfaceSub::new(afs, ibus_tx));
        interfaces.add(ifname.to_owned());

        (interfaces, ibus_rx, netlink_tx, netlink_rx)
    }

    fn flags_up() -> InterfaceFlags {
        InterfaceFlags::OPERATIVE | InterfaceFlags::BROADCAST
    }

    // Returns all pending notifications.
    fn drain(ibus_rx: &mut UnboundedReceiver<IbusMsg>) -> Vec<IbusMsg> {
        let mut msgs = Vec::new();
        while let Ok(msg) = ibus_rx.try_recv() {
            msgs.push(msg);
        }
        msgs
    }

    // Returns the ifindex and flags of the last interface update notification.
    fn last_upd(msgs: &[IbusMsg]) -> Option<(u32, InterfaceFlags)> {
        msgs.iter().rev().find_map(|msg| match msg {
            IbusMsg::InterfaceUpd(msg) => Some((msg.ifindex, msg.flags)),
            _ => None,
        })
    }

    // Returns the ifindex carried by the last interface update notification.
    fn last_upd_ifindex(msgs: &[IbusMsg]) -> Option<u32> {
        last_upd(msgs).map(|(ifindex, _)| ifindex)
    }

    // Returns the addresses carried by the address removal notifications.
    fn addr_dels(msgs: &[IbusMsg]) -> Vec<IpNetwork> {
        msgs.iter()
            .filter_map(|msg| match msg {
                IbusMsg::InterfaceAddressDel(msg) => Some(msg.addr),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn netdev_removal_clears_kernel_state() {
        let (mut interfaces, mut ibus_rx, netlink_tx, _netlink_rx) =
            setup("eth0");

        interfaces.update(
            "eth0".to_owned(),
            10,
            1500,
            flags_up(),
            MacAddr::default(),
            &netlink_tx,
        );
        assert_eq!(interfaces.get_by_name("eth0").unwrap().ifindex, Some(10));
        assert!(interfaces.get_by_ifindex(10).is_some());
        assert_eq!(last_upd_ifindex(&drain(&mut ibus_rx)), Some(10));

        let addr4: IpNetwork = "10.0.0.1/24".parse().unwrap();
        let addr6: IpNetwork = "2001:db8::1/64".parse().unwrap();
        interfaces.addr_add(10, addr4);
        interfaces.addr_add(10, addr6);
        let _ = drain(&mut ibus_rx);

        interfaces.remove("eth0", Owner::SYSTEM, &netlink_tx);
        let msgs = drain(&mut ibus_rx);

        // The interface survives since it's still configured, but all
        // kernel-derived state is gone.
        let iface = interfaces.get_by_name("eth0").unwrap();
        assert_eq!(iface.owner, Owner::CONFIG);
        assert_eq!(iface.ifindex, None);
        assert_eq!(iface.mtu, None);
        assert_eq!(iface.flags, InterfaceFlags::default());
        assert!(iface.addresses.is_empty());
        assert!(interfaces.get_by_ifindex(10).is_none());

        // Subscribers are told the interface is no longer operative, and the
        // notification carries the old ifindex, never zero.
        assert_eq!(last_upd(&msgs), Some((10, InterfaceFlags::default())));

        // Each address of the interface is withdrawn.
        let mut dels = addr_dels(&msgs);
        dels.sort();
        assert_eq!(dels, vec![addr4, addr6]);
    }

    #[test]
    fn netdev_recreated_with_new_ifindex() {
        let (mut interfaces, mut ibus_rx, netlink_tx, _netlink_rx) =
            setup("eth0");

        interfaces.update(
            "eth0".to_owned(),
            10,
            1500,
            flags_up(),
            MacAddr::default(),
            &netlink_tx,
        );
        interfaces.remove("eth0", Owner::SYSTEM, &netlink_tx);
        let _ = drain(&mut ibus_rx);

        interfaces.update(
            "eth0".to_owned(),
            11,
            1500,
            flags_up(),
            MacAddr::default(),
            &netlink_tx,
        );

        let iface = interfaces.get_by_name("eth0").unwrap();
        assert_eq!(iface.ifindex, Some(11));
        assert_eq!(iface.owner, Owner::CONFIG | Owner::SYSTEM);
        assert_eq!(
            interfaces.get_by_ifindex(11).map(|iface| &iface.name),
            Some(&"eth0".to_owned())
        );
        assert!(interfaces.get_by_ifindex(10).is_none());

        // The notification carries the new ifindex.
        assert_eq!(last_upd_ifindex(&drain(&mut ibus_rx)), Some(11));
    }

    #[test]
    fn ifindex_change_without_removal_rebinds() {
        let (mut interfaces, mut ibus_rx, netlink_tx, _netlink_rx) =
            setup("eth0");

        interfaces.update(
            "eth0".to_owned(),
            10,
            1500,
            flags_up(),
            MacAddr::default(),
            &netlink_tx,
        );
        let _ = drain(&mut ibus_rx);

        interfaces.update(
            "eth0".to_owned(),
            11,
            1500,
            flags_up(),
            MacAddr::default(),
            &netlink_tx,
        );

        assert_eq!(interfaces.get_by_name("eth0").unwrap().ifindex, Some(11));
        assert_eq!(
            interfaces.get_by_ifindex(11).map(|iface| &iface.name),
            Some(&"eth0".to_owned())
        );
        assert!(interfaces.get_by_ifindex(10).is_none());
        assert_eq!(last_upd_ifindex(&drain(&mut ibus_rx)), Some(11));
    }

    #[test]
    fn address_installed_on_new_ifindex() {
        let (mut interfaces, _ibus_rx, netlink_tx, _netlink_rx) = setup("eth0");

        interfaces.update(
            "eth0".to_owned(),
            10,
            1500,
            flags_up(),
            MacAddr::default(),
            &netlink_tx,
        );
        interfaces.remove("eth0", Owner::SYSTEM, &netlink_tx);
        interfaces.update(
            "eth0".to_owned(),
            11,
            1500,
            flags_up(),
            MacAddr::default(),
            &netlink_tx,
        );

        let addr: IpNetwork = "10.0.0.1/24".parse().unwrap();
        interfaces.addr_add(11, addr);

        let iface = interfaces.get_by_name("eth0").unwrap();
        assert!(iface.addresses.contains_key(&addr));
    }
}
