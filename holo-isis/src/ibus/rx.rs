//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//
// Sponsored by NLnet as part of the Next Generation Internet initiative.
// See: https://nlnet.nl/NGI0
//

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use holo_utils::bfd;
use holo_utils::bier::BierCfg;
use holo_utils::ip::IpNetworkKind;
use holo_utils::southbound::{
    AddressMsg, InterfaceUpdateMsg, RouteKeyMsg, RouteMsg,
};
use holo_utils::sr::{MsdType, SrCfg};

use crate::adjacency::{AdjacencyEvent, AdjacencyState};
use crate::error::Error;
use crate::instance::Instance;
use crate::packet::LevelType;
use crate::route::RouteSys;

// ===== global functions =====

pub(crate) fn process_router_id_update(
    instance: &mut Instance,
    router_id: Option<Ipv4Addr>,
) {
    instance.system.router_id = router_id;

    // Schedule LSP reorigination.
    if let Some((mut instance, _)) = instance.as_up() {
        instance.schedule_lsp_origination(LevelType::All);
    }
}

pub(crate) fn process_iface_update(
    instance: &mut Instance,
    msg: InterfaceUpdateMsg,
) -> Result<(), Error> {
    // Lookup interface.
    let Some(iface) = instance.arenas.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return Ok(());
    };
    let iface_idx = iface.index;

    // Update interface data.
    let old_mtu = iface.system.mtu;
    iface.system.flags = msg.flags;
    iface.system.mtu = Some(msg.mtu);
    iface.system.msd = msg.msd;
    iface.system.mac_addr = Some(msg.mac_address);
    if iface.system.ifindex != Some(msg.ifindex) {
        instance
            .arenas
            .interfaces
            .update_ifindex(iface_idx, Some(msg.ifindex));
    }

    if let Some((mut instance, arenas)) = instance.as_up() {
        let iface = &mut arenas.interfaces[iface_idx];

        // Update the padding used in Hello PDUs if the MTU has changed.
        if iface.config.hello_padding
            && iface.system.mtu != old_mtu
            && iface.state.active
            && !iface.is_passive()
        {
            iface.hello_interval_start(&instance, LevelType::All);
        }

        // Check if IS-IS needs to be activated or deactivated on this interface.
        iface.update(&mut instance, &mut arenas.adjacencies)?;
    }

    Ok(())
}

pub(crate) fn process_addr_add(instance: &mut Instance, msg: AddressMsg) {
    // Lookup interface.
    let Some(iface) = instance.arenas.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };
    let iface_idx = iface.index;

    // Add address to interface.
    iface.system.addr_list.insert(msg.addr);

    if let Some((mut instance, arenas)) = instance.as_up() {
        let iface = &mut arenas.interfaces[iface_idx];

        if iface.state.active {
            // Update Hello Tx task(s).
            if !iface.is_passive() {
                iface.hello_interval_start(&instance, LevelType::All);
            }

            // Schedule LSP reorigination.
            instance.schedule_lsp_origination(LevelType::All);
        }
    }
}

pub(crate) fn process_addr_del(instance: &mut Instance, msg: AddressMsg) {
    // Lookup interface.
    let Some(iface) = instance.arenas.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };
    let iface_idx = iface.index;

    // Remove address from interface.
    iface.system.addr_list.remove(&msg.addr);

    if let Some((mut instance, arenas)) = instance.as_up() {
        let iface = &mut arenas.interfaces[iface_idx];

        if iface.state.active {
            // Update Hello Tx task(s).
            if !iface.is_passive() {
                iface.hello_interval_start(&instance, LevelType::All);
            }

            // Schedule LSP reorigination.
            instance.schedule_lsp_origination(LevelType::All);
        }
    }
}

pub(crate) fn process_route_add(instance: &mut Instance, msg: RouteMsg) {
    let prefix = msg.prefix;
    if !prefix.is_routable() {
        return;
    }

    // Return if no configuration exists for the address family.
    let Some(af_cfg) = instance.config.afs.get(&prefix.address_family()) else {
        return;
    };

    // Iterate over levels where redistribution is enabled for this route's
    // protocol.
    for level in instance
        .config
        .levels()
        .filter(|level| {
            af_cfg.redistribution.contains_key(&(*level, msg.protocol))
        })
        .collect::<Vec<_>>()
    {
        let route = RouteSys {
            protocol: msg.protocol,
            metric: msg.metric,
            tag: msg.tag,
            opaque_attrs: msg.opaque_attrs,
        };
        let routes = instance.system.routes.get_mut(level);
        routes.insert(prefix, route);

        // Schedule LSP reorigination.
        if let Some((mut instance, _)) = instance.as_up() {
            instance.schedule_lsp_origination(level);
        }
    }
}

pub(crate) fn process_route_del(instance: &mut Instance, msg: RouteKeyMsg) {
    let prefix = msg.prefix;
    if !prefix.is_routable() {
        return;
    }

    // Return if no configuration exists for the address family.
    let Some(af_cfg) = instance.config.afs.get(&prefix.address_family()) else {
        return;
    };

    // Iterate over levels where redistribution is enabled for this route's
    // protocol.
    for level in instance
        .config
        .levels()
        .filter(|level| {
            af_cfg.redistribution.contains_key(&(*level, msg.protocol))
        })
        .collect::<Vec<_>>()
    {
        // Remove the route only if it is the one being advertised: the RIB
        // sends a delete per protocol, and a prefix redistributed from two
        // protocols is held here once. When the best route for a prefix
        // changes protocol, the RIB sends an add for the new protocol
        // followed by a delete for the old one; an unconditional remove would
        // drop the entry the add just installed.
        let routes = instance.system.routes.get_mut(level);
        if routes
            .get(&prefix)
            .is_none_or(|route| route.protocol != msg.protocol)
        {
            continue;
        }
        routes.remove(&prefix);

        // Schedule LSP reorigination.
        if let Some((mut instance, _)) = instance.as_up() {
            instance.schedule_lsp_origination(level);
        }
    }
}

pub(crate) fn process_hostname_update(
    instance: &mut Instance,
    hostname: Option<String>,
) {
    // Update hostname.
    instance.shared.hostname = hostname;

    // Schedule LSP reorigination.
    if let Some((mut instance, _)) = instance.as_up() {
        instance.schedule_lsp_origination(instance.config.level_type);
    }
}

pub(crate) fn process_bfd_state_update(
    instance: &mut Instance,
    sess_key: bfd::SessionKey,
    state: bfd::State,
) -> Result<(), Error> {
    // We're only interested on peer down notifications.
    if state != bfd::State::Down {
        return Ok(());
    }

    // Ignore notification if the IS-IS instance isn't active anymore.
    let Some((mut instance, arenas)) = instance.as_up() else {
        return Ok(());
    };

    // Lookup interface.
    let bfd::SessionKey::IpSingleHop { ifname, .. } = &sess_key else {
        return Ok(());
    };
    let Some(iface) = arenas.interfaces.get_mut_by_name(ifname) else {
        return Ok(());
    };

    // On LAN interfaces, both L1 and L2 adjacencies share the same BFD session.
    iface.with_adjacencies(&mut arenas.adjacencies, |iface, adj| {
        let bfd = adj
            .bfd
            .iter_mut()
            .filter_map(|(_, b)| b.as_mut())
            .find(|b| b.sess_key == sess_key);
        if let Some(bfd) = bfd {
            // Update the status of the BFD session.
            bfd.state = Some(state);
            if !adj.is_bfd_healthy() {
                adj.state_change(
                    iface,
                    &mut instance,
                    AdjacencyEvent::BfdDown,
                    AdjacencyState::Down,
                );
            }
        }
    });
    instance.schedule_lsp_origination(instance.config.level_type);

    Ok(())
}

pub(crate) fn process_keychain_update(
    instance: &mut Instance,
    keychain_name: &str,
) -> Result<(), Error> {
    // Update global auth if it uses this keychain.
    if instance.config.auth.all.keychain.as_deref() == Some(keychain_name) {
        let keychains = &instance.shared.keychains;
        let auth = instance.config.auth.all.method(keychains);
        instance.config.auth_resolved.store(Arc::new(auth));

        // Schedule LSP reorigination to encode with the new key.
        if let Some((mut instance, _)) = instance.as_up() {
            instance.schedule_lsp_origination(instance.config.level_type);
        }
    }

    // Update hello auth on each interface that uses this keychain.
    for iface in instance.arenas.interfaces.iter_mut() {
        if iface.config.hello_auth.all.keychain.as_deref()
            == Some(keychain_name)
        {
            let keychains = &instance.shared.keychains;
            let auth = iface.config.hello_auth.all.method(keychains);
            iface.config.hello_auth_resolved.store(Arc::new(auth));
        }
    }

    Ok(())
}

pub(crate) fn process_sr_cfg_update(
    instance: &mut Instance,
    sr_config: Arc<SrCfg>,
) {
    // Update SR configuration.
    instance.shared.sr_config = sr_config;

    // Schedule LSP reorigination.
    if instance.config.sr.enabled
        && let Some((mut instance, _)) = instance.as_up()
    {
        instance.schedule_lsp_origination(instance.config.level_type);
    }
}

pub(crate) fn process_bier_cfg_update(
    instance: &mut Instance,
    bier_config: Arc<BierCfg>,
) {
    // Update BIER configuration.
    instance.shared.bier_config = bier_config;

    // Schedule LSP reorigination.
    if instance.config.bier.enabled
        && instance.config.bier.advertise
        && let Some((mut instance, _)) = instance.as_up()
    {
        instance.schedule_lsp_origination(instance.config.level_type);
    }
}

pub(crate) fn process_msd_update(
    instance: &mut Instance,
    node_msd: BTreeMap<MsdType, u8>,
) {
    // Update node MSD.
    instance.system.node_msd = node_msd;

    // Schedule LSP reorigination.
    if let Some((mut instance, _)) = instance.as_up() {
        instance.schedule_lsp_origination(instance.config.level_type);
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use holo_protocol::{InstanceChannelsTx, ProtocolInstance};
    use holo_utils::ibus::ibus_channels;
    use holo_utils::ip::AddressFamily;
    use holo_utils::protocol::Protocol;
    use holo_utils::southbound::RouteOpaqueAttrs;
    use ipnetwork::IpNetwork;
    use tokio::sync::mpsc;

    use super::*;
    use crate::northbound::configuration::{
        AddressFamilyCfg, RedistributionCfg,
    };
    use crate::packet::LevelNumber;

    // Builds an instance whose IPv4 address family redistributes both static
    // and OSPFv2 routes at level 2, holding one redistributed route for
    // `prefix` learned from `protocol`.
    fn test_instance(prefix: IpNetwork, protocol: Protocol) -> Instance {
        let (nb_tx, _nb_rx) = mpsc::unbounded_channel();
        let (ibus_tx, _ibus_rx) = ibus_channels();
        let (protocol_input_tx, _protocol_input_rx) =
            Instance::protocol_input_channels();
        let (protocol_output_tx, _protocol_output_rx) = mpsc::channel(4);
        let tx = InstanceChannelsTx::new(
            nb_tx,
            ibus_tx,
            protocol_input_tx,
            protocol_output_tx,
        );
        let mut instance =
            Instance::new("test".to_owned(), Default::default(), tx);

        instance.config.level_type = LevelType::L2;
        let mut af_cfg = AddressFamilyCfg::default();
        for protocol in [Protocol::STATIC, Protocol::OSPFV2] {
            af_cfg
                .redistribution
                .insert((LevelNumber::L2, protocol), RedistributionCfg {});
        }
        instance.config.afs.insert(AddressFamily::Ipv4, af_cfg);

        instance.system.routes.get_mut(LevelNumber::L2).insert(
            prefix,
            RouteSys {
                protocol,
                metric: 10,
                tag: None,
                opaque_attrs: RouteOpaqueAttrs::None,
            },
        );
        instance
    }

    // The RIB sends a redistribute delete per protocol, but a prefix is held
    // here once. When the best route for a prefix changes protocol the RIB
    // sends an add for the new protocol followed by a delete for the old one;
    // a delete that ignored the protocol would drop the entry the add just
    // installed and withdraw the prefix from the LSP.
    #[test]
    fn route_del_of_another_protocol_keeps_the_route() {
        let prefix: IpNetwork = "10.249.0.1/32".parse().unwrap();
        let mut instance = test_instance(prefix, Protocol::OSPFV2);

        process_route_del(
            &mut instance,
            RouteKeyMsg {
                protocol: Protocol::STATIC,
                prefix,
            },
        );

        let route = instance
            .system
            .routes
            .get(LevelNumber::L2)
            .get(&prefix)
            .expect("route of another protocol must not be removed");
        assert_eq!(route.protocol, Protocol::OSPFV2);
    }

    // The guard must not stop the delete that does own the route.
    #[test]
    fn route_del_of_the_advertised_protocol_removes_the_route() {
        let prefix: IpNetwork = "10.249.0.1/32".parse().unwrap();
        let mut instance = test_instance(prefix, Protocol::OSPFV2);

        process_route_del(
            &mut instance,
            RouteKeyMsg {
                protocol: Protocol::OSPFV2,
                prefix,
            },
        );

        assert!(
            instance
                .system
                .routes
                .get(LevelNumber::L2)
                .get(&prefix)
                .is_none()
        );
    }
}
