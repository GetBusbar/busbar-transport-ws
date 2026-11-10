// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(linked_every_transport)]
#[test]
fn actual_ws_locates_before_open_without_network_or_runtime_state() {
    use crate::root::loader::dispatch::{Bind, ConnTable, DispatchConfig, Dispatcher, NoSink};
    let on = Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    );
    let binding = || Bind {
        instance: Arc::from("pure-config-locate"),
        max_inflight_cap: 1,
        sink: Arc::new(NoSink),
        dispatcher: on.adopter(),
        conns: ConnTable::NoNeeds,
    };
    for (door, target, secure) in [(
        busbar_transport_ws::door as busbar_contract::abi::mechanism::door::DoorFn,
        "wss://unreachable.invalid:9443/path",
        true,
    )] {
        let plugin = crate::root::test_plugins::linked_transport(door, binding());
        assert!(!plugin.is_open());
        let located =
            crate::root::doors::locate_bound(&plugin, target).expect("pure pre-open locate");
        assert_eq!(located.secure, secure);
        assert!(located.authority.ends_with(":9443"));
        assert!(
            !plugin.is_open(),
            "LOCATE must not transition lifecycle state"
        );
    }
}
