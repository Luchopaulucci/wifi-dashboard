use wifi_core::{
    neighbor_is_live, parse_ip_neigh, parse_iw_info, parse_iw_link, parse_nmcli_device_show,
    parse_nmcli_wifi_list, parse_ping_latency, parse_ping_stats, parse_proc_wireless,
    split_nmcli_terse, Band,
};

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).expect("fixture")
}

#[test]
fn nmcli_terse_unescapes_bssid() {
    let cols = split_nmcli_terse(r#"*:AA\:BB\:CC\:11\:22\:33:Fibertel-5G:36"#);
    assert_eq!(cols[0], "*");
    assert_eq!(cols[1], "AA:BB:CC:11:22:33");
    assert_eq!(cols[2], "Fibertel-5G");
    assert_eq!(cols[3], "36");
}

#[test]
fn nmcli_wifi_list_fixture() {
    let list = parse_nmcli_wifi_list(&fixture("nmcli_wifi_list.txt")).unwrap();
    assert_eq!(list.len(), 4);
    assert!(list[0].in_use);
    assert_eq!(list[0].ssid, "Fibertel-5G");
    assert_eq!(list[0].bssid, "AA:BB:CC:11:22:33");
    assert_eq!(list[0].channel, Some(36));
    assert_eq!(list[0].frequency_mhz, Some(5180));
    assert_eq!(list[0].band, Some(Band::Ghz5));
    assert_eq!(list[0].signal_pct, Some(96));
    assert_eq!(list[0].security, "WPA2");
    assert_eq!(list[1].band, Some(Band::Ghz24));
    assert_eq!(list[3].ssid, "");
}

#[test]
fn nmcli_device_show_fixture() {
    let live = parse_nmcli_device_show(&fixture("nmcli_device_show.txt"));
    assert_eq!(live.iface, "wlp2s0");
    assert_eq!(live.ssid.as_deref(), Some("Fibertel-5G"));
    assert_eq!(live.ip.as_deref(), Some("192.168.0.24"));
    assert_eq!(live.prefix_len, Some(24));
    assert_eq!(live.gateway.as_deref(), Some("192.168.0.1"));
    assert_eq!(live.dns, vec!["192.168.0.1", "1.1.1.1"]);
}

#[test]
fn iw_link_fixture() {
    let live = parse_iw_link(&fixture("iw_link.txt"));
    assert_eq!(live.ssid.as_deref(), Some("Fibertel-5G"));
    assert_eq!(live.bssid.as_deref(), Some("aa:bb:cc:11:22:33"));
    assert_eq!(live.frequency_mhz, Some(5180));
    assert_eq!(live.band, Some(Band::Ghz5));
    assert_eq!(live.signal_dbm, Some(-52));
    assert_eq!(live.signal_pct, Some(96));
    assert_eq!(live.tx_mbps, Some(866.7));
    assert_eq!(live.rx_mbps, Some(780.0));
}

#[test]
fn iw_info_fixture() {
    let live = parse_iw_info(&fixture("iw_info.txt"));
    assert_eq!(live.iface, "wlp2s0");
    assert_eq!(live.ssid.as_deref(), Some("Fibertel-5G"));
    assert_eq!(live.channel, Some(36));
    assert_eq!(live.frequency_mhz, Some(5180));
}

#[test]
fn proc_wireless_fixture() {
    let text = fixture("proc_wireless.txt");
    let (name, dbm, pct) = parse_proc_wireless(&text, Some("wlp2s0")).unwrap();
    assert_eq!(name, "wlp2s0");
    assert_eq!(dbm, -52);
    assert_eq!(pct, 96);
    let wlan = parse_proc_wireless(&text, Some("wlan0")).unwrap();
    assert_eq!(wlan.1, -70);
}

#[test]
fn ip_neigh_skips_failed_and_ipv6() {
    let devices = parse_ip_neigh(&fixture("ip_neigh.txt"));
    let ips: Vec<_> = devices.iter().map(|d| d.ip.as_str()).collect();
    assert!(ips.contains(&"192.168.0.1"));
    assert!(ips.contains(&"192.168.0.18"));
    assert!(!ips.contains(&"192.168.0.99"));
    assert!(devices.iter().all(|d| !d.ip.contains(':')));
    let gw = devices.iter().find(|d| d.ip == "192.168.0.1").unwrap();
    assert_eq!(gw.mac.as_deref(), Some("aa:bb:cc:11:22:33"));
    assert_eq!(gw.state, "REACHABLE");
}

#[test]
fn ip_neigh_skips_incomplete() {
    assert!(!neighbor_is_live("INCOMPLETE"));
    assert!(!neighbor_is_live("FAILED"));
    assert!(neighbor_is_live("REACHABLE"));
    assert!(neighbor_is_live("STALE"));
    assert!(neighbor_is_live("DELAY"));
    let devices = parse_ip_neigh(&fixture("ip_neigh.txt"));
    let ips: Vec<_> = devices.iter().map(|d| d.ip.as_str()).collect();
    assert!(!ips.contains(&"192.168.0.50"));
    assert!(!ips.contains(&"192.168.0.99"));
}

#[test]
fn ping_fixture_latency() {
    let text = fixture("ping.txt");
    assert_eq!(parse_ping_latency(&text), Some(18.312));
    let (sent, recv, avg) = parse_ping_stats(&text);
    assert_eq!(sent, 1);
    assert_eq!(recv, 1);
    assert_eq!(avg, Some(18.312));
}

#[test]
fn ping_fixture_loss_is_not_alive() {
    let text = fixture("ping_loss.txt");
    assert_eq!(parse_ping_latency(&text), None);
    let (sent, recv, avg) = parse_ping_stats(&text);
    assert_eq!(sent, 1);
    assert_eq!(recv, 0);
    assert_eq!(avg, None);
}
