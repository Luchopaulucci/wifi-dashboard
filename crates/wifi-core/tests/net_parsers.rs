use std::net::IpAddr;

use wifi_core::net::{
    classify_hops, classify_reach, classify_talker, explain_rule_criollo, is_permission_error,
    is_public_ip, parse_conntrack, parse_ip_api, parse_iptables_save, parse_journal_resolved,
    parse_nft_ruleset, parse_proc_net_dev, parse_proc_net_netstat, parse_proc_net_snmp, parse_rdap,
    parse_resolvectl_cache, parse_resolvectl_statistics, parse_ss_listeners, parse_ss_sockets,
    parse_trace_line, snmp_counters, summarize_verdicts, Reachability, TraceHopKind,
};
use wifi_core::validate_host;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).expect("fixture")
}

#[test]
fn ss_tunap_fixture() {
    let rows = parse_ss_sockets(&fixture("ss_tunap.txt"));
    assert!(rows.len() >= 7);
    let ff = rows
        .iter()
        .find(|r| r.remote_ip == "1.1.1.1" && r.remote_port == "443")
        .unwrap();
    assert_eq!(ff.protocol, "tcp");
    assert_eq!(ff.state, "ESTABLISHED");
    assert_eq!(ff.process.as_deref(), Some("firefox"));
    assert_eq!(ff.pid, Some(4321));
    let dns = rows.iter().find(|r| r.remote_port == "53").unwrap();
    assert_eq!(dns.process.as_deref(), Some("systemd-resolve"));
    let tw = rows.iter().find(|r| r.state == "TIME_WAIT").unwrap();
    assert_eq!(tw.process.as_deref(), Some("code"));
    let v6 = rows
        .iter()
        .find(|r| r.remote_ip.contains("2606:4700"))
        .unwrap();
    assert_eq!(v6.remote_port, "443");
}

#[test]
fn ss_listeners_reachability() {
    let rows = parse_ss_listeners(&fixture("ss_tulpn.txt"));
    let ssh = rows
        .iter()
        .find(|r| r.local_port == "22" && r.local_ip == "0.0.0.0")
        .unwrap();
    assert_eq!(ssh.process.as_deref(), Some("sshd"));
    assert_eq!(ssh.reach, Reachability::NetworkAll);
    let cups = rows.iter().find(|r| r.local_port == "631").unwrap();
    assert_eq!(cups.reach, Reachability::LocalOnly);
    let py = rows.iter().find(|r| r.local_port == "8080").unwrap();
    assert_eq!(py.reach, Reachability::LanAddress);
    assert_eq!(classify_reach("127.0.0.1"), Reachability::LocalOnly);
    assert_eq!(classify_reach("::1"), Reachability::LocalOnly);
    assert_eq!(classify_reach("0.0.0.0"), Reachability::NetworkAll);
    assert_eq!(classify_reach("::"), Reachability::NetworkAll);
}

#[test]
fn conntrack_nat_orig_vs_reply() {
    let rows = parse_conntrack(&fixture("conntrack.txt"));
    assert_eq!(rows.len(), 5);
    let plain = rows
        .iter()
        .find(|r| r.dest_ip == "1.1.1.1" && r.protocol == "tcp")
        .unwrap();
    assert_eq!(plain.internal_ip, "192.168.0.24");
    assert_eq!(plain.translated_ip, "192.168.0.24");
    assert_eq!(plain.nat_kind, "ninguno");
    assert_eq!(plain.timeout_secs, Some(431999));
    assert!(plain.assured);

    let snat = rows.iter().find(|r| r.nat_kind == "SNAT").unwrap();
    assert_eq!(snat.internal_ip, "10.0.0.5");
    assert_eq!(snat.translated_ip, "181.15.20.30");
    assert_eq!(snat.dest_ip, "8.8.8.8");

    let dnat = rows.iter().find(|r| r.nat_kind == "DNAT").unwrap();
    assert_eq!(dnat.internal_ip, "192.168.0.24");
    assert_eq!(dnat.dest_ip, "203.0.113.10");
    assert_eq!(dnat.translated_ip, "192.168.0.24");
}

#[test]
fn nft_ruleset_and_criollo() {
    let tables = parse_nft_ruleset(&fixture("nft_ruleset.txt"));
    assert_eq!(tables.len(), 2);
    let filter = tables.iter().find(|t| t.name == "filter").unwrap();
    let input = filter.chains.iter().find(|c| c.name == "input").unwrap();
    assert_eq!(input.policy.as_deref(), Some("drop"));
    assert!(input.rules.iter().any(|r| r.text.contains("dport 22")));
    let drop = input
        .rules
        .iter()
        .find(|r| r.verdict.as_deref() == Some("drop"))
        .unwrap();
    assert_eq!(drop.packets, Some(12));
    assert_eq!(drop.bytes, Some(840));
    let ssh = input
        .rules
        .iter()
        .find(|r| r.text.contains("dport 22"))
        .unwrap();
    assert!(ssh.criollo.contains("SSH") || ssh.criollo.contains("22"));
    let nat = tables.iter().find(|t| t.name == "nat").unwrap();
    let post = nat.chains.iter().find(|c| c.name == "postrouting").unwrap();
    let masq = post
        .rules
        .iter()
        .find(|r| r.text.contains("masquerade"))
        .unwrap();
    assert!(masq.criollo.to_ascii_lowercase().contains("nat") || masq.criollo.contains("disfraza"));
}

#[test]
fn iptables_save_counters() {
    let tables = parse_iptables_save(&fixture("iptables_save.txt"));
    let filter = tables.iter().find(|t| t.name == "filter").unwrap();
    let input = filter.chains.iter().find(|c| c.name == "INPUT").unwrap();
    assert_eq!(input.policy.as_deref(), Some("DROP"));
    assert_eq!(input.policy_packets, Some(10));
    let ssh = input
        .rules
        .iter()
        .find(|r| r.text.contains("--dport 22"))
        .unwrap();
    assert_eq!(ssh.packets, Some(2));
    assert_eq!(ssh.verdict.as_deref(), Some("accept"));
    let (acc_p, _, drop_p, _) = summarize_verdicts(&tables);
    assert!(acc_p >= 1230);
    assert!(drop_p >= 10 + 5);
}

#[test]
fn traceroute_and_tracepath_hops() {
    let mut hops: Vec<_> = fixture("traceroute.txt")
        .lines()
        .filter_map(parse_trace_line)
        .collect();
    assert_eq!(hops.len(), 5);
    classify_hops(&mut hops, Some("192.168.0.1"), "8.8.8.8");
    assert_eq!(hops[0].kind, TraceHopKind::HomeRouter);
    assert_eq!(hops[1].kind, TraceHopKind::Private);
    assert_eq!(hops[2].kind, TraceHopKind::IspStart);
    assert!(hops[3].lost);
    assert_eq!(hops[3].kind, TraceHopKind::Lost);
    assert_eq!(hops[4].kind, TraceHopKind::Destination);
    assert_eq!(hops[0].rtt_ms, Some(1.234));

    let tp: Vec<_> = fixture("tracepath.txt")
        .lines()
        .filter_map(parse_trace_line)
        .collect();
    assert!(tp
        .iter()
        .any(|h| h.kind == TraceHopKind::Localhost || h.hostname.as_deref() == Some("LOCALHOST")));
    assert!(tp.iter().any(|h| h.lost));
    assert!(tp.iter().any(|h| h.address.as_deref() == Some("8.8.8.8")));
}

#[test]
fn snmp_and_dev_counters() {
    let snmp = parse_proc_net_snmp(&fixture("proc_net_snmp.txt"));
    assert_eq!(snmp.get("Tcp.ActiveOpens").copied(), Some(1500));
    assert_eq!(snmp.get("Udp.OutDatagrams").copied(), Some(4000));
    let netstat = parse_proc_net_netstat(&fixture("proc_net_netstat.txt"));
    assert_eq!(netstat.get("IpExt.OutOctets").copied(), Some(500000));
    let counters = snmp_counters(&snmp, &netstat);
    assert!(counters
        .iter()
        .any(|c| c.id == "tcp_active_opens" && c.value == 1500));
    assert!(counters.iter().any(|c| c.source.contains("/proc/net/snmp")));
    let ifaces = parse_proc_net_dev(&fixture("proc_net_dev.txt"));
    let wlan = ifaces.iter().find(|i| i.name == "wlan0").unwrap();
    assert_eq!(wlan.tx_bytes, 500000);
    assert_eq!(wlan.rx_packets, 5000);
}

#[test]
fn dns_stats_cache_journal_talkers() {
    let st = parse_resolvectl_statistics(&fixture("resolvectl_statistics.txt"));
    assert_eq!(st.queries_total, Some(847));
    assert_eq!(st.cache_hits, Some(500));
    let (rows, map) = parse_resolvectl_cache(&fixture("resolvectl_cache.txt"));
    assert!(map.get("142.250.184.14").unwrap().contains("google"));
    assert!(rows.iter().any(|r| r.domain.contains("metrics.ubuntu.com")));
    let journal = parse_journal_resolved(&fixture("journal_resolved.txt"));
    let g = journal
        .iter()
        .find(|r| r.domain == "www.google.com")
        .unwrap();
    assert_eq!(g.count, 2);
    assert!(classify_talker("metrics.ubuntu.com").is_some());
    assert!(classify_talker("daisy.ubuntu.com").unwrap().kind == "telemetria");
    assert!(classify_talker("api.snapcraft.io").unwrap().kind == "updates");
}

#[test]
fn geo_parsers_and_public_ip() {
    let g = parse_ip_api(&fixture("ip_api.json")).unwrap();
    assert_eq!(g.asn.as_deref(), Some("AS15169"));
    assert!(g.source_label.contains("externa"));
    let r = parse_rdap(&fixture("rdap.json"), "8.8.8.8").unwrap();
    assert_eq!(r.ip, "8.8.8.8");
    assert!(r.org.as_deref().unwrap().contains("Google") || r.source == "rdap.org");
    let pub_ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert!(is_public_ip(pub_ip));
    assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
}

#[test]
fn privilege_and_host_validation() {
    assert!(is_permission_error("Operation not permitted"));
    assert!(validate_host("https://one.one.one.one/cdn-cgi").is_ok());
    assert!(validate_host("8.8.8.8;rm").is_err());
    let c = explain_rule_criollo("ct state invalid drop");
    assert!(
        c.to_ascii_lowercase().contains("inválid")
            || c.contains("inválidos")
            || c.contains("invalid")
            || c.contains("tira")
    );
}
