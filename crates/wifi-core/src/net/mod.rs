//! Diagnóstico de red de solo lectura: conexiones, NAT, firewall, ruta,
//! tráfico desde el arranque y puertos en escucha.
//!
//! Nunca cambia el estado del sistema. Si un comando pide root/CAP_NET_ADMIN,
//! se devuelve un panel con un botón que eleva esa acción vía pkexec.

mod addr;
mod collect;
mod conntrack;
mod criollo;
mod dns;
mod firewall;
mod geo;
mod privilege;
mod ss;
mod stats;
mod talkers;
mod trace;

pub use addr::{is_public_ip, parse_ip_opt};
pub use collect::{
    alloc_trace_session, apply_listener_session, collect_boot_traffic, collect_connections,
    collect_firewall, collect_listeners, collect_nat, default_gateway, ingest_monitor_line,
    listener_keys, lookup_ptr, monitor_rows, remember_dns_talker, spawn_dns_monitor, start_trace,
    GeoCache, ListenerScan, ListenerSession, PtrCache, TraceSession,
};
pub use conntrack::parse_conntrack;
pub use criollo::explain_rule_criollo;
pub use dns::{
    is_noise_domain, parse_journal_resolved, parse_resolvectl_cache, parse_resolvectl_statistics,
    ResolvedStats,
};
pub use firewall::{parse_iptables_save, parse_nft_ruleset, summarize_verdicts};
pub use geo::{
    geo_opt_in_denied_message, lookup_ip_external, parse_ip_api, parse_rdap, rdap_source_label,
    RateLimiter,
};
pub use privilege::{
    is_permission_error, privilege_hint, ElevateError, Pkexec, PrivilegeHint, PrivilegedAction,
};
pub use ss::{
    classify_reach, is_ephemeral_udp, listener_key, parse_ss_listeners, parse_ss_sockets,
};
pub use stats::{
    iface_counters, parse_proc_net_dev, parse_proc_net_netstat, parse_proc_net_snmp, snmp_counters,
    IfaceCounters,
};
pub use talkers::classify_talker;
pub use trace::{classify_hops, parse_trace_line};
pub use types::{
    BootTrafficReport, ConnectionRow, ConnectionsReport, DnsDomainRow, DnsMonitorStatus,
    DnsProgramRow, FirewallChain, FirewallReport, FirewallRule, FirewallTable, GeoInfo,
    ListenerRow, ListenersReport, NatReport, NatTranslation, PrivilegePanel, Reachability,
    TalkerTag, TraceEvent, TraceHop, TraceHopKind, TrafficCounter,
};

mod types;
