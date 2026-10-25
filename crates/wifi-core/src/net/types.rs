use serde::{Deserialize, Serialize};

use super::privilege::PrivilegeHint;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivilegePanel {
    pub hint: PrivilegeHint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionRow {
    pub protocol: String,
    pub local_ip: String,
    pub local_port: String,
    pub remote_ip: String,
    pub remote_port: String,
    pub state: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub domain: Option<String>,
    pub domain_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectionsReport {
    pub collected_at_ms: u64,
    pub rows: Vec<ConnectionRow>,
    pub sources: Vec<String>,
    pub missing: Vec<String>,
    pub privilege: Option<PrivilegeHint>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NatTranslation {
    pub protocol: String,
    pub internal_ip: String,
    pub internal_port: String,
    pub translated_ip: String,
    pub translated_port: String,
    pub dest_ip: String,
    pub dest_port: String,
    pub state: Option<String>,
    pub timeout_secs: Option<u64>,
    pub nat_kind: String,
    pub assured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NatReport {
    pub collected_at_ms: u64,
    pub translations: Vec<NatTranslation>,
    pub active_count: u64,
    pub snat_count: u64,
    pub dnat_count: u64,
    pub source: Option<String>,
    pub missing: Vec<String>,
    pub privilege: Option<PrivilegeHint>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallRule {
    pub table: String,
    pub family: Option<String>,
    pub chain: String,
    pub handle: Option<String>,
    pub text: String,
    pub criollo: String,
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    pub verdict: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallTable {
    pub name: String,
    pub family: Option<String>,
    pub chains: Vec<FirewallChain>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallChain {
    pub name: String,
    pub hook: Option<String>,
    pub policy: Option<String>,
    pub policy_packets: Option<u64>,
    pub policy_bytes: Option<u64>,
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallReport {
    pub collected_at_ms: u64,
    pub backend: Option<String>,
    pub tables: Vec<FirewallTable>,
    pub accepted_packets: u64,
    pub accepted_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
    pub missing: Vec<String>,
    pub privilege: Option<PrivilegeHint>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceHopKind {
    HomeRouter,
    Private,
    IspStart,
    Transit,
    Destination,
    Lost,
    Localhost,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceHop {
    pub hop: u32,
    pub address: Option<String>,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
    pub lost: bool,
    pub kind: TraceHopKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceEvent {
    pub session_id: String,
    pub kind: String,
    pub hop: Option<TraceHop>,
    pub message: Option<String>,
    pub tool: Option<String>,
    pub privilege: Option<PrivilegeHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrafficCounter {
    pub id: String,
    pub label: String,
    pub value: u64,
    pub meaning: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsDomainRow {
    pub domain: String,
    pub count: u64,
    pub source: String,
    pub talker: Option<TalkerTag>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsProgramRow {
    pub process: String,
    pub pid: Option<u32>,
    pub dns_server: Option<String>,
    pub proto: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsMonitorStatus {
    pub running: bool,
    pub error: Option<String>,
    pub needs_privilege: bool,
    pub explanation: String,
}

impl Default for DnsMonitorStatus {
    fn default() -> Self {
        Self {
            running: false,
            error: None,
            needs_privilege: false,
            explanation: "El monitor DNS todavía no arrancó.".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TalkerTag {
    pub label: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BootTrafficReport {
    pub collected_at_ms: u64,
    pub counters: Vec<TrafficCounter>,
    pub domains: Vec<DnsDomainRow>,
    pub programs: Vec<DnsProgramRow>,
    pub missing: Vec<String>,
    pub privilege: Option<PrivilegeHint>,
    pub limitations: Vec<String>,
    pub dns_monitor: DnsMonitorStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    LocalOnly,
    NetworkAll,
    LanAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListenerRow {
    pub protocol: String,
    pub local_ip: String,
    pub local_port: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub reach: Reachability,
    pub reach_label: String,
    pub key: String,
    pub is_new: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListenersReport {
    pub collected_at_ms: u64,
    pub rows: Vec<ListenerRow>,
    pub alerts: Vec<ListenerRow>,
    pub new_count: u64,
    pub source: Option<String>,
    pub missing: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeoInfo {
    pub ip: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub as_name: Option<String>,
    pub source: String,
    pub source_label: String,
}
