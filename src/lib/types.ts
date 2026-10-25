export type Band = "ghz24" | "ghz5" | "ghz6";

export interface LiveWifi {
  iface: string;
  ssid: string | null;
  bssid: string | null;
  signal_dbm: number | null;
  signal_pct: number | null;
  channel: number | null;
  frequency_mhz: number | null;
  band: Band | null;
  tx_mbps: number | null;
  rx_mbps: number | null;
  ip: string | null;
  prefix_len: number | null;
  gateway: string | null;
  dns: string[];
}

export interface NearbyNetwork {
  in_use: boolean;
  ssid: string;
  bssid: string;
  channel: number | null;
  frequency_mhz: number | null;
  band: Band | null;
  signal_dbm: number | null;
  signal_pct: number | null;
  security: string;
  rate: string | null;
}

export interface LanDevice {
  ip: string;
  mac: string | null;
  iface: string | null;
  state: string;
  hostname: string | null;
  vendor: string | null;
  is_gateway: boolean;
}

export interface ProbeInstant {
  target: string;
  label: string;
  latency_ms: number | null;
  lost: boolean;
  jitter_ms: number | null;
  loss_pct: number | null;
}

export interface HistoryPoint {
  ts_ms: number;
  latency_ms: number | null;
  loss_pct: number;
  jitter_ms: number | null;
}

export interface ChannelBar {
  channel: number;
  band: Band;
  count: number;
  overlap: number;
  strongest_pct: number | null;
}

export interface Snapshot {
  mock: boolean;
  mock_reason: string | null;
  collected_at_ms: number;
  live: LiveWifi | null;
  nearby: NearbyNetwork[];
  devices: LanDevice[];
  probes: ProbeInstant[];
  congestion: ChannelBar[];
  sources: string[];
}

export type HistoryRange = "hour" | "day" | "week";
export type TabId =
  | "live"
  | "nearby"
  | "monitor"
  | "devices"
  | "connections"
  | "nat"
  | "firewall"
  | "route"
  | "boot"
  | "ports";

export type PrivilegedAction =
  | "nft_list"
  | "conntrack_list"
  | "iptables_save"
  | "iptables_list"
  | "journal_resolved"
  | "ss_list"
  | "traceroute";

export interface PrivilegeHint {
  binary: string;
  capability: string;
  why: string;
  action: PrivilegedAction | null;
  commands?: string[];
  polkit_note: string;
}

export type PrivilegedReport =
  | { kind: "firewall"; data: FirewallReport }
  | { kind: "nat"; data: NatReport }
  | { kind: "connections"; data: ConnectionsReport }
  | { kind: "boot"; data: BootTrafficReport };

export interface ConnectionRow {
  protocol: string;
  local_ip: string;
  local_port: string;
  remote_ip: string;
  remote_port: string;
  state: string;
  process: string | null;
  pid: number | null;
  domain: string | null;
  domain_source: string | null;
}

export interface ConnectionsReport {
  collected_at_ms: number;
  rows: ConnectionRow[];
  sources: string[];
  missing: string[];
  privilege: PrivilegeHint | null;
  notes: string[];
}

export interface NatTranslation {
  protocol: string;
  internal_ip: string;
  internal_port: string;
  translated_ip: string;
  translated_port: string;
  dest_ip: string;
  dest_port: string;
  state: string | null;
  timeout_secs: number | null;
  nat_kind: string;
  assured: boolean;
}

export interface NatReport {
  collected_at_ms: number;
  translations: NatTranslation[];
  active_count: number;
  snat_count: number;
  dnat_count: number;
  source: string | null;
  missing: string[];
  privilege: PrivilegeHint | null;
  notes: string[];
}

export interface FirewallRule {
  table: string;
  family: string | null;
  chain: string;
  handle: string | null;
  text: string;
  criollo: string;
  packets: number | null;
  bytes: number | null;
  verdict: string | null;
}

export interface FirewallChain {
  name: string;
  hook: string | null;
  policy: string | null;
  policy_packets: number | null;
  policy_bytes: number | null;
  rules: FirewallRule[];
}

export interface FirewallTable {
  name: string;
  family: string | null;
  chains: FirewallChain[];
}

export interface FirewallReport {
  collected_at_ms: number;
  backend: string | null;
  tables: FirewallTable[];
  accepted_packets: number;
  accepted_bytes: number;
  dropped_packets: number;
  dropped_bytes: number;
  missing: string[];
  privilege: PrivilegeHint | null;
  notes: string[];
}

export type TraceHopKind =
  | "home_router"
  | "private"
  | "isp_start"
  | "transit"
  | "destination"
  | "lost"
  | "localhost";

export interface TraceHop {
  hop: number;
  address: string | null;
  hostname: string | null;
  rtt_ms: number | null;
  lost: boolean;
  kind: TraceHopKind;
}

export interface TraceEvent {
  session_id: string;
  kind: string;
  hop: TraceHop | null;
  message: string | null;
  tool: string | null;
  privilege: PrivilegeHint | null;
}

export interface TrafficCounter {
  id: string;
  label: string;
  value: number;
  meaning: string;
  source: string;
}

export interface TalkerTag {
  label: string;
  kind: string;
}

export interface DnsDomainRow {
  domain: string;
  count: number;
  source: string;
  talker: TalkerTag | null;
}

export interface DnsProgramRow {
  process: string;
  pid: number | null;
  dns_server: string | null;
  proto: string;
  note: string;
}

export interface DnsMonitorStatus {
  running: boolean;
  error: string | null;
  needs_privilege: boolean;
  explanation: string;
}

export interface BootTrafficReport {
  collected_at_ms: number;
  counters: TrafficCounter[];
  domains: DnsDomainRow[];
  programs: DnsProgramRow[];
  missing: string[];
  privilege: PrivilegeHint | null;
  limitations: string[];
  dns_monitor: DnsMonitorStatus;
}

export type Reachability = "local_only" | "network_all" | "lan_address";

export interface ListenerRow {
  protocol: string;
  local_ip: string;
  local_port: string;
  process: string | null;
  pid: number | null;
  reach: Reachability;
  reach_label: string;
  key: string;
  is_new: boolean;
}

export interface ListenersReport {
  collected_at_ms: number;
  rows: ListenerRow[];
  alerts: ListenerRow[];
  new_count: number;
  source: string | null;
  missing: string[];
  notes: string[];
}

export interface GeoInfo {
  ip: string;
  country: string | null;
  country_code: string | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  as_name: string | null;
  source: string;
  source_label: string;
}
