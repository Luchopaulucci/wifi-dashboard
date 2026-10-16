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
export type TabId = "live" | "nearby" | "monitor" | "devices";
