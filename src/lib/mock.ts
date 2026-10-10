import { congestionBars } from "./congestion";
import type { HistoryPoint, HistoryRange, Snapshot } from "./types";

export const MOCK_REASON = "No hay interfaz WiFi. Mostramos datos de ejemplo.";

export function mockSnapshot(now = Date.now()): Snapshot {
  const nearby = [
    {
      in_use: true,
      ssid: "Fibertel-5G",
      bssid: "aa:bb:cc:11:22:33",
      channel: 36,
      frequency_mhz: 5180,
      band: "ghz5" as const,
      signal_dbm: -52,
      signal_pct: 96,
      security: "WPA2",
      rate: "866 Mbit/s",
    },
    {
      in_use: false,
      ssid: "Fibertel-2.4",
      bssid: "aa:bb:cc:11:22:34",
      channel: 6,
      frequency_mhz: 2437,
      band: "ghz24" as const,
      signal_dbm: -61,
      signal_pct: 78,
      security: "WPA2",
      rate: "144 Mbit/s",
    },
    {
      in_use: false,
      ssid: "Vecino-Claro",
      bssid: "11:22:33:44:55:66",
      channel: 1,
      frequency_mhz: 2412,
      band: "ghz24" as const,
      signal_dbm: -72,
      signal_pct: 56,
      security: "WPA2",
      rate: "72 Mbit/s",
    },
    {
      in_use: false,
      ssid: "Personal-5G",
      bssid: "22:33:44:55:66:77",
      channel: 44,
      frequency_mhz: 5220,
      band: "ghz5" as const,
      signal_dbm: -80,
      signal_pct: 40,
      security: "WPA3",
      rate: "433 Mbit/s",
    },
    {
      in_use: false,
      ssid: "Movistar-Fibra",
      bssid: "33:44:55:66:77:88",
      channel: 11,
      frequency_mhz: 2462,
      band: "ghz24" as const,
      signal_dbm: -68,
      signal_pct: 64,
      security: "WPA2",
      rate: "144 Mbit/s",
    },
    {
      in_use: false,
      ssid: "INVITADOS",
      bssid: "44:55:66:77:88:99",
      channel: 6,
      frequency_mhz: 2437,
      band: "ghz24" as const,
      signal_dbm: -85,
      signal_pct: 30,
      security: "Abierta",
      rate: "54 Mbit/s",
    },
    {
      in_use: false,
      ssid: "Depto-6G",
      bssid: "55:66:77:88:99:00",
      channel: 37,
      frequency_mhz: 6135,
      band: "ghz6" as const,
      signal_dbm: -70,
      signal_pct: 60,
      security: "WPA3",
      rate: "1201 Mbit/s",
    },
  ];

  return {
    mock: true,
    mock_reason: MOCK_REASON,
    collected_at_ms: now,
    live: {
      iface: "wlp2s0",
      ssid: "Fibertel-5G",
      bssid: "aa:bb:cc:11:22:33",
      signal_dbm: -52,
      signal_pct: 96,
      channel: 36,
      frequency_mhz: 5180,
      band: "ghz5",
      tx_mbps: 866.7,
      rx_mbps: 780,
      ip: "192.168.0.24",
      prefix_len: 24,
      gateway: "192.168.0.1",
      dns: ["192.168.0.1", "1.1.1.1"],
    },
    nearby,
    congestion: congestionBars(nearby),
    devices: [
      {
        ip: "192.168.0.1",
        mac: "aa:bb:cc:11:22:33",
        iface: "wlp2s0",
        state: "REACHABLE",
        hostname: "router.local",
        vendor: "TP-Link",
        is_gateway: true,
      },
      {
        ip: "192.168.0.24",
        mac: "3c:22:fb:10:20:30",
        iface: "wlp2s0",
        state: "REACHABLE",
        hostname: "idea-pad.local",
        vendor: "Intel",
        is_gateway: false,
      },
      {
        ip: "192.168.0.18",
        mac: "f8:a4:5f:aa:bb:cc",
        iface: "wlp2s0",
        state: "STALE",
        hostname: "celular-lu.local",
        vendor: "Xiaomi",
        is_gateway: false,
      },
      {
        ip: "192.168.0.40",
        mac: "a4:77:33:11:22:33",
        iface: "wlp2s0",
        state: "REACHABLE",
        hostname: "smart-tv.local",
        vendor: "Samsung",
        is_gateway: false,
      },
      {
        ip: "192.168.0.55",
        mac: "00:1a:11:99:88:77",
        iface: "wlp2s0",
        state: "DELAY",
        hostname: "nest-mini.local",
        vendor: "Google",
        is_gateway: false,
      },
    ],
    probes: [
      {
        target: "192.168.0.1",
        label: "Puerta de enlace",
        latency_ms: 3.8,
        lost: false,
        jitter_ms: 0.4,
        loss_pct: 0,
      },
      {
        target: "1.1.1.1",
        label: "Internet (1.1.1.1)",
        latency_ms: 17.4,
        lost: false,
        jitter_ms: 2.1,
        loss_pct: 1.2,
      },
      {
        target: "8.8.8.8",
        label: "Internet (8.8.8.8)",
        latency_ms: 21.1,
        lost: false,
        jitter_ms: 2.8,
        loss_pct: 2,
      },
    ],
    sources: ["mock"],
  };
}

export function mockHistory(target: string, range: HistoryRange, now = Date.now()): HistoryPoint[] {
  const windows = { hour: 3_600_000, day: 86_400_000, week: 604_800_000 };
  const buckets = { hour: 15_000, day: 300_000, week: 3_600_000 };
  const base = target === "192.168.0.1" ? 4 : target === "1.1.1.1" ? 18 : 22;
  const amp = target === "192.168.0.1" ? 1.2 : 6;
  const points: HistoryPoint[] = [];
  const span = windows[range];
  const step = buckets[range];
  for (let ts = now - span, i = 0; ts <= now; ts += step, i += 1) {
    const wave = Math.sin(i / 18);
    points.push({
      ts_ms: ts,
      latency_ms: Math.max(1, base + amp * wave),
      loss_pct: i % 37 === 0 ? 4 : 0,
      jitter_ms: amp / 4,
    });
  }
  return points;
}
