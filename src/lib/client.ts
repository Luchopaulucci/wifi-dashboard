import type {
  BootTrafficReport,
  ConnectionsReport,
  FirewallReport,
  GeoInfo,
  HistoryPoint,
  HistoryRange,
  ListenersReport,
  NatReport,
  PrivilegedAction,
  PrivilegedReport,
  Snapshot,
  TraceEvent,
} from "./types";
import { mockHistory, mockSnapshot } from "./mock";
import {
  mockBootTraffic,
  mockConnections,
  mockFirewall,
  mockGeo,
  mockListeners,
  mockNat,
  mockTraceEvents,
} from "./mock-net";

export interface DashboardClient {
  snapshot(): Promise<Snapshot>;
  rescan(): Promise<Snapshot>;
  sweepLan(): Promise<Snapshot>;
  history(target: string, range: HistoryRange): Promise<HistoryPoint[]>;
  connections(): Promise<ConnectionsReport>;
  nat(): Promise<NatReport>;
  firewall(): Promise<FirewallReport>;
  bootTraffic(): Promise<BootTrafficReport>;
  listeners(): Promise<ListenersReport>;
  dismissListener(key: string): Promise<void>;
  lookupIp(ip: string, allowExternal: boolean): Promise<GeoInfo>;
  startTrace(destination: string, elevated?: boolean): Promise<void>;
  cancelTrace(): Promise<void>;
  onTrace(cb: (ev: TraceEvent) => void): Promise<() => void>;
  runPrivileged(action: PrivilegedAction): Promise<PrivilegedReport>;
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
  }
}

export function isTauri(): boolean {
  return typeof window !== "undefined" && Boolean(window.__TAURI_INTERNALS__);
}

function mockClient(): DashboardClient {
  const traceListeners = new Set<(ev: TraceEvent) => void>();
  let traceTimer: number | null = null;
  return {
    async snapshot() {
      return mockSnapshot();
    },
    async rescan() {
      return mockSnapshot();
    },
    async sweepLan() {
      return mockSnapshot();
    },
    async history(target, range) {
      return mockHistory(target, range);
    },
    async connections() {
      return mockConnections();
    },
    async nat() {
      return mockNat();
    },
    async firewall() {
      return mockFirewall();
    },
    async bootTraffic() {
      return mockBootTraffic();
    },
    async listeners() {
      return mockListeners();
    },
    async dismissListener() {
      /* mock: la alerta se descarta en la UI */
    },
    async lookupIp(ip, allowExternal) {
      if (!allowExternal) {
        throw new Error(
          "Las consultas externas están apagadas (opt-in). Si las prendés, Señal manda SOLO esta IP pública por HTTPS a rdap.org para preguntar país y organización del bloque. No se manda tu nombre, tu red local ni otras IPs.",
        );
      }
      if (
        ip.startsWith("10.") ||
        ip.startsWith("192.168.") ||
        ip.startsWith("127.") ||
        ip === "::1"
      ) {
        throw new Error("IP privada o no ruteable: no se consulta un servicio externo");
      }
      return mockGeo(ip);
    },
    async startTrace(destination) {
      if (traceTimer != null) window.clearTimeout(traceTimer);
      const events = mockTraceEvents(destination);
      let i = 0;
      const tick = () => {
        const ev = events[i];
        if (!ev) return;
        traceListeners.forEach((cb) => cb(ev));
        i += 1;
        if (i < events.length) {
          traceTimer = window.setTimeout(tick, 280);
        }
      };
      tick();
    },
    async runPrivileged(action) {
      if (action === "nft_list" || action === "iptables_save" || action === "iptables_list") {
        return { kind: "firewall", data: mockFirewall(true) };
      }
      if (action === "conntrack_list") {
        return { kind: "nat", data: mockNat() };
      }
      if (action === "ss_list") {
        return { kind: "connections", data: mockConnections() };
      }
      if (action === "journal_resolved") {
        return { kind: "boot", data: mockBootTraffic() };
      }
      throw new Error("La ruta se eleva con el botón del panel, no con un comando libre.");
    },
    async cancelTrace() {
      if (traceTimer != null) window.clearTimeout(traceTimer);
      traceTimer = null;
    },
    async onTrace(cb) {
      traceListeners.add(cb);
      return () => {
        traceListeners.delete(cb);
      };
    },
  };
}

async function tauriClient(): Promise<DashboardClient> {
  const { invoke } = await import("@tauri-apps/api/core");
  const { listen } = await import("@tauri-apps/api/event");
  return {
    snapshot: () => invoke<Snapshot>("get_snapshot"),
    rescan: () => invoke<Snapshot>("rescan_nearby"),
    sweepLan: () => invoke<Snapshot>("sweep_lan"),
    history: (target, range) => invoke<HistoryPoint[]>("get_history", { target, range }),
    connections: () => invoke<ConnectionsReport>("get_connections"),
    nat: () => invoke<NatReport>("get_nat"),
    firewall: () => invoke<FirewallReport>("get_firewall"),
    bootTraffic: () => invoke<BootTrafficReport>("get_boot_traffic"),
    listeners: () => invoke<ListenersReport>("get_listeners"),
    dismissListener: (key) => invoke("dismiss_listener", { key }),
    lookupIp: (ip, allowExternal) =>
      invoke<GeoInfo>("lookup_remote_ip", { ip, allowExternal }),
    startTrace: (destination, elevated) =>
      invoke("start_trace_route", { destination, elevated: elevated ?? false }),
    runPrivileged: (action) => invoke<PrivilegedReport>("run_privileged", { action }),
    cancelTrace: () => invoke("cancel_trace_route"),
    onTrace: async (cb) => {
      const un = await listen<TraceEvent>("trace-progress", (e) => cb(e.payload));
      return () => {
        void un();
      };
    },
  };
}

let cached: Promise<DashboardClient> | null = null;

export function getClient(): Promise<DashboardClient> {
  if (!cached) {
    cached = isTauri() ? tauriClient() : Promise.resolve(mockClient());
  }
  return cached;
}
