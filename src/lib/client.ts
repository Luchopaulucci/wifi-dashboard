import type { HistoryPoint, HistoryRange, Snapshot } from "./types";
import { mockHistory, mockSnapshot } from "./mock";

export interface DashboardClient {
  snapshot(): Promise<Snapshot>;
  rescan(): Promise<Snapshot>;
  sweepLan(): Promise<Snapshot>;
  history(target: string, range: HistoryRange): Promise<HistoryPoint[]>;
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
  };
}

async function tauriClient(): Promise<DashboardClient> {
  const { invoke } = await import("@tauri-apps/api/core");
  return {
    snapshot: () => invoke<Snapshot>("get_snapshot"),
    rescan: () => invoke<Snapshot>("rescan_nearby"),
    sweepLan: () => invoke<Snapshot>("sweep_lan"),
    history: (target, range) =>
      invoke<HistoryPoint[]>("get_history", { target, range }),
  };
}

let cached: Promise<DashboardClient> | null = null;

export function getClient(): Promise<DashboardClient> {
  if (!cached) {
    cached = isTauri() ? tauriClient() : Promise.resolve(mockClient());
  }
  return cached;
}
