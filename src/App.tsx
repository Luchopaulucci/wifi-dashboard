import { useCallback, useEffect, useState } from "react";
import { DevicesView } from "./components/Devices";
import { LiveWifiView } from "./components/LiveWifi";
import { MockBanner } from "./components/MockBanner";
import { MonitorView } from "./components/Monitor";
import { NearbyView } from "./components/Nearby";
import { BootTrafficView } from "./components/net/BootTrafficView";
import { ConnectionsView } from "./components/net/ConnectionsView";
import { FirewallView } from "./components/net/FirewallView";
import { NatView } from "./components/net/NatView";
import { PortsView } from "./components/net/PortsView";
import { RouteView } from "./components/net/RouteView";
import { getClient } from "./lib/client";
import { relativeAgo } from "./lib/format";
import { SNAPSHOT_POLL_MS, useSafePoll } from "./lib/poll";
import type { Snapshot, TabId } from "./lib/types";

const WIFI_TABS: { id: TabId; label: string; hint: string }[] = [
  { id: "live", label: "Tu WiFi en vivo", hint: "SSID, señal, canal, IP" },
  { id: "nearby", label: "Redes de alrededor", hint: "Escaneo y congestión" },
  { id: "monitor", label: "Monitoreo", hint: "Latencia e historial" },
  { id: "devices", label: "Equipos en tu red", hint: "Solo tu LAN" },
];

const NET_TABS: { id: TabId; label: string; hint: string }[] = [
  { id: "connections", label: "Conexiones", hint: "Sockets y procesos" },
  { id: "nat", label: "NAT", hint: "Traducciones orig/reply" },
  { id: "firewall", label: "Firewall", hint: "Reglas en criollo" },
  { id: "route", label: "Ruta", hint: "Traceroute / tracepath" },
  { id: "boot", label: "Desde que prende", hint: "DNS y contadores" },
  { id: "ports", label: "Puertos abiertos", hint: "LISTEN y alertas" },
];

const ALL_TABS = [...WIFI_TABS, ...NET_TABS];
const NET_TAB_IDS = new Set<TabId>(NET_TABS.map((t) => t.id));

function NavButtons({
  tab,
  setTab,
  compact,
}: {
  tab: TabId;
  setTab: (id: TabId) => void;
  compact?: boolean;
}) {
  const btn = (item: { id: TabId; label: string; hint: string }) => (
    <button
      key={item.id}
      type="button"
      onClick={() => setTab(item.id)}
      className={
        compact
          ? `rounded-full px-3 py-1.5 font-ui text-sm ${
              tab === item.id ? "bg-white text-slate-950" : "bg-white/5"
            }`
          : `w-full rounded-xl px-3 py-1.5 text-left ${
              tab === item.id ? "bg-white text-slate-950" : "text-slate-300 hover:bg-white/5"
            }`
      }
    >
      {compact ? (
        item.label
      ) : (
        <>
          <span className="block text-sm">{item.label}</span>
          <span className="block font-ui text-[11px] opacity-70">{item.hint}</span>
        </>
      )}
    </button>
  );

  if (compact) {
    return <>{ALL_TABS.map(btn)}</>;
  }

  return (
    <>
      <p className="px-1 pb-1 font-ui text-[11px] uppercase tracking-[0.18em] text-slate-500">
        WiFi y LAN
      </p>
      <div className="space-y-2">{WIFI_TABS.map(btn)}</div>
      <p className="mt-4 px-1 pb-1 font-ui text-[11px] uppercase tracking-[0.18em] text-slate-500">
        Conexiones y firewall
      </p>
      <div className="space-y-2">{NET_TABS.map(btn)}</div>
    </>
  );
}

export default function App() {
  const [tab, setTab] = useState<TabId>("live");
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const refresh = useCallback(async () => {
    try {
      const client = await getClient();
      const next = await client.snapshot();
      setSnapshot(next);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useSafePoll(refresh, SNAPSHOT_POLL_MS);

  useEffect(() => {
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(clock);
  }, []);

  const onRescan = async () => {
    setBusy(true);
    try {
      const client = await getClient();
      setSnapshot(await client.rescan());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const onSweep = async () => {
    setBusy(true);
    try {
      const client = await getClient();
      setSnapshot(await client.sweepLan());
      setError(null);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      setError(`No se pudo buscar equipos: ${detail}`);
    } finally {
      setBusy(false);
    }
  };

  const view = snapshot;
  const netTab = NET_TAB_IDS.has(tab);

  return (
    <div className="grid-bg flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-72 shrink-0 flex-col overflow-hidden border-r border-white/10 bg-slate-950/70 px-5 py-6 md:flex">
        <div className="mb-5 flex items-center gap-3">
          <img src="/senal.svg" alt="" className="h-11 w-11" />
          <div>
            <p className="text-2xl font-semibold leading-none">Señal</p>
            <p className="mt-1 font-ui text-xs uppercase tracking-[0.18em] text-slate-500">
              tu red en vivo
            </p>
          </div>
        </div>
        <nav className="min-h-0 flex-1 overflow-y-auto pr-1">
          <NavButtons tab={tab} setTab={setTab} />
        </nav>
        <p className="mt-3 shrink-0 font-ui text-[10px] leading-4 text-slate-500">
          IPC local · no root · pestañas nuevas solo lectura
        </p>
      </aside>
      <main className="min-w-0 flex-1 px-5 py-6 md:px-10">
        <div className="mb-4 flex flex-wrap gap-2 md:hidden">
          <NavButtons tab={tab} setTab={setTab} compact />
        </div>
        {view?.mock && !netTab ? <MockBanner reason={view.mock_reason} /> : null}
        {view && !netTab ? (
          <p className="mb-6 font-ui text-xs text-slate-500">
            Actualizado {relativeAgo(view.collected_at_ms, now)}
          </p>
        ) : null}
        {error && tab !== "devices" ? (
          <p className="mb-4 rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm text-rose-100">
            {error}
          </p>
        ) : null}
        {!view && !netTab ? <p className="font-ui text-slate-400">Cargando tu red…</p> : null}
        {view && tab === "live" ? <LiveWifiView snapshot={view} /> : null}
        {view && tab === "nearby" ? (
          <NearbyView snapshot={view} onRescan={() => void onRescan()} busy={busy} />
        ) : null}
        {view && tab === "monitor" ? <MonitorView snapshot={view} /> : null}
        {view && tab === "devices" ? (
          <DevicesView
            snapshot={view}
            onSweep={() => void onSweep()}
            busy={busy}
            error={error}
          />
        ) : null}
        {tab === "connections" ? <ConnectionsView /> : null}
        {tab === "nat" ? <NatView /> : null}
        {tab === "firewall" ? <FirewallView /> : null}
        {tab === "route" ? <RouteView /> : null}
        {tab === "boot" ? <BootTrafficView /> : null}
        {tab === "ports" ? <PortsView /> : null}
      </main>
    </div>
  );
}
