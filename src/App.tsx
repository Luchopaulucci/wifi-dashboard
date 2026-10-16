import { useCallback, useEffect, useState } from "react";
import { DevicesView } from "./components/Devices";
import { LiveWifiView } from "./components/LiveWifi";
import { MockBanner } from "./components/MockBanner";
import { MonitorView } from "./components/Monitor";
import { NearbyView } from "./components/Nearby";
import { getClient } from "./lib/client";
import { relativeAgo } from "./lib/format";
import type { Snapshot, TabId } from "./lib/types";

const TABS: { id: TabId; label: string; hint: string }[] = [
  { id: "live", label: "Tu WiFi en vivo", hint: "SSID, señal, canal, IP" },
  { id: "nearby", label: "Redes de alrededor", hint: "Escaneo y congestión" },
  { id: "monitor", label: "Monitoreo", hint: "Latencia e historial" },
  { id: "devices", label: "Equipos en tu red", hint: "Solo tu LAN" },
];

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

  useEffect(() => {
    void refresh();
    const poll = window.setInterval(() => void refresh(), 4000);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      window.clearInterval(poll);
      window.clearInterval(clock);
    };
  }, [refresh]);

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
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const view = snapshot;

  return (
    <div className="grid-bg flex min-h-screen">
      <aside className="hidden w-72 shrink-0 flex-col border-r border-white/10 bg-slate-950/70 px-5 py-6 md:flex">
        <div className="mb-10 flex items-center gap-3">
          <img src="/senal.svg" alt="" className="h-11 w-11" />
          <div>
            <p className="text-2xl font-semibold leading-none">Señal</p>
            <p className="mt-1 font-ui text-xs uppercase tracking-[0.18em] text-slate-500">
              tu red en vivo
            </p>
          </div>
        </div>
        <nav className="space-y-2">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`w-full rounded-2xl px-3 py-3 text-left ${
                tab === item.id ? "bg-white text-slate-950" : "text-slate-300 hover:bg-white/5"
              }`}
            >
              <span className="block text-base">{item.label}</span>
              <span className="mt-0.5 block font-ui text-xs opacity-70">{item.hint}</span>
            </button>
          ))}
        </nav>
        <p className="mt-auto font-ui text-xs leading-5 text-slate-500">
          Sin servidor de red. IPC solo en 127.0.0.1. No corre como root.
        </p>
      </aside>
      <main className="min-w-0 flex-1 px-5 py-6 md:px-10">
        <div className="mb-4 flex flex-wrap gap-2 md:hidden">
          {TABS.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`rounded-full px-3 py-1.5 font-ui text-sm ${
                tab === item.id ? "bg-white text-slate-950" : "bg-white/5"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
        {view?.mock ? <MockBanner reason={view.mock_reason} /> : null}
        {view ? (
          <p className="mb-6 font-ui text-xs text-slate-500">
            Actualizado {relativeAgo(view.collected_at_ms, now)}
          </p>
        ) : null}
        {error ? (
          <p className="mb-4 rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm text-rose-100">
            {error}
          </p>
        ) : null}
        {!view ? <p className="font-ui text-slate-400">Cargando tu red…</p> : null}
        {view && tab === "live" ? <LiveWifiView snapshot={view} /> : null}
        {view && tab === "nearby" ? (
          <NearbyView snapshot={view} onRescan={() => void onRescan()} busy={busy} />
        ) : null}
        {view && tab === "monitor" ? <MonitorView snapshot={view} /> : null}
        {view && tab === "devices" ? (
          <DevicesView snapshot={view} onSweep={() => void onSweep()} busy={busy} />
        ) : null}
      </main>
    </div>
  );
}
