import type { Snapshot } from "../lib/types";
import { bandLabel, formatDbm, formatMbps, formatPct, signalTone } from "../lib/format";
import { StatCard } from "./StatCard";

export function LiveWifiView({ snapshot }: { snapshot: Snapshot }) {
  const live = snapshot.live;
  if (!live) {
    return (
      <p className="text-slate-400">
        No hay datos de la WiFi conectada. ¿Está NetworkManager o el adaptador arriba?
      </p>
    );
  }

  return (
    <section className="space-y-5">
      <header>
        <p className="text-sm text-teal-300">Conectado a</p>
        <h2 className="mt-1 text-4xl font-semibold tracking-tight">{live.ssid ?? "(sin SSID)"}</h2>
        <p className="mt-2 font-ui text-sm text-slate-400">
          Interfaz {live.iface || "—"} · fuentes {snapshot.sources.join(", ") || "—"}
        </p>
      </header>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Señal"
          value={formatPct(live.signal_pct)}
          hint={formatDbm(live.signal_dbm)}
          tone={signalTone(live.signal_pct)}
        />
        <StatCard
          label="Canal / banda"
          value={live.channel ?? "—"}
          hint={`${bandLabel(live.band)} · ${live.frequency_mhz ?? "—"} MHz`}
        />
        <StatCard
          label="Velocidad del enlace"
          value={formatMbps(live.tx_mbps)}
          hint={`RX ${formatMbps(live.rx_mbps)}`}
        />
        <StatCard
          label="Dirección"
          value={live.ip ?? "—"}
          hint={live.prefix_len ? `/${live.prefix_len}` : undefined}
        />
      </div>
      <div className="card rounded-2xl p-5 font-ui text-sm">
        <dl className="grid gap-4 sm:grid-cols-2">
          <div>
            <dt className="text-slate-400">BSSID</dt>
            <dd className="mt-1 font-mono text-slate-100">{live.bssid ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-slate-400">Puerta de enlace</dt>
            <dd className="mt-1 font-mono text-slate-100">{live.gateway ?? "—"}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-slate-400">DNS</dt>
            <dd className="mt-1 font-mono text-slate-100">
              {live.dns.length ? live.dns.join(" · ") : "—"}
            </dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
