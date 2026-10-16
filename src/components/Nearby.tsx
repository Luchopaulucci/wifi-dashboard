import type { Snapshot } from "../lib/types";
import { bandLabel, formatDbm, formatPct, hiddenSsid, signalTone } from "../lib/format";
import { ChannelChart } from "./ChannelChart";

interface Props {
  snapshot: Snapshot;
  onRescan: () => void;
  busy: boolean;
}

export function NearbyView({ snapshot, onRescan, busy }: Props) {
  return (
    <section className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-3xl font-semibold">Redes de alrededor</h2>
          <p className="mt-1 font-ui text-sm text-slate-400">
            Escaneo con nmcli. El rescan espera al menos 15 s para no saturar el adaptador.
          </p>
        </div>
        <button
          type="button"
          onClick={onRescan}
          disabled={busy}
          className="rounded-full bg-teal-400 px-4 py-2 font-ui text-sm font-semibold text-slate-950 disabled:opacity-50"
        >
          {busy ? "Escaneando…" : "Volver a escanear"}
        </button>
      </header>

      <div className="card rounded-2xl p-5">
        <h3 className="mb-4 text-lg">Congestión de canales</h3>
        <div className="grid gap-8 lg:grid-cols-3">
          <ChannelChart bars={snapshot.congestion} band="ghz24" />
          <ChannelChart bars={snapshot.congestion} band="ghz5" />
          <ChannelChart bars={snapshot.congestion} band="ghz6" />
        </div>
        <p className="mt-4 font-ui text-xs text-slate-500">
          En 2.4 GHz, el ámbar es solapamiento (un AP de 20 MHz pisa ±4 canales).
        </p>
      </div>

      <div className="card overflow-hidden rounded-2xl">
        <table className="w-full font-ui text-sm">
          <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-4 py-3">SSID</th>
              <th className="px-4 py-3">BSSID</th>
              <th className="px-4 py-3">Canal</th>
              <th className="px-4 py-3">Señal</th>
              <th className="px-4 py-3">Seguridad</th>
            </tr>
          </thead>
          <tbody>
            {snapshot.nearby.map((n) => (
              <tr key={n.bssid} className="border-t border-white/5">
                <td className="px-4 py-3">
                  {hiddenSsid(n.ssid)}
                  {n.in_use ? (
                    <span className="ml-2 rounded-full bg-teal-400/15 px-2 py-0.5 text-[11px] text-teal-200">
                      en uso
                    </span>
                  ) : null}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">{n.bssid}</td>
                <td className="px-4 py-3">
                  {n.channel ?? "—"} · {bandLabel(n.band)}
                </td>
                <td className={`px-4 py-3 ${signalTone(n.signal_pct)}`}>
                  {formatPct(n.signal_pct)} ({formatDbm(n.signal_dbm)})
                </td>
                <td className="px-4 py-3">{n.security || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
