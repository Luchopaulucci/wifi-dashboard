import type { Snapshot } from "../lib/types";

interface Props {
  snapshot: Snapshot;
  onSweep: () => void;
  busy: boolean;
}

export function DevicesView({ snapshot, onSweep, busy }: Props) {
  return (
    <section className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-3xl font-semibold">Equipos en tu red</h2>
          <p className="mt-1 max-w-2xl font-ui text-sm text-slate-400">
            Solo la LAN a la que estás conectado: tabla de vecinos (`ip neigh`) y, si pedís, un
            barrido liviano de ping de esa /24. Nunca se recorren otras redes.
          </p>
        </div>
        <button
          type="button"
          onClick={onSweep}
          disabled={busy}
          className="rounded-full bg-indigo-300 px-4 py-2 font-ui text-sm font-semibold text-slate-950 disabled:opacity-50"
        >
          {busy ? "Buscando…" : "Buscar equipos en tu red"}
        </button>
      </header>
      <div className="card overflow-hidden rounded-2xl">
        <table className="w-full font-ui text-sm">
          <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-4 py-3">IP</th>
              <th className="px-4 py-3">Nombre</th>
              <th className="px-4 py-3">MAC</th>
              <th className="px-4 py-3">Fabricante</th>
              <th className="px-4 py-3">Estado</th>
            </tr>
          </thead>
          <tbody>
            {snapshot.devices.map((d) => (
              <tr key={`${d.ip}-${d.mac ?? ""}`} className="border-t border-white/5">
                <td className="px-4 py-3 font-mono">
                  {d.ip}
                  {d.is_gateway ? (
                    <span className="ml-2 rounded-full bg-indigo-300/15 px-2 py-0.5 text-[11px] text-indigo-200">
                      gateway
                    </span>
                  ) : null}
                </td>
                <td className="px-4 py-3">{d.hostname ?? "—"}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">{d.mac ?? "—"}</td>
                <td className="px-4 py-3">{d.vendor ?? "—"}</td>
                <td className="px-4 py-3 text-slate-400">{d.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
