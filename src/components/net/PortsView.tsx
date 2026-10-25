import { useCallback, useState } from "react";
import { getClient } from "../../lib/client";
import { PORTS_POLL_MS, TABLE_PAGE_SIZE, useSafePoll } from "../../lib/poll";
import type { ListenersReport } from "../../lib/types";
import { Notes } from "./Notes";
import { TabHeader } from "./ExplainButton";

export function PortsView({ pageSize = TABLE_PAGE_SIZE }: { pageSize?: number } = {}) {
  const [data, setData] = useState<ListenersReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [shown, setShown] = useState(pageSize);

  const refresh = useCallback(async () => {
    try {
      const client = await getClient();
      setData(await client.listeners());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useSafePoll(refresh, PORTS_POLL_MS, true);

  const alerts = data?.alerts ?? [];

  const onDismiss = async (key: string) => {
    setData((prev) =>
      prev
        ? {
            ...prev,
            alerts: prev.alerts.filter((a) => a.key !== key),
            new_count: Math.max(0, prev.new_count - 1),
            rows: prev.rows.map((r) => (r.key === key ? { ...r, is_new: false } : r)),
          }
        : prev,
    );
    try {
      const client = await getClient();
      await client.dismissListener(key);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      void refresh();
    }
  };

  return (
    <section className="space-y-6">
      <TabHeader
        tab="ports"
        title="Puertos abiertos"
        hint="Sockets en LISTEN (`ss -tulpn`): proceso, si es solo local o alcanzable desde la red. Avisamos contra la foto inicial de esta sesión; la alerta queda hasta que la descartes. UDP efímero se ignora."
      />
      {error ? (
        <p className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm">{error}</p>
      ) : null}
      {!data && !error ? (
        <p className="font-ui text-sm text-slate-400" data-testid="ports-loading">
          Cargando puertos…
        </p>
      ) : null}
      {data ? <Notes notes={data.notes} missing={data.missing} /> : null}
      {alerts.length ? (
        <div
          role="status"
          data-testid="new-listener-alert"
          className="rounded-2xl border border-amber-400/30 bg-amber-400/10 px-4 py-3 text-amber-50"
        >
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-amber-200">
            Apareció un listener nuevo
          </p>
          <ul className="mt-2 space-y-2 font-ui text-sm">
            {alerts.map((r) => (
              <li
                key={r.key}
                className="flex flex-wrap items-center justify-between gap-2"
              >
                <span>
                  {r.process ?? "proceso ?"} · {r.protocol} {r.local_ip}:{r.local_port} ·{" "}
                  {r.reach_label}
                </span>
                <button
                  type="button"
                  data-testid={`dismiss-listener-${r.key}`}
                  className="rounded-full bg-amber-400 px-3 py-1 text-[11px] font-semibold uppercase text-slate-950"
                  onClick={() => void onDismiss(r.key)}
                >
                  Descartar
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <div className="card overflow-auto rounded-2xl">
        <table className="w-full font-ui text-sm">
          <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-4 py-3">Proceso</th>
              <th className="px-4 py-3">Dirección</th>
              <th className="px-4 py-3">Puerto</th>
              <th className="px-4 py-3">Proto</th>
              <th className="px-4 py-3">Alcance</th>
            </tr>
          </thead>
          <tbody>
            {(data?.rows ?? []).slice(0, shown).map((r) => (
              <tr
                key={r.key || `${r.protocol}-${r.local_ip}-${r.local_port}-${r.pid ?? ""}`}
                className={`border-t border-white/5 ${r.is_new ? "bg-amber-400/10" : ""}`}
              >
                <td className="px-4 py-3">
                  {r.process ?? "—"}
                  {r.pid != null ? (
                    <span className="ml-2 font-mono text-[11px] text-slate-500">pid {r.pid}</span>
                  ) : null}
                  {r.is_new ? (
                    <span className="ml-2 rounded-full bg-amber-400 px-2 py-0.5 text-[10px] font-semibold uppercase text-slate-950">
                      nuevo
                    </span>
                  ) : null}
                </td>
                <td className="px-4 py-3 font-mono text-xs">{r.local_ip}</td>
                <td className="px-4 py-3 font-mono">{r.local_port}</td>
                <td className="px-4 py-3 uppercase">{r.protocol}</td>
                <td className="px-4 py-3 text-slate-300">{r.reach_label}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {(data?.rows.length ?? 0) > shown ? (
          <div className="border-t border-white/5 px-4 py-3">
            <button
              type="button"
              data-testid="show-more-ports"
              className="rounded-full bg-white/10 px-4 py-1.5 font-ui text-sm text-slate-100 hover:bg-white/15"
              onClick={() => setShown((n) => n + pageSize)}
            >
              Mostrar más ({(data?.rows.length ?? 0) - shown} restantes)
            </button>
          </div>
        ) : null}
      </div>
    </section>
  );
}
