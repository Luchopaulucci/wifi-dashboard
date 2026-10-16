import { useCallback, useEffect, useState } from "react";
import { getClient } from "../../lib/client";
import { formatCount, formatTimeout } from "../../lib/format";
import type { NatReport } from "../../lib/types";
import { StatCard } from "../StatCard";
import { Notes } from "./Notes";
import { TabHeader } from "./ExplainButton";

export function NatView() {
  const [data, setData] = useState<NatReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const client = await getClient();
      setData(await client.nat());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 4000);
    return () => window.clearInterval(id);
  }, [refresh]);

  return (
    <section className="space-y-6">
      <TabHeader
        tab="nat"
        title="NAT"
        hint="Traducciones de conntrack: IP interna, con qué IP sale, y el destino. El timeout es cuánto le queda de vida a la entrada, no cuánto lleva abierta."
      />
      {error ? (
        <p className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm">{error}</p>
      ) : null}
      {data ? (
        <>
          <Notes privilege={data.privilege} notes={data.notes} missing={data.missing} />
          <div className="grid gap-3 sm:grid-cols-3">
            <StatCard label="Traducciones activas" value={formatCount(data.active_count)} hint={data.source ?? "sin fuente"} />
            <StatCard label="SNAT" value={formatCount(data.snat_count)} hint="reescribe el origen (cómo te ven afuera)" />
            <StatCard label="DNAT" value={formatCount(data.dnat_count)} hint="reescribe el destino (port-forward)" />
          </div>
          <div className="card overflow-auto rounded-2xl">
            <table className="w-full font-ui text-sm">
              <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-4 py-3">Interna</th>
                  <th className="px-4 py-3">Sale como</th>
                  <th className="px-4 py-3">Destino</th>
                  <th className="px-4 py-3">Tipo</th>
                  <th className="px-4 py-3">Timeout</th>
                  <th className="px-4 py-3">Estado</th>
                </tr>
              </thead>
              <tbody>
                {data.translations.map((t, i) => (
                  <tr
                    key={`${t.protocol}-${t.internal_ip}:${t.internal_port}-${t.dest_ip}:${t.dest_port}-${i}`}
                    className="border-t border-white/5"
                  >
                    <td className="px-4 py-3 font-mono text-xs">
                      {t.internal_ip}:{t.internal_port}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {t.translated_ip}:{t.translated_port}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {t.dest_ip}:{t.dest_port}
                      <span className="ml-2 uppercase text-slate-500">{t.protocol}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[11px] ${
                          t.nat_kind === "ninguno"
                            ? "bg-white/10 text-slate-300"
                            : "bg-amber-400/15 text-amber-100"
                        }`}
                      >
                        {t.nat_kind}
                      </span>
                    </td>
                    <td className="px-4 py-3">{formatTimeout(t.timeout_secs)}</td>
                    <td className="px-4 py-3 text-slate-400">
                      {t.state ?? "—"}
                      {t.assured ? " · assured" : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data.translations.length === 0 && !data.privilege ? (
              <p className="px-4 py-6 font-ui text-sm text-slate-400">
                No hay entradas de conntrack visibles. En una notebook sin compartir Internet es
                normal no ver SNAT propio: el NAT lo hace el router.
              </p>
            ) : null}
          </div>
        </>
      ) : (
        <p className="font-ui text-slate-400">Leyendo conntrack…</p>
      )}
    </section>
  );
}
