import { useCallback, useEffect, useState } from "react";
import { getClient } from "../../lib/client";
import { formatBytes, formatCount } from "../../lib/format";
import type { FirewallReport } from "../../lib/types";
import { StatCard } from "../StatCard";
import { Notes } from "./Notes";
import { TabHeader } from "./ExplainButton";

export function FirewallView() {
  const [data, setData] = useState<FirewallReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const client = await getClient();
      setData(await client.firewall());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <section className="space-y-6">
      <TabHeader
        tab="firewall"
        title="Firewall"
        hint="Reglas de nftables (o iptables de fallback), en criollo, con contadores de paquetes/bytes. Solo lectura: no se toca ninguna regla."
      />
      {error ? (
        <p className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm">{error}</p>
      ) : null}
      {data ? (
        <>
          <Notes privilege={data.privilege} notes={data.notes} missing={data.missing} />
          <p className="font-ui text-xs text-slate-500">Fuente: {data.backend ?? "ninguna"}</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <StatCard
              label="Aceptados (suma de reglas accept)"
              value={formatCount(data.accepted_packets)}
              hint={`${formatBytes(data.accepted_bytes)} · no es tráfico total si faltan counter`}
              tone="text-teal-200"
            />
            <StatCard
              label="Descartados (drop/reject + policy drop)"
              value={formatCount(data.dropped_packets)}
              hint={formatBytes(data.dropped_bytes)}
              tone="text-rose-300"
            />
          </div>
          {data.tables.map((table) => (
            <article key={`${table.family}-${table.name}`} className="card space-y-4 rounded-2xl p-5">
              <h3 className="text-lg">
                Tabla {table.name}
                {table.family ? (
                  <span className="ml-2 font-ui text-sm text-slate-400">{table.family}</span>
                ) : null}
              </h3>
              {table.chains.map((chain) => (
                <div key={chain.name} className="overflow-auto rounded-xl border border-white/5">
                  <div className="flex flex-wrap items-baseline justify-between gap-2 bg-white/5 px-4 py-2">
                    <p className="font-medium">
                      Cadena {chain.name}
                      {chain.hook ? (
                        <span className="ml-2 font-ui text-xs text-slate-400">hook {chain.hook}</span>
                      ) : null}
                    </p>
                    <p className="font-ui text-xs text-slate-400">
                      política {chain.policy ?? "—"}
                      {chain.policy_packets != null
                        ? ` · ${formatCount(chain.policy_packets)} pkts · ${formatBytes(chain.policy_bytes)}`
                        : ""}
                    </p>
                  </div>
                  <table className="w-full font-ui text-sm">
                    <thead className="text-left text-xs uppercase tracking-wider text-slate-500">
                      <tr>
                        <th className="px-4 py-2">Regla</th>
                        <th className="px-4 py-2">En criollo</th>
                        <th className="px-4 py-2">Pkts</th>
                        <th className="px-4 py-2">Bytes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {chain.rules.map((r, i) => (
                        <tr key={`${r.text}-${i}`} className="border-t border-white/5 align-top">
                          <td className="px-4 py-3 font-mono text-xs text-slate-300">
                            <span
                              className={`mr-2 rounded-full px-2 py-0.5 text-[10px] uppercase ${
                                r.verdict === "drop" || r.verdict === "reject"
                                  ? "bg-rose-400/15 text-rose-200"
                                  : r.verdict === "accept"
                                    ? "bg-teal-400/15 text-teal-200"
                                    : "bg-amber-400/15 text-amber-100"
                              }`}
                            >
                              {r.verdict ?? "—"}
                            </span>
                            {r.text}
                          </td>
                          <td className="px-4 py-3 text-slate-200">{r.criollo}</td>
                          <td className="px-4 py-3">{r.packets == null ? "—" : formatCount(r.packets)}</td>
                          <td className="px-4 py-3">{r.bytes == null ? "—" : formatBytes(r.bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}
            </article>
          ))}
        </>
      ) : (
        <p className="font-ui text-slate-400">Leyendo ruleset…</p>
      )}
    </section>
  );
}
