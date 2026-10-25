import { useCallback, useEffect, useState } from "react";
import { getClient } from "../../lib/client";
import { formatCount } from "../../lib/format";
import type { BootTrafficReport } from "../../lib/types";
import { Notes } from "./Notes";
import { TabHeader } from "./ExplainButton";

export function BootTrafficView() {
  const [data, setData] = useState<BootTrafficReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const client = await getClient();
      setData(await client.bootTraffic());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(id);
  }, [refresh]);

  return (
    <section className="space-y-6">
      <TabHeader
        tab="boot"
        title="Desde que prende la PC"
        hint="Contadores del kernel desde el arranque, dominios del journal/caché (sin basura .arpa) y programas que hablaron con DNS en esta sesión. Si algo pide root, se dice acá."
      />
      {error ? (
        <p className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm">{error}</p>
      ) : null}
      {data ? (
        <>
          <Notes privilege={data.privilege} notes={data.limitations} missing={data.missing} />
          <aside
            role="status"
            data-testid="dns-monitor-status"
            className={`rounded-2xl border px-4 py-3 font-ui text-sm leading-6 ${
              data.dns_monitor.running
                ? "border-teal-400/30 bg-teal-400/10 text-teal-50"
                : "border-amber-400/30 bg-amber-400/10 text-amber-50"
            }`}
          >
            <p className="text-xs font-semibold uppercase tracking-[0.16em]">
              Monitor DNS {data.dns_monitor.running ? "en vivo" : "no disponible"}
            </p>
            <p className="mt-2">{data.dns_monitor.explanation}</p>
            {data.dns_monitor.error ? (
              <p className="mt-2 font-mono text-xs">{data.dns_monitor.error}</p>
            ) : null}
            {data.dns_monitor.needs_privilege ? (
              <p className="mt-2 text-xs">
                Esto pide privilegios que Señal no va a tomar. Sin root no hay consultas DNS en vivo
                por `resolvectl monitor`.
              </p>
            ) : null}
          </aside>
          <div className="grid gap-3 md:grid-cols-2">
            {data.counters.map((c) => (
              <article key={c.id} className="card rounded-2xl px-4 py-4">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-400">{c.label}</p>
                <p className="mt-2 text-2xl font-semibold">{formatCount(c.value)}</p>
                <p className="mt-2 font-ui text-sm leading-6 text-slate-300">{c.meaning}</p>
                <p className="mt-2 font-mono text-[11px] text-slate-500">{c.source}</p>
              </article>
            ))}
          </div>
          <article className="card overflow-auto rounded-2xl">
            <h3 className="px-4 pt-4 text-lg">Dominios observados</h3>
            <table className="mt-2 w-full font-ui text-sm">
              <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-4 py-3">Dominio</th>
                  <th className="px-4 py-3">Veces</th>
                  <th className="px-4 py-3">Hablador</th>
                  <th className="px-4 py-3">Fuente</th>
                </tr>
              </thead>
              <tbody>
                {data.domains.map((d) => (
                  <tr key={`${d.domain}-${d.source}`} className="border-t border-white/5">
                    <td className="px-4 py-3 font-mono text-xs">{d.domain}</td>
                    <td className="px-4 py-3">{formatCount(d.count)}</td>
                    <td className="px-4 py-3">
                      {d.talker ? (
                        <span className="rounded-full bg-amber-400/15 px-2 py-0.5 text-[11px] text-amber-100">
                          {d.talker.label} · {d.talker.kind}
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{d.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {data.domains.length === 0 ? (
              <p className="px-4 py-6 font-ui text-sm text-slate-400">
                Todavía no hay dominios. Si resolved no loguea queries y el monitor acaba de arrancar,
                es esperable.
              </p>
            ) : null}
          </article>
          <article className="card overflow-auto rounded-2xl">
            <h3 className="px-4 pt-4 text-lg">Programas que hablaron con DNS en esta sesión</h3>
            <table className="mt-2 w-full font-ui text-sm">
              <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-4 py-3">Proceso</th>
                  <th className="px-4 py-3">Servidor</th>
                  <th className="px-4 py-3">Nota</th>
                </tr>
              </thead>
              <tbody>
                {data.programs.map((p, i) => (
                  <tr key={`${p.process}-${p.pid}-${i}`} className="border-t border-white/5">
                    <td className="px-4 py-3">
                      {p.process}
                      {p.pid != null ? (
                        <span className="ml-2 font-mono text-[11px] text-slate-500">pid {p.pid}</span>
                      ) : null}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {p.dns_server ?? "—"} · {p.proto}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{p.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </article>
        </>
      ) : (
        <p className="font-ui text-slate-400">Leyendo contadores…</p>
      )}
    </section>
  );
}
