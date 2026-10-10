import { useEffect, useState } from "react";
import { getClient } from "../lib/client";
import type { HistoryPoint, HistoryRange, Snapshot } from "../lib/types";
import { formatMs, formatPct } from "../lib/format";
import { HistoryChart } from "./HistoryChart";
import { StatCard } from "./StatCard";

const RANGES: { id: HistoryRange; label: string }[] = [
  { id: "hour", label: "Última hora" },
  { id: "day", label: "Último día" },
  { id: "week", label: "Última semana" },
];

export function MonitorView({ snapshot }: { snapshot: Snapshot }) {
  const [range, setRange] = useState<HistoryRange>("hour");
  const [series, setSeries] = useState<Record<string, HistoryPoint[]>>({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const client = await getClient();
      const next: Record<string, HistoryPoint[]> = {};
      for (const probe of snapshot.probes) {
        next[probe.target] = await client.history(probe.target, range);
      }
      if (!cancelled) setSeries(next);
    })().catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [range, snapshot.probes]);

  return (
    <section className="space-y-6">
      <header>
        <h2 className="text-3xl font-semibold">Monitoreo</h2>
        <p className="mt-1 font-ui text-sm text-slate-400">
          Latencia, jitter y pérdida hacia tu puerta de enlace y a Internet. Se guarda en SQLite
          local (se borra lo que tenga más de una semana).
        </p>
      </header>
      <div className="grid gap-3 md:grid-cols-3">
        {snapshot.probes.map((p) => (
          <StatCard
            key={p.target}
            label={p.label}
            value={p.lost ? "pérdida" : formatMs(p.latency_ms)}
            hint={`jitter ${formatMs(p.jitter_ms)} · pérdida ${formatPct(p.loss_pct, 1)}`}
            tone={p.lost ? "text-rose-300" : "text-teal-200"}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        {RANGES.map((r) => (
          <button
            key={r.id}
            type="button"
            onClick={() => setRange(r.id)}
            className={`rounded-full px-3 py-1.5 font-ui text-sm ${
              range === r.id ? "bg-white text-slate-950" : "bg-white/5 text-slate-300"
            }`}
          >
            {r.label}
          </button>
        ))}
      </div>
      <div className="grid gap-4">
        {snapshot.probes.map((p) => (
          <HistoryChart key={p.target} label={p.label} points={series[p.target] ?? []} />
        ))}
      </div>
    </section>
  );
}
