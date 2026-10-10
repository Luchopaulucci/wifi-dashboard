import type { HistoryPoint } from "../lib/types";

export function HistoryChart({
  points,
  label,
}: {
  points: HistoryPoint[];
  label: string;
}) {
  const w = 640;
  const h = 160;
  const pad = 12;
  const vals = points.map((p) => p.latency_ms).filter((v): v is number => v != null);
  const max = Math.max(10, ...vals);
  const min = 0;
  const coords = points
    .map((p, i) => {
      if (p.latency_ms == null) return null;
      const x = pad + (i / Math.max(1, points.length - 1)) * (w - pad * 2);
      const y = pad + (1 - (p.latency_ms - min) / (max - min)) * (h - pad * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .filter((v): v is string => v != null);

  return (
    <div className="card rounded-2xl p-4" data-testid={`history-${label}`}>
      <p className="mb-2 font-ui text-xs uppercase tracking-[0.16em] text-slate-400">{label}</p>
      {coords.length < 2 ? (
        <p className="text-sm text-slate-500">Todavía no hay suficientes muestras.</p>
      ) : (
        <svg viewBox={`0 0 ${w} ${h}`} className="h-40 w-full" role="img" aria-label={label}>
          <polyline
            fill="none"
            stroke="#3dd6c6"
            strokeWidth="2.4"
            points={coords.join(" ")}
          />
        </svg>
      )}
    </div>
  );
}
