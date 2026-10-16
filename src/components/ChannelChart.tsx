import type { Band, ChannelBar } from "../lib/types";
import { bandLabel } from "../lib/format";

export function ChannelChart({ bars, band }: { bars: ChannelBar[]; band: Band }) {
  const data = bars.filter((b) => b.band === band);
  if (data.length === 0) {
    return <p className="text-sm text-slate-500">No hay redes en {bandLabel(band)}.</p>;
  }
  const max = Math.max(1, ...data.map((b) => b.count + b.overlap));
  return (
    <div data-testid={`chart-${band}`}>
      <h3 className="mb-3 text-sm uppercase tracking-[0.16em] text-slate-400">
        {bandLabel(band)}
        {band === "ghz24" ? " · solapamiento 20 MHz" : ""}
      </h3>
      <div className="flex items-end gap-1.5">
        {data.map((bar) => {
          const total = bar.count + bar.overlap;
          const h = Math.max(8, Math.round((total / max) * 120));
          const own = Math.round((bar.count / Math.max(1, total)) * h);
          return (
            <div key={`${bar.band}-${bar.channel}`} className="flex flex-1 flex-col items-center">
              <div className="flex h-[120px] w-full items-end justify-center">
                <div
                  className="flex w-full max-w-8 flex-col-reverse overflow-hidden rounded-t-md"
                  style={{ height: h }}
                  title={`Canal ${bar.channel}: ${bar.count} redes, ${bar.overlap} solapadas`}
                >
                  <div className="bg-teal-400" style={{ height: own }} />
                  {bar.overlap > 0 ? (
                    <div className="bg-amber-400/70" style={{ height: h - own }} />
                  ) : null}
                </div>
              </div>
              <span className="mt-2 font-ui text-[11px] text-slate-400">{bar.channel}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
