import type { ReactNode } from "react";

interface Props {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: string;
}

export function StatCard({ label, value, hint, tone }: Props) {
  return (
    <article className="card rounded-2xl px-4 py-4">
      <p className="text-xs uppercase tracking-[0.16em] text-slate-400">{label}</p>
      <p className={`mt-2 text-2xl font-semibold ${tone ?? "text-white"}`}>{value}</p>
      {hint ? <p className="mt-1 text-sm text-slate-400">{hint}</p> : null}
    </article>
  );
}
