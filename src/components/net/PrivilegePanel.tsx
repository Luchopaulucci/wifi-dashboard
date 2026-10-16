import type { PrivilegeHint } from "../../lib/types";

export function PrivilegePanel({ hint }: { hint: PrivilegeHint }) {
  return (
    <aside
      role="status"
      data-testid="privilege-panel"
      className="rounded-2xl border border-amber-400/30 bg-amber-400/10 px-4 py-4 text-amber-50"
    >
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-amber-200">
        Hace falta un privilegio — Señal no corre como root
      </p>
      <p className="mt-2 text-sm leading-6">{hint.why}</p>
      <p className="mt-2 font-ui text-xs text-amber-200/90">
        Binario <span className="font-mono">{hint.binary}</span> · {hint.capability}
      </p>
      <div className="mt-3 space-y-1 rounded-xl bg-black/30 p-3 font-mono text-xs text-amber-100">
        {hint.commands.map((c) => (
          <p key={c}>{c}</p>
        ))}
      </div>
      <p className="mt-3 font-ui text-xs leading-5 text-amber-200/80">{hint.polkit_note}</p>
    </aside>
  );
}
