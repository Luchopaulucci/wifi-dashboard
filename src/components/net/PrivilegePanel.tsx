import type { PrivilegeHint } from "../../lib/types";

export function PrivilegePanel({
  hint,
  onElevate,
  busy = false,
  error = null,
}: {
  hint: PrivilegeHint;
  onElevate?: () => void;
  busy?: boolean;
  error?: string | null;
}) {
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
      {error ? (
        <p role="alert" data-testid="privilege-error" className="mt-3 text-sm text-rose-200">
          {error}
        </p>
      ) : null}
      {hint.action && onElevate ? (
        <button
          type="button"
          data-testid="privilege-elevate"
          disabled={busy}
          onClick={onElevate}
          className="mt-3 rounded-full bg-amber-300 px-4 py-2 font-ui text-sm font-semibold text-slate-950 disabled:opacity-50"
        >
          {busy ? "Esperando contraseña…" : "Ver con permisos de administrador"}
        </button>
      ) : null}
      {hint.commands && hint.commands.length > 0 ? (
        <ul className="mt-3 space-y-1 font-mono text-xs text-amber-100/80">
          {hint.commands.map((cmd) => (
            <li key={cmd}>{cmd}</li>
          ))}
        </ul>
      ) : null}
      <p className="mt-3 font-ui text-xs leading-5 text-amber-200/80">{hint.polkit_note}</p>
    </aside>
  );
}
