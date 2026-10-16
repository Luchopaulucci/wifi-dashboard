import type { PrivilegeHint } from "../../lib/types";
import { PrivilegePanel } from "./PrivilegePanel";

export function Notes({
  privilege,
  notes,
  missing,
}: {
  privilege?: PrivilegeHint | null;
  notes?: string[];
  missing?: string[];
}) {
  return (
    <div className="space-y-3">
      {privilege ? <PrivilegePanel hint={privilege} /> : null}
      {missing && missing.length ? (
        <p className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 font-ui text-sm text-slate-300">
          Binarios o archivos que no están: {missing.join(", ")}. La pestaña sigue en solo lectura y
          no rompe el resto de Señal.
        </p>
      ) : null}
      {notes?.map((n) => (
        <p
          key={n}
          className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 font-ui text-sm text-slate-300"
        >
          {n}
        </p>
      ))}
    </div>
  );
}
