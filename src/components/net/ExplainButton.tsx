import { useState, type ReactNode } from "react";
import { EXPLAIN } from "../../lib/explain";
import type { TabId } from "../../lib/types";

export function ExplainButton({ tab }: { tab: TabId }) {
  const [open, setOpen] = useState(false);
  const note = EXPLAIN[tab];
  return (
    <>
      <button
        type="button"
        data-testid="explain-button"
        onClick={() => setOpen(true)}
        className="rounded-full border border-white/15 px-3 py-1.5 font-ui text-sm text-slate-200 hover:bg-white/5"
      >
        Explicame esto
      </button>
      {open ? (
        <div
          className="fixed inset-0 z-50 flex items-end justify-center bg-black/60 p-4 md:items-center"
          role="dialog"
          aria-modal="true"
          aria-labelledby="explain-title"
          data-testid="explain-dialog"
        >
          <div className="card max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-3xl p-6">
            <div className="flex items-start justify-between gap-4">
              <h3 id="explain-title" className="text-2xl font-semibold">
                {note.title}
              </h3>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="rounded-full bg-white/10 px-3 py-1 font-ui text-sm"
              >
                Cerrar
              </button>
            </div>
            <div className="mt-4 space-y-3 font-ui text-sm leading-6 text-slate-300">
              {note.body.map((p) => (
                <p key={p}>{p}</p>
              ))}
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}

export function TabHeader({
  title,
  hint,
  tab,
  extra,
}: {
  title: string;
  hint: string;
  tab: TabId;
  extra?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 className="text-3xl font-semibold">{title}</h2>
        <p className="mt-1 max-w-2xl font-ui text-sm text-slate-400">{hint}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {extra}
        <ExplainButton tab={tab} />
      </div>
    </header>
  );
}
