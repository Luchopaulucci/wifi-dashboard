interface Props {
  reason: string | null;
}

export function MockBanner({ reason }: Props) {
  return (
    <div
      role="status"
      data-testid="mock-banner"
      className="mb-5 flex items-start gap-3 rounded-2xl border border-amber-400/30 bg-amber-400/10 px-4 py-3 text-amber-100"
    >
      <span className="mt-0.5 inline-flex rounded-full bg-amber-400 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-slate-950">
        Modo simulado
      </span>
      <p className="text-sm leading-6">
        {reason ?? "No hay interfaz WiFi. Mostramos datos de ejemplo."} En la IdeaPad con
        NetworkManager vas a ver tu red real.
      </p>
    </div>
  );
}
