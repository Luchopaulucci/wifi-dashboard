export function GeoOptIn({
  enabled,
  onChange,
}: {
  enabled: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label
      data-testid="geo-opt-in"
      className="flex max-w-xl cursor-pointer items-start gap-2 rounded-2xl border border-white/10 bg-white/5 px-3 py-2 font-ui text-xs leading-5 text-slate-300"
    >
      <input
        type="checkbox"
        className="mt-0.5"
        checked={enabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        Consultas externas HTTPS (apagadas por defecto). Si lo prendés, Señal manda{" "}
        <strong className="font-semibold text-slate-100">solo esa IP pública</strong> por HTTPS a{" "}
        <span className="font-mono">rdap.org</span> para preguntar país y organización del bloque.
        No se manda tu nombre ni IPs de la LAN.
      </span>
    </label>
  );
}
