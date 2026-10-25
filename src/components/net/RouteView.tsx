import { useEffect, useState } from "react";
import { getClient } from "../../lib/client";
import { formatMs } from "../../lib/format";
import type { GeoInfo, PrivilegeHint, TraceHop } from "../../lib/types";
import { GeoOptIn } from "./GeoOptIn";
import { Notes } from "./Notes";
import { TabHeader } from "./ExplainButton";

const KIND_LABEL: Record<string, string> = {
  home_router: "router de casa",
  private: "red privada",
  isp_start: "acá arranca el ISP",
  transit: "tránsito",
  destination: "destino",
  lost: "sin respuesta",
  localhost: "localhost",
};

export function RouteView() {
  const [dest, setDest] = useState("1.1.1.1");
  const [hops, setHops] = useState<TraceHop[]>([]);
  const [status, setStatus] = useState("Escribí un destino y dale a Trazar.");
  const [tool, setTool] = useState<string | null>(null);
  const [privilege, setPrivilege] = useState<PrivilegeHint | null>(null);
  const [busy, setBusy] = useState(false);
  const [elevateError, setElevateError] = useState<string | null>(null);
  const [ispGeo, setIspGeo] = useState<GeoInfo | null>(null);
  const [geoEnabled, setGeoEnabled] = useState(false);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    (async () => {
      const client = await getClient();
      unlisten = await client.onTrace((ev) => {
        if (ev.tool) setTool(ev.tool);
        if (ev.privilege) setPrivilege(ev.privilege);
        if (ev.kind === "start") {
          setHops([]);
          setIspGeo(null);
          setStatus(ev.message ?? "Trazando…");
        } else if (ev.kind === "hop" && ev.hop) {
          setHops((prev) => {
            const next = prev.filter((h) => h.hop !== ev.hop!.hop);
            next.push(ev.hop!);
            next.sort((a, b) => a.hop - b.hop);
            return next;
          });
        } else if (ev.kind === "done") {
          setBusy(false);
          setStatus(ev.message ?? "Listo.");
        } else if (ev.kind === "cancelled") {
          setBusy(false);
          setStatus("Cancelado.");
        } else if (ev.kind === "error") {
          setBusy(false);
          setStatus(ev.message ?? "No se pudo trazar.");
          if (ev.message) setElevateError(ev.message);
        }
      });
    })().catch(() => undefined);
    return () => {
      cancelled = true;
      unlisten?.();
      void cancelled;
    };
  }, []);

  useEffect(() => {
    const isp = hops.find((h) => h.kind === "isp_start" && h.address);
    if (!isp?.address || !geoEnabled) return;
    let gone = false;
    (async () => {
      try {
        const client = await getClient();
        const g = await client.lookupIp(isp.address!, true);
        if (!gone) setIspGeo(g);
      } catch {
        /* lookup opcional */
      }
    })();
    return () => {
      gone = true;
    };
  }, [hops, geoEnabled]);

  const onElevate = async () => {
    setBusy(true);
    setElevateError(null);
    setHops([]);
    setStatus("Trazando con permisos…");
    try {
      const client = await getClient();
      await client.startTrace(dest.trim(), true);
    } catch (err) {
      setBusy(false);
      setElevateError(err instanceof Error ? err.message : String(err));
    }
  };

  const onGo = async () => {
    setBusy(true);
    setPrivilege(null);
    setElevateError(null);
    setHops([]);
    setStatus("Trazando…");
    try {
      const client = await getClient();
      await client.startTrace(dest.trim());
    } catch (err) {
      setBusy(false);
      setStatus(err instanceof Error ? err.message : String(err));
    }
  };

  const onCancel = async () => {
    const client = await getClient();
    await client.cancelTrace();
    setBusy(false);
  };

  return (
    <section className="space-y-6">
      <TabHeader
        tab="route"
        title="Ruta"
        hint="En Ubuntu usamos tracepath primero (UDP, sin root). Marcamos el router de casa, dónde aparece la primera IP pública (ISP) y los hops que no contestan. pmtu/asymm no son RTT."
      />
      {privilege ? (
        <Notes
          privilege={privilege}
          onElevate={privilege.action ? () => void onElevate() : undefined}
          elevateBusy={busy}
          elevateError={elevateError}
        />
      ) : null}
      <GeoOptIn enabled={geoEnabled} onChange={setGeoEnabled} />
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void onGo();
        }}
      >
        <input
          value={dest}
          onChange={(e) => setDest(e.target.value)}
          placeholder="1.1.1.1 o fibertel.com.ar"
          className="w-72 rounded-full border border-white/10 bg-white/5 px-4 py-2 font-ui text-sm outline-none focus:border-teal-400/50"
        />
        <button
          type="submit"
          disabled={busy || !dest.trim()}
          className="rounded-full bg-teal-400 px-4 py-2 font-ui text-sm font-semibold text-slate-950 disabled:opacity-50"
        >
          {busy ? "Trazando…" : "Trazar"}
        </button>
        {busy ? (
          <button
            type="button"
            onClick={() => void onCancel()}
            className="rounded-full bg-white/10 px-4 py-2 font-ui text-sm"
          >
            Cancelar
          </button>
        ) : null}
        <p className="font-ui text-xs text-slate-500">
          {status}
          {tool ? ` · ${tool}` : ""}
        </p>
      </form>
      {ispGeo ? (
        <p className="font-ui text-sm text-indigo-200">
          Primer hop público: {ispGeo.ip} · {ispGeo.asn ?? "ASN ?"} {ispGeo.as_name ?? ispGeo.org ?? ""}{" "}
          · {ispGeo.country ?? ""}{" "}
          <span className="text-xs text-slate-500">({ispGeo.source_label})</span>
        </p>
      ) : null}
      <div className="card overflow-auto rounded-2xl">
        <table className="w-full font-ui text-sm">
          <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-4 py-3">Hop</th>
              <th className="px-4 py-3">Dirección</th>
              <th className="px-4 py-3">RTT</th>
              <th className="px-4 py-3">Marca</th>
            </tr>
          </thead>
          <tbody>
            {hops.map((h) => (
              <tr key={h.hop} className={`border-t border-white/5 ${h.lost ? "text-rose-200" : ""}`}>
                <td className="px-4 py-3">{h.hop}</td>
                <td className="px-4 py-3 font-mono text-xs">
                  {h.lost ? "*" : (h.address ?? "—")}
                  {h.hostname ? <span className="ml-2 text-slate-400">{h.hostname}</span> : null}
                </td>
                <td className="px-4 py-3">{h.lost ? "pérdida" : formatMs(h.rtt_ms)}</td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded-full px-2 py-0.5 text-[11px] ${
                      h.kind === "home_router"
                        ? "bg-teal-400/15 text-teal-100"
                        : h.kind === "isp_start"
                          ? "bg-indigo-400/20 text-indigo-100"
                          : h.kind === "lost"
                            ? "bg-rose-400/15 text-rose-100"
                            : "bg-white/10 text-slate-300"
                    }`}
                  >
                    {KIND_LABEL[h.kind] ?? h.kind}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
