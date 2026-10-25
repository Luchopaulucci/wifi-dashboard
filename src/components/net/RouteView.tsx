import { useEffect, useRef, useState } from "react";
import { getClient } from "../../lib/client";
import { formatMs } from "../../lib/format";
import {
  applyTraceEvent,
  beginRouteSession,
  emptyRouteTraceState,
  type RouteTraceState,
} from "../../lib/route-trace";
import type { GeoInfo } from "../../lib/types";
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
  const [trace, setTrace] = useState<RouteTraceState>(() => emptyRouteTraceState());
  const traceRef = useRef(trace);
  traceRef.current = trace;
  const [ispGeo, setIspGeo] = useState<GeoInfo | null>(null);
  const [geoEnabled, setGeoEnabled] = useState(false);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let gone = false;
    (async () => {
      const client = await getClient();
      unlisten = await client.onTrace((ev) => {
        const next = applyTraceEvent(traceRef.current, ev);
        traceRef.current = next;
        setTrace(next);
        if (ev.kind === "start" && next.sessionId === ev.session_id) {
          setIspGeo(null);
        }
      });
    })().catch(() => undefined);
    return () => {
      gone = true;
      unlisten?.();
      void gone;
    };
  }, []);

  useEffect(() => {
    const isp = trace.hops.find((h) => h.kind === "isp_start" && h.address);
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
  }, [trace.hops, geoEnabled]);

  const onElevate = async () => {
    const next = beginRouteSession(traceRef.current, "Trazando con permisos…");
    traceRef.current = next;
    setTrace(next);
    try {
      const client = await getClient();
      await client.startTrace(dest.trim(), true);
    } catch (err) {
      setTrace((prev) => ({
        ...prev,
        busy: false,
        elevateError: err instanceof Error ? err.message : String(err),
      }));
    }
  };

  const onGo = async () => {
    const next = beginRouteSession(
      { ...traceRef.current, privilege: null },
      "Trazando…",
    );
    traceRef.current = next;
    setTrace(next);
    try {
      const client = await getClient();
      await client.startTrace(dest.trim());
    } catch (err) {
      setTrace((prev) => ({
        ...prev,
        busy: false,
        status: err instanceof Error ? err.message : String(err),
      }));
    }
  };

  const onCancel = async () => {
    const client = await getClient();
    await client.cancelTrace();
  };

  return (
    <section className="space-y-6">
      <TabHeader
        tab="route"
        title="Ruta"
        hint="En Ubuntu usamos tracepath primero (UDP, sin root). Marcamos el router de casa, dónde aparece la primera IP pública (ISP) y los hops que no contestan. pmtu/asymm no son RTT."
      />
      {trace.privilege ? (
        <Notes
          privilege={trace.privilege}
          onElevate={trace.privilege.action ? () => void onElevate() : undefined}
          elevateBusy={trace.busy}
          elevateError={trace.elevateError}
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
          disabled={trace.busy || !dest.trim()}
          className="rounded-full bg-teal-400 px-4 py-2 font-ui text-sm font-semibold text-slate-950 disabled:opacity-50"
        >
          {trace.busy ? "Trazando…" : "Trazar"}
        </button>
        {trace.busy ? (
          <button
            type="button"
            onClick={() => void onCancel()}
            className="rounded-full bg-white/10 px-4 py-2 font-ui text-sm"
          >
            Cancelar
          </button>
        ) : null}
        {trace.busy ? (
          <p className="basis-full font-ui text-xs text-amber-200/80">
            Cancelar solo deja de esperar. Un traceroute elevado corre como root: Señal no puede
            mandarle una señal y puede seguir hasta que termine.
          </p>
        ) : null}
        <p className="font-ui text-xs text-slate-500">
          {trace.status}
          {trace.tool ? ` · ${trace.tool}` : ""}
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
            {trace.hops.map((h) => (
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
