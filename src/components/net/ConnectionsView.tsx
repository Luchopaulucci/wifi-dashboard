import { useCallback, useEffect, useMemo, useState } from "react";
import { getClient } from "../../lib/client";
import type { ConnectionRow, ConnectionsReport, GeoInfo } from "../../lib/types";
import { Notes } from "./Notes";
import { TabHeader } from "./ExplainButton";

function isProbablyPrivate(ip: string): boolean {
  if (ip === "::1" || ip.startsWith("fe80:") || ip.startsWith("fd") || ip.startsWith("fc")) {
    return true;
  }
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return (
    a === 10 ||
    a === 127 ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

export function ConnectionsView() {
  const [data, setData] = useState<ConnectionsReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [auto, setAuto] = useState(true);
  const [selected, setSelected] = useState<ConnectionRow | null>(null);
  const [geo, setGeo] = useState<GeoInfo | null>(null);
  const [geoError, setGeoError] = useState<string | null>(null);
  const [geoBusy, setGeoBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const client = await getClient();
      setData(await client.connections());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!auto) return;
    const id = window.setInterval(() => void refresh(), 3000);
    return () => window.clearInterval(id);
  }, [auto, refresh]);

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q || !data) return data?.rows ?? [];
    return data.rows.filter((r) => (r.process ?? "").toLowerCase().includes(q));
  }, [data, filter]);

  const onSelect = async (row: ConnectionRow) => {
    setSelected(row);
    setGeo(null);
    setGeoError(null);
    if (isProbablyPrivate(row.remote_ip) || row.remote_ip === "*" || row.remote_ip === "0.0.0.0") {
      setGeoError(
        "IP privada o local: no hay país/ASN. Es tu LAN o loopback. No consultamos un servicio externo.",
      );
      return;
    }
    setGeoBusy(true);
    try {
      const client = await getClient();
      setGeo(await client.lookupIp(row.remote_ip));
    } catch (err) {
      setGeoError(err instanceof Error ? err.message : String(err));
    } finally {
      setGeoBusy(false);
    }
  };

  return (
    <section className="space-y-6">
      <TabHeader
        tab="connections"
        title="Conexiones activas"
        hint="Sockets de `ss -tunap`: proceso, IP y dominio destino, puerto, protocolo y estado. Solo lectura. El dominio sale de PTR o de DNS observado; el país/ASN es una consulta externa al hacer clic."
        extra={
          <label className="flex items-center gap-2 font-ui text-sm text-slate-300">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            Auto-refresh
          </label>
        }
      />
      {error ? (
        <p className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm">{error}</p>
      ) : null}
      {data ? (
        <Notes privilege={data.privilege} notes={data.notes} missing={data.missing} />
      ) : null}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filtrar por programa…"
          className="w-64 rounded-full border border-white/10 bg-white/5 px-4 py-2 font-ui text-sm outline-none focus:border-teal-400/50"
        />
        <p className="font-ui text-xs text-slate-500">
          {rows.length} conexiones
          {data?.sources.length ? ` · ${data.sources.join(", ")}` : ""}
        </p>
      </div>
      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        <div className="card overflow-auto rounded-2xl">
          <table className="w-full font-ui text-sm">
            <thead className="bg-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-4 py-3">Proceso</th>
                <th className="px-4 py-3">Destino</th>
                <th className="px-4 py-3">Puerto</th>
                <th className="px-4 py-3">Proto</th>
                <th className="px-4 py-3">Estado</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => {
                const key = `${r.protocol}-${r.local_ip}:${r.local_port}-${r.remote_ip}:${r.remote_port}-${r.pid ?? i}`;
                const active =
                  selected &&
                  selected.remote_ip === r.remote_ip &&
                  selected.remote_port === r.remote_port &&
                  selected.pid === r.pid;
                return (
                  <tr
                    key={key}
                    className={`cursor-pointer border-t border-white/5 ${active ? "bg-white/10" : "hover:bg-white/5"}`}
                    onClick={() => void onSelect(r)}
                  >
                    <td className="px-4 py-3">
                      {r.process ?? "—"}
                      {r.pid != null ? (
                        <span className="ml-2 font-mono text-[11px] text-slate-500">pid {r.pid}</span>
                      ) : null}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs">{r.remote_ip}</span>
                      {r.domain ? (
                        <span className="mt-0.5 block text-teal-200">
                          {r.domain}
                          {r.domain_source ? (
                            <span className="ml-2 text-[11px] text-slate-500">{r.domain_source}</span>
                          ) : null}
                        </span>
                      ) : null}
                    </td>
                    <td className="px-4 py-3 font-mono">{r.remote_port}</td>
                    <td className="px-4 py-3 uppercase">{r.protocol}</td>
                    <td className="px-4 py-3 text-slate-300">{r.state}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <aside className="card rounded-2xl p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Detalle</p>
          {!selected ? (
            <p className="mt-3 font-ui text-sm text-slate-400">
              Clic en una fila para país, empresa y ASN. Es una consulta externa, cacheada.
            </p>
          ) : (
            <div className="mt-3 space-y-2 font-ui text-sm">
              <p>
                {selected.process ?? "proceso ?"} → {selected.remote_ip}:{selected.remote_port}
              </p>
              <p className="text-xs text-slate-500">
                Origen {selected.local_ip}:{selected.local_port}
              </p>
              {geoBusy ? <p className="text-slate-400">Consultando…</p> : null}
              {geoError ? <p className="text-amber-200">{geoError}</p> : null}
              {geo ? (
                <dl className="space-y-2">
                  <div>
                    <dt className="text-slate-400">País</dt>
                    <dd>
                      {geo.country ?? "—"} {geo.country_code ? `(${geo.country_code})` : ""}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">Empresa / org</dt>
                    <dd>{geo.org ?? geo.isp ?? "—"}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-400">ASN</dt>
                    <dd>
                      {geo.asn ?? "—"} {geo.as_name ? `· ${geo.as_name}` : ""}
                    </dd>
                  </div>
                  <p className="text-[11px] leading-5 text-slate-500">{geo.source_label}</p>
                </dl>
              ) : null}
            </div>
          )}
        </aside>
      </div>
    </section>
  );
}
