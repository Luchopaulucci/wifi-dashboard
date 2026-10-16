use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::command::{bin_exists, run_cmd_capture, spawn_allowed, validate_host};
use crate::error::{CoreError, Result};
use crate::types::now_ms;

use super::addr::{is_public_ip, parse_ip_opt};
use super::conntrack::parse_conntrack;
use super::dns::{
    merge_domain_rows, parse_journal_resolved, parse_resolvectl_cache,
    parse_resolvectl_monitor_line, parse_resolvectl_statistics,
};
use super::firewall::{parse_iptables_save, parse_nft_ruleset, summarize_verdicts};
use super::geo::{lookup_ip_external, RateLimiter};
use super::privilege::{is_permission_error, is_permission_output, privilege_hint, PrivilegeHint};
use super::ss::{classify_reach, listener_key, parse_ss_listeners, parse_ss_sockets, reach_label};
use super::stats::{
    iface_counters, parse_proc_net_dev, parse_proc_net_netstat, parse_proc_net_snmp, snmp_counters,
};
use super::talkers::classify_talker;
use super::trace::{classify_hops as classify_hop_kinds, parse_trace_line};
use super::types::{
    BootTrafficReport, ConnectionRow, ConnectionsReport, DnsDomainRow, DnsProgramRow,
    FirewallReport, GeoInfo, ListenerRow, ListenersReport, NatReport, TraceEvent, TraceHop,
    TrafficCounter,
};

#[derive(Debug, Default)]
pub struct PtrCache {
    map: HashMap<String, Option<String>>,
    /// dest IP → nombre visto en respuestas DNS (cache resolved / journal)
    from_dns: HashMap<String, String>,
}

impl PtrCache {
    pub fn remember_dns_map(&mut self, ip_to_name: HashMap<String, String>) {
        for (ip, name) in ip_to_name {
            self.from_dns.entry(ip).or_insert(name);
        }
    }

    pub fn lookup_cached(&self, ip: &str) -> Option<(String, String)> {
        if let Some(name) = self.from_dns.get(ip) {
            return Some((
                name.clone(),
                "respuesta DNS observada (cache/journal)".into(),
            ));
        }
        match self.map.get(ip) {
            Some(Some(name)) => Some((name.clone(), "DNS inverso (PTR)".into())),
            _ => None,
        }
    }
}

pub fn lookup_ptr(cache: &mut PtrCache, ip: &str) -> Option<String> {
    if let Some(name) = cache.from_dns.get(ip) {
        return Some(name.clone());
    }
    if let Some(hit) = cache.map.get(ip) {
        return hit.clone();
    }
    let parsed = parse_ip_opt(ip)?;
    if !is_public_ip(parsed) {
        cache.map.insert(ip.to_string(), None);
        return None;
    }
    let name = std::thread::spawn(move || dns_lookup::lookup_addr(&parsed).ok())
        .join()
        .ok()
        .flatten();
    cache.map.insert(ip.to_string(), name.clone());
    name
}

#[derive(Default)]
pub struct GeoCache {
    map: HashMap<String, GeoInfo>,
    limiter: Option<RateLimiter>,
}

impl GeoCache {
    pub fn limiter(&mut self) -> &mut RateLimiter {
        self.limiter
            .get_or_insert_with(|| RateLimiter::new(Duration::from_millis(1500)))
    }

    pub fn get_or_lookup(&mut self, ip: &str) -> Result<GeoInfo> {
        if let Some(hit) = self.map.get(ip) {
            return Ok(hit.clone());
        }
        self.limiter().wait_if_needed();
        let info = lookup_ip_external(ip)?;
        self.map.insert(ip.to_string(), info.clone());
        Ok(info)
    }
}

pub fn collect_connections(ptr: &mut PtrCache) -> ConnectionsReport {
    let mut missing = Vec::new();
    let mut sources = Vec::new();
    let mut notes = Vec::new();
    let mut privilege = None;
    let mut rows = Vec::new();

    if bin_exists("ss") {
        let out = run_cmd_capture("ss", &["-H", "-tunap"], Duration::from_secs(5));
        match out {
            Ok(o) if is_permission_output(&o) => {
                privilege = Some(privilege_hint("ss", "CAP_NET_ADMIN"));
                notes.push("ss respondió sin permiso; reintentamos sin -H.".into());
            }
            Ok(o) => {
                let text = if o.stdout.trim().is_empty() {
                    run_cmd_capture("ss", &["-tunap"], Duration::from_secs(5))
                        .map(|x| x.stdout)
                        .unwrap_or_default()
                } else {
                    o.stdout
                };
                rows = parse_ss_sockets(&text);
                sources.push("ss -tunap".into());
            }
            Err(CoreError::BinaryMissing(b)) => missing.push(b),
            Err(e) => notes.push(e.to_string()),
        }
    } else {
        missing.push("ss".into());
        notes.push("Falta iproute2 (`ss`). En Ubuntu: sudo apt install iproute2".into());
    }

    if bin_exists("conntrack") {
        match run_cmd_capture("conntrack", &["-L"], Duration::from_secs(5)) {
            Ok(o) if is_permission_output(&o) => {
                notes.push(
                    "conntrack está pero pide CAP_NET_ADMIN: las conexiones salen de ss; NAT va en su pestaña."
                        .into(),
                );
            }
            Ok(o) if !o.stdout.trim().is_empty() => {
                sources.push("conntrack -L".into());
                notes.push(
                    "conntrack disponible: las traducciones NAT están en la pestaña NAT.".into(),
                );
            }
            _ => {}
        }
    }

    // Enriquecer con PTR (pocos, para no clavar el refresh).
    let mut budget = 6u32;
    for row in rows.iter_mut() {
        if let Some((dom, src)) = ptr.lookup_cached(&row.remote_ip) {
            row.domain = Some(dom);
            row.domain_source = Some(src);
            continue;
        }
        if budget == 0 {
            continue;
        }
        if parse_ip_opt(&row.remote_ip).is_some_and(is_public_ip) {
            budget -= 1;
            if let Some(name) = lookup_ptr(ptr, &row.remote_ip) {
                row.domain = Some(name);
                row.domain_source = Some("DNS inverso (PTR)".into());
            }
        }
    }

    ConnectionsReport {
        collected_at_ms: now_ms(),
        rows,
        sources,
        missing,
        privilege,
        notes,
    }
}

pub fn collect_nat() -> NatReport {
    let mut missing = Vec::new();
    let mut notes = Vec::new();
    let mut privilege = None;
    let mut translations = Vec::new();
    let mut source = None;

    if bin_exists("conntrack") {
        match run_cmd_capture("conntrack", &["-L"], Duration::from_secs(6)) {
            Ok(o) if is_permission_output(&o) => {
                privilege = Some(privilege_hint("conntrack", "CAP_NET_ADMIN"));
            }
            Ok(o) => {
                translations = parse_conntrack(&o.stdout);
                source = Some("conntrack -L".into());
            }
            Err(CoreError::BinaryMissing(b)) => missing.push(b),
            Err(e) => notes.push(e.to_string()),
        }
    } else {
        missing.push("conntrack".into());
    }

    if translations.is_empty() && privilege.is_none() {
        if let Ok(text) = std::fs::read_to_string("/proc/net/nf_conntrack") {
            translations = parse_conntrack(&text);
            source = Some("/proc/net/nf_conntrack".into());
        } else if let Err(e) = std::fs::read_to_string("/proc/net/nf_conntrack") {
            let msg = e.to_string();
            if is_permission_error(&msg) && privilege.is_none() {
                privilege = Some(privilege_hint("conntrack", "CAP_NET_ADMIN"));
                notes
                    .push("Tampoco se pudo leer /proc/net/nf_conntrack (permiso denegado).".into());
            }
        }
    }

    if !bin_exists("conntrack") && translations.is_empty() && privilege.is_none() {
        notes.push(
            "No está `conntrack` (paquete conntrack-tools) ni se pudo leer /proc/net/nf_conntrack."
                .into(),
        );
    }

    let snat_count = translations
        .iter()
        .filter(|t| t.nat_kind.contains("SNAT"))
        .count() as u64;
    let dnat_count = translations
        .iter()
        .filter(|t| t.nat_kind.contains("DNAT"))
        .count() as u64;
    let active_count = translations.len() as u64;

    NatReport {
        collected_at_ms: now_ms(),
        translations,
        active_count,
        snat_count,
        dnat_count,
        source,
        missing,
        privilege,
        notes,
    }
}

pub fn collect_firewall() -> FirewallReport {
    let mut missing = Vec::new();
    let mut notes = Vec::new();
    let mut privilege = None;
    let mut backend = None;
    let mut tables = Vec::new();

    if bin_exists("nft") {
        match run_cmd_capture("nft", &["list", "ruleset"], Duration::from_secs(8)) {
            Ok(o) if is_permission_output(&o) => {
                privilege = Some(privilege_hint("nft", "CAP_NET_ADMIN"));
            }
            Ok(o) => {
                tables = parse_nft_ruleset(&o.stdout);
                backend = Some("nft list ruleset".into());
            }
            Err(CoreError::BinaryMissing(b)) => missing.push(b),
            Err(e) => notes.push(e.to_string()),
        }
    } else {
        missing.push("nft".into());
    }

    if tables.is_empty() && bin_exists("iptables-save") {
        match run_cmd_capture("iptables-save", &["-c"], Duration::from_secs(8)) {
            Ok(o) if is_permission_output(&o) => {
                if privilege.is_none() {
                    privilege = Some(privilege_hint("iptables-save", "CAP_NET_ADMIN"));
                }
            }
            Ok(o) if !o.stdout.trim().is_empty() => {
                tables = parse_iptables_save(&o.stdout);
                backend = Some("iptables-save -c".into());
            }
            Ok(_) => {}
            Err(CoreError::BinaryMissing(b)) => missing.push(b),
            Err(e) => notes.push(e.to_string()),
        }
    } else if !bin_exists("iptables-save") {
        missing.push("iptables-save".into());
    }

    if tables.is_empty() && bin_exists("iptables") {
        match run_cmd_capture("iptables", &["-S"], Duration::from_secs(8)) {
            Ok(o) if is_permission_output(&o) => {
                if privilege.is_none() {
                    privilege = Some(privilege_hint("iptables", "CAP_NET_ADMIN"));
                }
            }
            Ok(o) if !o.stdout.trim().is_empty() => {
                tables = parse_iptables_save(&format!("*filter\n{}\nCOMMIT\n", o.stdout));
                backend = Some("iptables -S".into());
            }
            Ok(_) => {}
            Err(CoreError::BinaryMissing(b)) => missing.push(b),
            Err(e) => notes.push(e.to_string()),
        }
    }

    if backend.is_none() && tables.is_empty() && privilege.is_none() {
        notes.push(
            "No hay nft ni iptables visibles. En Ubuntu moderno el backend es nftables (`nft`)."
                .into(),
        );
    }

    let (accepted_packets, accepted_bytes, dropped_packets, dropped_bytes) =
        summarize_verdicts(&tables);

    if tables.iter().any(|t| {
        t.chains
            .iter()
            .any(|c| c.rules.iter().any(|r| r.packets.is_none()) && c.policy_packets.is_none())
    }) {
        notes.push(
            "Si una regla no muestra paquetes/bytes es porque no tiene `counter` (nft) o no vino de `iptables-save -c`."
                .into(),
        );
    }

    FirewallReport {
        collected_at_ms: now_ms(),
        backend,
        tables,
        accepted_packets,
        accepted_bytes,
        dropped_packets,
        dropped_bytes,
        missing,
        privilege,
        notes,
    }
}

pub fn collect_listeners(prev: Option<&HashSet<String>>) -> ListenersReport {
    let mut missing = Vec::new();
    let mut notes = Vec::new();
    let mut rows = Vec::new();
    let mut source = None;

    if bin_exists("ss") {
        let text = match run_cmd_capture("ss", &["-H", "-tulpn"], Duration::from_secs(5)) {
            Ok(o) if o.stdout.trim().is_empty() => {
                run_cmd_capture("ss", &["-tulpn"], Duration::from_secs(5))
                    .map(|x| x.stdout)
                    .unwrap_or_default()
            }
            Ok(o) => o.stdout,
            Err(CoreError::BinaryMissing(b)) => {
                missing.push(b);
                String::new()
            }
            Err(e) => {
                notes.push(e.to_string());
                String::new()
            }
        };
        if !text.is_empty() {
            rows = parse_ss_listeners(&text);
            source = Some("ss -tulpn".into());
        }
    } else {
        missing.push("ss".into());
        notes.push("Falta `ss` (iproute2).".into());
    }

    let mut new_count = 0u64;
    if let Some(prev) = prev {
        for row in rows.iter_mut() {
            let key = listener_key(row);
            if !prev.contains(&key) {
                row.is_new = true;
                new_count += 1;
            }
        }
        if prev.is_empty() {
            for row in rows.iter_mut() {
                row.is_new = false;
            }
            new_count = 0;
            notes.push(
                "Primera foto de puertos: a partir de ahora avisamos si aparece uno nuevo.".into(),
            );
        }
    } else {
        notes.push(
            "Primera foto de puertos: a partir de ahora avisamos si aparece uno nuevo.".into(),
        );
    }

    // Re-label reach
    for row in rows.iter_mut() {
        row.reach = classify_reach(&row.local_ip);
        row.reach_label = reach_label(row.reach);
    }

    ListenersReport {
        collected_at_ms: now_ms(),
        rows,
        new_count,
        source,
        missing,
        notes,
    }
}

pub fn listener_keys(rows: &[ListenerRow]) -> HashSet<String> {
    rows.iter().map(listener_key).collect()
}

pub fn collect_boot_traffic(
    monitor_domains: &[DnsDomainRow],
    connections: &[ConnectionRow],
) -> BootTrafficReport {
    let mut missing = Vec::new();
    let mut limitations = Vec::new();
    let mut privilege = None;
    let mut counters = Vec::new();
    let mut domains = Vec::new();
    let mut programs = Vec::new();

    if let Ok(text) = std::fs::read_to_string("/proc/net/snmp") {
        let snmp = parse_proc_net_snmp(&text);
        let netstat = std::fs::read_to_string("/proc/net/netstat")
            .ok()
            .map(|t| parse_proc_net_netstat(&t))
            .unwrap_or_default();
        counters.extend(snmp_counters(&snmp, &netstat));
    } else {
        missing.push("/proc/net/snmp".into());
    }
    if let Ok(text) = std::fs::read_to_string("/proc/net/dev") {
        counters.extend(iface_counters(&parse_proc_net_dev(&text)));
    }

    if bin_exists("resolvectl") {
        match run_cmd_capture("resolvectl", &["statistics"], Duration::from_secs(4)) {
            Ok(o) if !o.stdout.trim().is_empty() => {
                let st = parse_resolvectl_statistics(&o.stdout);
                if let Some(v) = st.queries_total {
                    counters.push(TrafficCounter {
                        id: "resolved_queries".into(),
                        label: "Consultas DNS (systemd-resolved)".into(),
                        value: v,
                        meaning: "Total de transacciones DNS que vio systemd-resolved desde que arrancó ESE servicio, no necesariamente desde que prendiste la PC (si se reinició resolved, el contador vuelve a 0).".into(),
                        source: "resolvectl statistics → Queries/transactions Total".into(),
                    });
                }
                if let Some(v) = st.cache_hits {
                    counters.push(TrafficCounter {
                        id: "resolved_cache_hits".into(),
                        label: "DNS cache hits".into(),
                        value: v,
                        meaning: "Consultas que resolved contestó desde su caché.".into(),
                        source: "resolvectl statistics → Cache hits".into(),
                    });
                }
                if let Some(v) = st.cache_misses {
                    counters.push(TrafficCounter {
                        id: "resolved_cache_misses".into(),
                        label: "DNS cache misses".into(),
                        value: v,
                        meaning: "Consultas que resolved tuvo que preguntarle a un servidor."
                            .into(),
                        source: "resolvectl statistics → Cache misses".into(),
                    });
                }
            }
            Ok(_) => {}
            Err(CoreError::BinaryMissing(b)) => missing.push(b),
            Err(e) => limitations.push(e.to_string()),
        }
        match run_cmd_capture("resolvectl", &["show-cache"], Duration::from_secs(4)) {
            Ok(o) if is_permission_output(&o) => {
                limitations.push(
                    "resolvectl show-cache pidió privilegios; no leemos la caché DNS.".into(),
                );
            }
            Ok(o) if !o.stdout.trim().is_empty() => {
                let (rows, _map) = parse_resolvectl_cache(&o.stdout);
                domains.extend(rows);
            }
            _ => {}
        }
    } else {
        missing.push("resolvectl".into());
        limitations.push(
            "No está systemd-resolved (`resolvectl`). Los números DNS van a ser parciales.".into(),
        );
    }

    if bin_exists("journalctl") {
        match run_cmd_capture(
            "journalctl",
            &[
                "-u",
                "systemd-resolved",
                "-b",
                "--no-pager",
                "-o",
                "cat",
                "-n",
                "400",
            ],
            Duration::from_secs(6),
        ) {
            Ok(o)
                if is_permission_output(&o) || o.stderr.to_ascii_lowercase().contains("d-bus") =>
            {
                privilege = Some(privilege_hint("journalctl", "systemd-journal"));
            }
            Ok(o) => {
                let rows = parse_journal_resolved(&o.stdout);
                if rows.is_empty() {
                    limitations.push(
                        "El journal de systemd-resolved no trae consultas (el log de queries suele estar en debug). Por eso no hay dominios 'desde el boot' por journal.".into(),
                    );
                }
                domains.extend(rows);
            }
            Err(e) => limitations.push(e.to_string()),
        }
    } else {
        missing.push("journalctl".into());
    }

    domains.extend(monitor_domains.iter().cloned());
    domains = merge_domain_rows(domains);

    // Procesos que ahora mismo hablan con DNS (puerto 53/853).
    for row in connections {
        let dns_port =
            row.remote_port == "53" || row.remote_port == "853" || row.local_port == "53";
        if dns_port {
            programs.push(DnsProgramRow {
                process: row.process.clone().unwrap_or_else(|| "(desconocido)".into()),
                pid: row.pid,
                dns_server: Some(row.remote_ip.clone()),
                proto: row.protocol.clone(),
                note: "Socket abierto ahora hacia un puerto DNS. No es el historial desde el arranque ni el listado de dominios que preguntó.".into(),
            });
        }
    }

    limitations.push(
        "Linux no guarda 'dominio X lo preguntó el proceso Y desde el boot' sin un sniffer (tcpdump) o auditd, y eso pide CAP_NET_RAW/root. Señal no captura tráfico. Los dominios salen de resolved (stats/caché/monitor mientras la app está abierta) y, si hay permiso, del journal.".into(),
    );
    limitations.push(
        "Los contadores de /proc/net/* son desde que arrancó el kernel. Los de systemd-resolved, desde que arrancó resolved. Los del monitor, desde que abriste Señal.".into(),
    );

    for d in domains.iter_mut() {
        if d.talker.is_none() {
            d.talker = classify_talker(&d.domain);
        }
    }

    BootTrafficReport {
        collected_at_ms: now_ms(),
        counters,
        domains,
        programs,
        missing,
        privilege,
        limitations,
    }
}

pub struct TraceSession {
    pub cancel: Arc<AtomicBool>,
}

impl Default for TraceSession {
    fn default() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Corre traceroute/tracepath y llama `on_event` por cada hop (y al terminar).
pub fn start_trace<F>(
    destination: &str,
    gateway: Option<&str>,
    cancel: Arc<AtomicBool>,
    mut on_event: F,
) -> Result<()>
where
    F: FnMut(TraceEvent),
{
    let dest = validate_host(destination)?;
    let session_id = format!("{}-{}", now_ms(), dest);
    let ipv6 = dest.parse::<std::net::Ipv6Addr>().is_ok();

    let candidates: Vec<(&str, Vec<String>)> = if ipv6 {
        vec![
            (
                "traceroute",
                vec![
                    "-6".into(),
                    "-n".into(),
                    "-q".into(),
                    "1".into(),
                    "-w".into(),
                    "2".into(),
                ],
            ),
            (
                "traceroute6",
                vec![
                    "-n".into(),
                    "-q".into(),
                    "1".into(),
                    "-w".into(),
                    "2".into(),
                ],
            ),
            ("tracepath", vec!["-6".into(), "-n".into()]),
            ("tracepath6", vec!["-n".into()]),
        ]
    } else {
        vec![
            (
                "traceroute",
                vec![
                    "-n".into(),
                    "-q".into(),
                    "1".into(),
                    "-w".into(),
                    "2".into(),
                ],
            ),
            ("tracepath", vec!["-n".into()]),
        ]
    };

    let mut last_priv: Option<PrivilegeHint> = None;
    let mut last_missing = Vec::new();

    for (bin, mut args) in candidates {
        if !bin_exists(bin) {
            last_missing.push(bin.to_string());
            continue;
        }
        args.push("--".into());
        args.push(dest.clone());
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match spawn_allowed(bin, &arg_refs) {
            Ok(mut child) => {
                on_event(TraceEvent {
                    session_id: session_id.clone(),
                    kind: "start".into(),
                    hop: None,
                    message: Some(format!("{bin} {}", args.join(" "))),
                    tool: Some(bin.into()),
                    privilege: None,
                });
                let stdout = child.stdout.take();
                let stderr = child.stderr.take();
                if let Some(err) = stderr {
                    std::thread::spawn(move || {
                        let mut buf = Vec::new();
                        let mut err = err;
                        let _ = err.read_to_end(&mut buf);
                    });
                }
                let mut hops: Vec<TraceHop> = Vec::new();
                if let Some(out) = stdout {
                    let reader = BufReader::new(out);
                    for line in reader.lines() {
                        if cancel.load(Ordering::Relaxed) {
                            let _ = child.kill();
                            break;
                        }
                        let Ok(line) = line else { break };
                        if let Some(mut hop) = parse_trace_line(&line) {
                            classify_hop_kinds(std::slice::from_mut(&mut hop), gateway, &dest);
                            // Reclassify globally for ISP start
                            hops.retain(|h| h.hop != hop.hop);
                            hops.push(hop.clone());
                            hops.sort_by_key(|h| h.hop);
                            classify_hop_kinds(&mut hops, gateway, &dest);
                            let emitted = hops
                                .iter()
                                .find(|h| h.hop == hop.hop)
                                .cloned()
                                .unwrap_or(hop);
                            on_event(TraceEvent {
                                session_id: session_id.clone(),
                                kind: "hop".into(),
                                hop: Some(emitted),
                                message: None,
                                tool: Some(bin.into()),
                                privilege: None,
                            });
                        }
                    }
                }
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    on_event(TraceEvent {
                        session_id: session_id.clone(),
                        kind: "cancelled".into(),
                        hop: None,
                        message: Some("Ruta cancelada.".into()),
                        tool: Some(bin.into()),
                        privilege: None,
                    });
                    return Ok(());
                }
                let status = child.wait();
                let fail_perm = status.ok().is_some_and(|s| !s.success()) && hops.is_empty();
                if fail_perm {
                    last_priv = Some(privilege_hint(bin, "CAP_NET_RAW"));
                    continue;
                }
                on_event(TraceEvent {
                    session_id: session_id.clone(),
                    kind: "done".into(),
                    hop: None,
                    message: Some(format!("Listo con {bin}.")),
                    tool: Some(bin.into()),
                    privilege: None,
                });
                return Ok(());
            }
            Err(CoreError::BinaryMissing(b)) => last_missing.push(b),
            Err(e) => {
                last_priv = if is_permission_error(&e.to_string()) {
                    Some(privilege_hint(bin, "CAP_NET_RAW"))
                } else {
                    last_priv
                };
            }
        }
    }

    {
        on_event(TraceEvent {
            session_id,
            kind: "error".into(),
            hop: None,
            message: Some(
                if last_missing.len() == 4 || (!last_missing.is_empty() && last_priv.is_none()) {
                    format!(
                    "No está traceroute ni tracepath. En Ubuntu: sudo apt install traceroute iputils-tracepath. Faltan: {}",
                    last_missing.join(", ")
                )
                } else {
                    "No se pudo trazar la ruta con los binarios disponibles.".into()
                },
            ),
            tool: None,
            privilege: last_priv,
        });
    }
    Ok(())
}

pub fn default_gateway() -> Option<String> {
    if !bin_exists("ip") {
        return None;
    }
    let out = run_cmd_capture("ip", &["route", "show", "default"], Duration::from_secs(3)).ok()?;
    crate::parse::parse_ip_route_default(&out.stdout).map(|(gw, _dev)| gw)
}

/// `resolvectl monitor` en background. No falla el arranque si no está o no hay permiso.
pub fn spawn_dns_monitor(acc: Arc<Mutex<HashMap<String, u64>>>, cancel: Arc<AtomicBool>) {
    if !bin_exists("resolvectl") {
        return;
    }
    std::thread::Builder::new()
        .name("senal-dns-monitor".into())
        .spawn(move || {
            let mut child = match spawn_allowed("resolvectl", &["monitor"]) {
                Ok(c) => c,
                Err(_) => return,
            };
            let stdout = match child.stdout.take() {
                Some(s) => s,
                None => return,
            };
            if let Some(err) = child.stderr.take() {
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut err = err;
                    let _ = err.read_to_end(&mut buf);
                });
            }
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    break;
                }
                let Ok(line) = line else { break };
                if let Ok(mut map) = acc.lock() {
                    ingest_monitor_line(&line, &mut map);
                }
            }
            let _ = child.wait();
        })
        .ok();
}

pub fn ingest_monitor_line(line: &str, acc: &mut HashMap<String, u64>) {
    for d in parse_resolvectl_monitor_line(line) {
        *acc.entry(d).or_insert(0) += 1;
    }
}

pub fn monitor_rows(acc: &HashMap<String, u64>) -> Vec<DnsDomainRow> {
    let mut rows: Vec<DnsDomainRow> = acc
        .iter()
        .map(|(domain, count)| DnsDomainRow {
            domain: domain.clone(),
            count: *count,
            source: "resolvectl monitor (mientras Señal está abierta)".into(),
            talker: classify_talker(domain),
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.count));
    rows
}
