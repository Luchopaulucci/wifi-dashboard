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
use super::geo::RateLimiter;
use super::privilege::{is_permission_error, is_permission_output, privilege_hint, PrivilegeHint};
use super::ss::{
    classify_reach, is_ephemeral_udp, listener_key, parse_ss_listeners, parse_ss_sockets,
    reach_label,
};
use super::stats::{
    iface_counters, parse_proc_net_dev, parse_proc_net_netstat, parse_proc_net_snmp, snmp_counters,
};
use super::talkers::classify_talker;
use super::trace::{classify_hops as classify_hop_kinds, parse_trace_line};
use super::types::{
    BootTrafficReport, ConnectionRow, ConnectionsReport, DnsDomainRow, DnsMonitorStatus,
    DnsProgramRow, FirewallReport, GeoInfo, ListenerRow, ListenersReport, NatReport, TraceEvent,
    TraceHop, TrafficCounter,
};

#[derive(Debug, Default, Clone)]
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

    pub fn decorate_rows(&self, rows: &mut [ConnectionRow]) {
        for row in rows.iter_mut() {
            if let Some((dom, src)) = self.lookup_cached(&row.remote_ip) {
                row.domain = Some(dom);
                row.domain_source = Some(src);
            }
        }
    }

    pub fn mark_non_public(&mut self, rows: &[ConnectionRow]) {
        for row in rows {
            if self.from_dns.contains_key(&row.remote_ip) || self.map.contains_key(&row.remote_ip) {
                continue;
            }
            if parse_ip_opt(&row.remote_ip).is_some_and(|ip| !is_public_ip(ip)) {
                self.map.insert(row.remote_ip.clone(), None);
            }
        }
    }

    pub fn pending_public_ips(&self, rows: &[ConnectionRow], budget: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for row in rows {
            if out.len() >= budget {
                break;
            }
            if !seen.insert(row.remote_ip.clone()) {
                continue;
            }
            if self.from_dns.contains_key(&row.remote_ip) || self.map.contains_key(&row.remote_ip) {
                continue;
            }
            if parse_ip_opt(&row.remote_ip).is_some_and(is_public_ip) {
                out.push(row.remote_ip.clone());
            }
        }
        out
    }

    /// DNS inverso sin tocar el caché. El caller guarda el resultado después.
    pub fn lookup_addr(ip: &str) -> Option<String> {
        let parsed = parse_ip_opt(ip)?;
        if !is_public_ip(parsed) {
            return None;
        }
        dns_lookup::lookup_addr(&parsed).ok()
    }

    pub fn remember(&mut self, ip: String, name: Option<String>) {
        self.map.insert(ip, name);
    }

    pub fn absorb(&mut self, other: PtrCache) {
        for (k, v) in other.map {
            self.map.entry(k).or_insert(v);
        }
        for (k, v) in other.from_dns {
            self.from_dns.entry(k).or_insert(v);
        }
    }
}

/// Solo lectura del caché. El DNS inverso va por `PtrCache::lookup_addr`.
pub fn lookup_ptr(cache: &PtrCache, ip: &str) -> Option<String> {
    if let Some(name) = cache.from_dns.get(ip) {
        return Some(name.clone());
    }
    cache.map.get(ip).cloned().flatten()
}

#[derive(Default)]
pub struct GeoCache {
    map: HashMap<String, GeoInfo>,
    limiter: Option<RateLimiter>,
}

impl GeoCache {
    fn limiter(&mut self) -> &mut RateLimiter {
        self.limiter
            .get_or_insert_with(|| RateLimiter::new(Duration::from_millis(1500)))
    }

    pub fn get(&self, ip: &str) -> Option<GeoInfo> {
        self.map.get(ip).cloned()
    }

    pub fn insert(&mut self, ip: String, info: GeoInfo) {
        self.map.insert(ip, info);
    }

    /// No duerme: el caller duerme fuera del lock del mapa.
    pub fn take_rate_delay(&mut self) -> Duration {
        self.limiter().delay_until_ready()
    }

    pub fn mark_rate(&mut self) {
        self.limiter().mark();
    }
}

#[derive(Debug, Default)]
pub struct ListenerSession {
    baseline: Option<HashSet<String>>,
    dismissed: HashSet<String>,
    alerts: HashMap<String, ListenerRow>,
}

#[derive(Debug, Default)]
pub struct ListenerScan {
    pub rows: Vec<ListenerRow>,
    pub source: Option<String>,
    pub missing: Vec<String>,
    pub notes: Vec<String>,
}

impl ListenerSession {
    pub fn dismiss(&mut self, key: &str) {
        self.dismissed.insert(key.to_string());
        self.alerts.remove(key);
    }

    /// `ss` sin tocar la sesión: el lock de alertas no cubre el comando.
    pub fn collect_rows() -> ListenerScan {
        let mut scan = ListenerScan::default();

        if bin_exists("ss") {
            let text = match run_cmd_capture("ss", &["-H", "-tulpn"], Duration::from_secs(5)) {
                Ok(o) if o.stdout.trim().is_empty() => {
                    run_cmd_capture("ss", &["-tulpn"], Duration::from_secs(5))
                        .map(|x| x.stdout)
                        .unwrap_or_default()
                }
                Ok(o) => o.stdout,
                Err(CoreError::BinaryMissing(b)) => {
                    scan.missing.push(b);
                    String::new()
                }
                Err(e) => {
                    scan.notes.push(e.to_string());
                    String::new()
                }
            };
            if !text.is_empty() {
                scan.rows = parse_ss_listeners(&text);
                scan.source = Some("ss -tulpn".into());
            }
        } else {
            scan.missing.push("ss".into());
            scan.notes.push("Falta `ss` (iproute2).".into());
        }
        scan
    }

    pub fn finish_report(&mut self, scan: ListenerScan) -> ListenersReport {
        let (rows, extra_notes) = apply_listener_session(self, scan.rows);
        let mut notes = scan.notes;
        notes.extend(extra_notes);
        let alerts: Vec<ListenerRow> = self.alerts.values().cloned().collect();
        let new_count = alerts.len() as u64;
        ListenersReport {
            collected_at_ms: now_ms(),
            rows,
            alerts,
            new_count,
            source: scan.source,
            missing: scan.missing,
            notes,
        }
    }
}

pub fn apply_listener_session(
    session: &mut ListenerSession,
    mut rows: Vec<ListenerRow>,
) -> (Vec<ListenerRow>, Vec<String>) {
    rows.retain(|r| !is_ephemeral_udp(r));
    for row in rows.iter_mut() {
        row.key = listener_key(row);
        row.reach = classify_reach(&row.local_ip);
        row.reach_label = reach_label(row.reach);
        row.is_new = false;
    }
    let mut notes = Vec::new();
    if session.baseline.is_none() {
        session.baseline = Some(rows.iter().map(|r| r.key.clone()).collect());
        notes.push(
            "Foto inicial de esta sesión: de acá en más avisamos si aparece un listener que no estaba (mismo proto+puerto+proceso). La alerta queda hasta que la descartes. UDP efímero (≥32768, clientes) se ignora. Reiniciar Señal toma una foto nueva.".into(),
        );
        return (rows, notes);
    }
    let baseline = session.baseline.as_ref().expect("baseline set");
    for row in &rows {
        if !baseline.contains(&row.key) && !session.dismissed.contains(&row.key) {
            session.alerts.entry(row.key.clone()).or_insert_with(|| {
                let mut alert = row.clone();
                alert.is_new = true;
                alert
            });
        }
    }
    for row in rows.iter_mut() {
        if session.alerts.contains_key(&row.key) {
            row.is_new = true;
        }
    }
    (rows, notes)
}

pub fn remember_dns_talker(acc: &mut HashMap<String, DnsProgramRow>, row: &ConnectionRow) {
    let dns_port = row.remote_port == "53" || row.remote_port == "853" || row.local_port == "53";
    if !dns_port {
        return;
    }
    let process = row
        .process
        .clone()
        .unwrap_or_else(|| "(desconocido)".into());
    let key = format!("{}|{}", process, row.pid.unwrap_or(0));
    acc.entry(key).or_insert(DnsProgramRow {
        process,
        pid: row.pid,
        dns_server: Some(row.remote_ip.clone()),
        proto: row.protocol.clone(),
        note: "Acumulado en esta sesión: este proceso tuvo un socket hacia :53/:853. No es el historial del kernel desde el boot ni los dominios que preguntó (Linux no lo guarda sin un sniffer, y eso pide root/CAP_NET_RAW).".into(),
    });
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

    // NAT/conntrack vive en su pestaña. Acá solo ss + nombres ya cacheados.
    ptr.decorate_rows(&mut rows);
    ptr.mark_non_public(&rows);

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

pub fn collect_listeners(session: &mut ListenerSession) -> ListenersReport {
    session.finish_report(ListenerSession::collect_rows())
}

pub fn listener_keys(rows: &[ListenerRow]) -> HashSet<String> {
    rows.iter().map(listener_key).collect()
}

pub fn collect_boot_traffic(
    ptr: &mut PtrCache,
    monitor_domains: &[DnsDomainRow],
    monitor_status: &DnsMonitorStatus,
    session_programs: &mut HashMap<String, DnsProgramRow>,
    connections: &[ConnectionRow],
) -> BootTrafficReport {
    let mut missing = Vec::new();
    let mut limitations = Vec::new();
    let mut privilege = None;
    let mut counters = Vec::new();
    let mut domains = Vec::new();

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
                let (rows, map) = parse_resolvectl_cache(&o.stdout);
                ptr.remember_dns_map(map);
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
                "4000",
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

    // Historial de programas que hablaron con DNS en ESTA sesión (no solo el poll actual).
    for row in connections {
        remember_dns_talker(session_programs, row);
    }
    let mut programs: Vec<_> = session_programs.values().cloned().collect();
    programs.sort_by(|a, b| a.process.cmp(&b.process));

    if !monitor_status.running {
        limitations.push(monitor_status.explanation.clone());
        if let Some(err) = &monitor_status.error {
            limitations.push(format!("resolvectl monitor: {err}"));
        }
    }

    limitations.push(
        "Linux no guarda 'dominio X lo preguntó el proceso Y desde el boot' sin un sniffer (tcpdump) o auditd, y eso pide CAP_NET_RAW/root. Señal no captura tráfico. Los dominios desde el boot salen del journal (si tu usuario puede leerlo) y de la caché de resolved. Los programas son el historial de sockets :53/:853 visto en esta sesión.".into(),
    );
    limitations.push(
        "Los contadores de /proc/net/* son desde que arrancó el kernel. Los de systemd-resolved, desde que arrancó resolved. Los del monitor, desde que abriste Señal (y solo si el monitor arrancó).".into(),
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
        dns_monitor: monitor_status.clone(),
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

    // Ubuntu default: tracepath (UDP, sin CAP_NET_RAW). traceroute después.
    let candidates: Vec<(&str, Vec<String>)> = if ipv6 {
        vec![
            ("tracepath", vec!["-6".into(), "-n".into()]),
            ("tracepath6", vec!["-n".into()]),
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
        ]
    } else {
        vec![
            ("tracepath", vec!["-n".into()]),
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
        match spawn_allowed(bin, &arg_refs, Duration::from_secs(90)) {
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

fn set_monitor_status(slot: &Mutex<DnsMonitorStatus>, status: DnsMonitorStatus) {
    if let Ok(mut g) = slot.lock() {
        *g = status;
    }
}

/// `resolvectl monitor` en background. Si falla sin root, lo dejamos escrito en `status`.
pub fn spawn_dns_monitor(
    acc: Arc<Mutex<HashMap<String, u64>>>,
    status: Arc<Mutex<DnsMonitorStatus>>,
    cancel: Arc<AtomicBool>,
) {
    if !bin_exists("resolvectl") {
        set_monitor_status(
            &status,
            DnsMonitorStatus {
                running: false,
                error: Some("no está el binario resolvectl".into()),
                needs_privilege: false,
                explanation: "No está systemd-resolved (`resolvectl`). Sin eso no hay monitor DNS en vivo. Señal no lo instala.".into(),
            },
        );
        return;
    }
    std::thread::Builder::new()
        .name("senal-dns-monitor".into())
        .spawn(move || {
            let mut child = match spawn_allowed("resolvectl", &["monitor"], Duration::ZERO) {
                Ok(c) => c,
                Err(e) => {
                    let msg = e.to_string();
                    let needs = is_permission_error(&msg);
                    set_monitor_status(
                        &status,
                        DnsMonitorStatus {
                            running: false,
                            error: Some(msg),
                            needs_privilege: needs,
                            explanation: if needs {
                                "resolvectl monitor falló sin privilegios. Señal no corre como root y no lo relanza con sudo. Igual acumulamos los programas que vimos hablando con :53/:853 en esta sesión y, si tu usuario lee el journal, los dominios desde el boot.".into()
                            } else {
                                "No se pudo arrancar resolvectl monitor. Los dominios en vivo de esta sesión no van a aparecer por esa vía.".into()
                            },
                        },
                    );
                    return;
                }
            };
            let stdout = match child.stdout.take() {
                Some(s) => s,
                None => {
                    set_monitor_status(
                        &status,
                        DnsMonitorStatus {
                            running: false,
                            error: Some("sin stdout".into()),
                            needs_privilege: false,
                            explanation: "resolvectl monitor no entregó stdout.".into(),
                        },
                    );
                    return;
                }
            };
            let stderr_handle = child.stderr.take().map(|mut err| {
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = err.read_to_end(&mut buf);
                    String::from_utf8_lossy(&buf).into_owned()
                })
            });
            set_monitor_status(
                &status,
                DnsMonitorStatus {
                    running: true,
                    error: None,
                    needs_privilege: false,
                    explanation: "resolvectl monitor está corriendo: las consultas DNS nuevas mientras Señal está abierta se acumulan acá.".into(),
                },
            );
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
            let wait = child.wait();
            let stderr = stderr_handle
                .and_then(|h| h.join().ok())
                .unwrap_or_default();
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let failed = wait.map(|s| !s.success()).unwrap_or(true);
            if failed || !stderr.trim().is_empty() {
                let needs = is_permission_error(&stderr);
                set_monitor_status(
                    &status,
                    DnsMonitorStatus {
                        running: false,
                        error: Some(if stderr.trim().is_empty() {
                            "resolvectl monitor salió".into()
                        } else {
                            stderr.trim().to_string()
                        }),
                        needs_privilege: needs,
                        explanation: if needs {
                            "resolvectl monitor falló sin privilegios. Señal no corre como root. No hay DNS en vivo por el monitor; sí hay historial de esta sesión (sockets :53/:853) y, si hay permiso, el journal desde el boot.".into()
                        } else {
                            format!(
                                "resolvectl monitor se detuvo. {}",
                                if stderr.trim().is_empty() {
                                    "Sin más detalle.".to_string()
                                } else {
                                    stderr.trim().to_string()
                                }
                            )
                        },
                    },
                );
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::types::Reachability;

    fn row(proto: &str, ip: &str, port: &str, process: &str) -> ListenerRow {
        let mut r = ListenerRow {
            protocol: proto.into(),
            local_ip: ip.into(),
            local_port: port.into(),
            process: Some(process.into()),
            pid: Some(1),
            reach: Reachability::LocalOnly,
            reach_label: String::new(),
            key: String::new(),
            is_new: false,
        };
        r.key = listener_key(&r);
        r
    }

    #[test]
    fn baseline_once_then_alert_until_dismiss() {
        let mut session = ListenerSession::default();
        let first = vec![row("tcp", "0.0.0.0", "22", "sshd")];
        let (rows, notes) = apply_listener_session(&mut session, first);
        assert!(!rows[0].is_new);
        assert!(session.alerts.is_empty());
        assert!(notes.iter().any(|n| n.contains("Foto inicial")));

        let second = vec![
            row("tcp", "0.0.0.0", "22", "sshd"),
            row("tcp", "127.0.0.1", "8080", "python3"),
        ];
        let (rows, _) = apply_listener_session(&mut session, second);
        assert_eq!(session.alerts.len(), 1);
        assert!(rows.iter().any(|r| r.local_port == "8080" && r.is_new));

        // Reopen after closing: still the same alert, no duplicate.
        let only_ssh = vec![row("tcp", "0.0.0.0", "22", "sshd")];
        let _ = apply_listener_session(&mut session, only_ssh);
        assert_eq!(session.alerts.len(), 1);
        let again = vec![
            row("tcp", "0.0.0.0", "22", "sshd"),
            row("tcp", "127.0.0.1", "8080", "python3"),
        ];
        let _ = apply_listener_session(&mut session, again);
        assert_eq!(session.alerts.len(), 1);

        session.dismiss(&row("tcp", "127.0.0.1", "8080", "python3").key);
        assert!(session.alerts.is_empty());
        let after = vec![
            row("tcp", "0.0.0.0", "22", "sshd"),
            row("tcp", "127.0.0.1", "8080", "python3"),
        ];
        let (rows, _) = apply_listener_session(&mut session, after);
        assert!(session.alerts.is_empty());
        assert!(rows.iter().all(|r| !r.is_new));
    }

    #[test]
    fn skips_ephemeral_udp() {
        let mut session = ListenerSession::default();
        let _ = apply_listener_session(&mut session, vec![row("udp", "0.0.0.0", "53", "resolved")]);
        let with_client = vec![
            row("udp", "0.0.0.0", "53", "resolved"),
            row("udp", "192.168.0.24", "47812", "chrome"),
        ];
        let (rows, _) = apply_listener_session(&mut session, with_client);
        assert!(rows.iter().all(|r| r.local_port != "47812"));
        assert!(session.alerts.is_empty());
    }

    #[test]
    fn dns_talkers_accumulate_across_polls() {
        let mut acc = HashMap::new();
        let a = ConnectionRow {
            protocol: "udp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: "55555".into(),
            remote_ip: "1.1.1.1".into(),
            remote_port: "53".into(),
            state: "UNCONN".into(),
            process: Some("firefox".into()),
            pid: Some(9),
            domain: None,
            domain_source: None,
        };
        remember_dns_talker(&mut acc, &a);
        remember_dns_talker(&mut acc, &a);
        assert_eq!(acc.len(), 1);
        let closed = ConnectionRow {
            protocol: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: "1".into(),
            remote_ip: "1.1.1.1".into(),
            remote_port: "443".into(),
            state: "ESTABLISHED".into(),
            process: Some("firefox".into()),
            pid: Some(9),
            domain: None,
            domain_source: None,
        };
        remember_dns_talker(&mut acc, &closed);
        assert_eq!(acc.len(), 1, "sin socket DNS no se borra el historial");
    }

    fn conn(remote_ip: &str) -> ConnectionRow {
        ConnectionRow {
            protocol: "tcp".into(),
            local_ip: "192.168.0.24".into(),
            local_port: "40000".into(),
            remote_ip: remote_ip.into(),
            remote_port: "443".into(),
            state: "ESTABLISHED".into(),
            process: Some("firefox".into()),
            pid: Some(1),
            domain: None,
            domain_source: None,
        }
    }

    #[test]
    fn ptr_cache_decorates_without_dns_and_lists_pending() {
        let mut cache = PtrCache::default();
        cache.remember("1.1.1.1".into(), Some("one.one.one.one".into()));
        let mut rows = vec![
            conn("1.1.1.1"),
            conn("192.168.0.1"),
            conn("8.8.8.8"),
            conn("8.8.8.8"),
        ];
        cache.decorate_rows(&mut rows);
        cache.mark_non_public(&rows);
        assert_eq!(rows[0].domain.as_deref(), Some("one.one.one.one"));
        assert_eq!(rows[0].domain_source.as_deref(), Some("DNS inverso (PTR)"));
        assert!(rows[1].domain.is_none());
        assert!(rows[2].domain.is_none());
        let pending = cache.pending_public_ips(&rows, 6);
        assert_eq!(pending, vec!["8.8.8.8".to_string()]);
        assert!(PtrCache::lookup_addr("192.168.0.1").is_none());
        assert!(lookup_ptr(&cache, "9.9.9.9").is_none());
        assert!(!cache.map.contains_key("9.9.9.9"));
    }

    #[test]
    fn ptr_absorb_keeps_existing_hits() {
        let mut live = PtrCache::default();
        live.remember("1.1.1.1".into(), Some("kept".into()));
        let mut other = PtrCache::default();
        other.remember("1.1.1.1".into(), Some("stale".into()));
        other.remember("8.8.8.8".into(), Some("dns.google".into()));
        live.absorb(other);
        assert_eq!(
            live.lookup_cached("1.1.1.1").map(|(n, _)| n).as_deref(),
            Some("kept")
        );
        assert_eq!(
            live.lookup_cached("8.8.8.8").map(|(n, _)| n).as_deref(),
            Some("dns.google")
        );
    }

    #[test]
    fn collect_connections_skips_conntrack() {
        let mut ptr = PtrCache::default();
        let report = collect_connections(&mut ptr);
        assert!(report.sources.iter().all(|s| !s.contains("conntrack")));
        assert!(report
            .notes
            .iter()
            .all(|n| !n.to_ascii_lowercase().contains("conntrack")));
    }

    #[test]
    fn finish_report_applies_session_without_ss() {
        let mut session = ListenerSession::default();
        let scan = ListenerScan {
            rows: vec![row("tcp", "0.0.0.0", "22", "sshd")],
            source: Some("fixture".into()),
            missing: vec![],
            notes: vec![],
        };
        let report = session.finish_report(scan);
        assert_eq!(report.source.as_deref(), Some("fixture"));
        assert!(!report.rows[0].is_new);
        assert!(report.notes.iter().any(|n| n.contains("Foto inicial")));
    }
}
