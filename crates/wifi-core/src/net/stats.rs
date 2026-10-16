use std::collections::HashMap;

use super::types::TrafficCounter;

/// /proc/net/snmp: filas de nombres + valores.
pub fn parse_proc_net_snmp(text: &str) -> HashMap<String, u64> {
    parse_named_rows(text)
}

pub fn parse_proc_net_netstat(text: &str) -> HashMap<String, u64> {
    parse_named_rows(text)
}

fn parse_named_rows(text: &str) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let mut pending: Option<(String, Vec<String>)> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(prefix) = parts.next() else {
            continue;
        };
        let prefix = prefix.trim_end_matches(':').to_string();
        let cols: Vec<String> = parts.map(|s| s.to_string()).collect();
        if cols
            .iter()
            .all(|c| c.parse::<i64>().is_err() && c.parse::<u64>().is_err())
        {
            pending = Some((prefix, cols));
        } else if let Some((p, names)) = pending.take() {
            if p == prefix {
                for (name, val) in names.iter().zip(cols.iter()) {
                    if let Ok(n) = val.parse::<u64>() {
                        map.insert(format!("{prefix}.{name}"), n);
                    } else if let Ok(n) = val.parse::<i64>() {
                        if n >= 0 {
                            map.insert(format!("{prefix}.{name}"), n as u64);
                        }
                    }
                }
            }
        }
    }
    map
}

#[derive(Debug, Clone, PartialEq)]
pub struct IfaceCounters {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

pub fn parse_proc_net_dev(text: &str) -> Vec<IfaceCounters> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if !line.contains(':') || line.starts_with("Inter") || line.starts_with("face") {
            continue;
        }
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() < 16 {
            continue;
        }
        let rx_bytes = cols[0].parse().unwrap_or(0);
        let rx_packets = cols[1].parse().unwrap_or(0);
        let tx_bytes = cols[8].parse().unwrap_or(0);
        let tx_packets = cols[9].parse().unwrap_or(0);
        out.push(IfaceCounters {
            name: name.trim().to_string(),
            rx_bytes,
            rx_packets,
            tx_bytes,
            tx_packets,
        });
    }
    out
}

pub fn snmp_counters(
    snmp: &HashMap<String, u64>,
    netstat: &HashMap<String, u64>,
) -> Vec<TrafficCounter> {
    let mut out = Vec::new();
    push(
        &mut out,
        "tcp_active_opens",
        "Conexiones TCP salientes (ActiveOpens)",
        snmp.get("Tcp.ActiveOpens").copied().unwrap_or(0),
        "TCP que esta PC inició (el SYN lo mandamos nosotros). Es el mejor proxy de 'pedidos salientes' desde el arranque del kernel.",
        "/proc/net/snmp → Tcp.ActiveOpens",
    );
    push(
        &mut out,
        "tcp_passive_opens",
        "Conexiones TCP entrantes (PassiveOpens)",
        snmp.get("Tcp.PassiveOpens").copied().unwrap_or(0),
        "TCP que alguien inició hacia un puerto en escucha de esta PC.",
        "/proc/net/snmp → Tcp.PassiveOpens",
    );
    push(
        &mut out,
        "tcp_out_segs",
        "Segmentos TCP enviados",
        snmp.get("Tcp.OutSegs").copied().unwrap_or(0),
        "Segmentos TCP que salieron (incluye retransmisiones no; esas van aparte).",
        "/proc/net/snmp → Tcp.OutSegs",
    );
    push(
        &mut out,
        "tcp_retrans",
        "Retransmisiones TCP",
        snmp.get("Tcp.RetransSegs").copied().unwrap_or(0),
        "Segmentos reenviados: red congestionada, pérdida, o el otro no contestó.",
        "/proc/net/snmp → Tcp.RetransSegs",
    );
    push(
        &mut out,
        "udp_out",
        "Datagramas UDP enviados",
        snmp.get("Udp.OutDatagrams").copied().unwrap_or(0),
        "UDP saliente. Ahí viajan DNS, QUIC, mDNS, juegos, etc. No es 1 a 1 con 'requests'.",
        "/proc/net/snmp → Udp.OutDatagrams",
    );
    push(
        &mut out,
        "ip_out_requests",
        "Datagramas IP salientes (OutRequests)",
        snmp.get("Ip.OutRequests").copied().unwrap_or(0),
        "Paquetes IPv4 que el stack local quiso mandar desde el arranque.",
        "/proc/net/snmp → Ip.OutRequests",
    );
    push(
        &mut out,
        "ip_in_delivers",
        "Datagramas IP entregados a apps (InDelivers)",
        snmp.get("Ip.InDelivers").copied().unwrap_or(0),
        "IPv4 que llegaron y se le entregaron a TCP/UDP/ICMP locales.",
        "/proc/net/snmp → Ip.InDelivers",
    );
    if let Some(v) = netstat.get("IpExt.OutOctets") {
        push(
            &mut out,
            "ip_out_octets",
            "Octetos IPv4 salientes",
            *v,
            "Bytes IPv4 enviados (incluye headers). Desde el arranque del kernel.",
            "/proc/net/netstat → IpExt.OutOctets",
        );
    }
    if let Some(v) = netstat.get("IpExt.InOctets") {
        push(
            &mut out,
            "ip_in_octets",
            "Octetos IPv4 entrantes",
            *v,
            "Bytes IPv4 recibidos. Desde el arranque del kernel.",
            "/proc/net/netstat → IpExt.InOctets",
        );
    }
    out
}

fn push(
    out: &mut Vec<TrafficCounter>,
    id: &str,
    label: &str,
    value: u64,
    meaning: &str,
    source: &str,
) {
    out.push(TrafficCounter {
        id: id.into(),
        label: label.into(),
        value,
        meaning: meaning.into(),
        source: source.into(),
    });
}

pub fn iface_counters(ifaces: &[IfaceCounters]) -> Vec<TrafficCounter> {
    let mut out = Vec::new();
    for i in ifaces {
        if i.name == "lo" {
            continue;
        }
        out.push(TrafficCounter {
            id: format!("iface_{}_tx_bytes", i.name),
            label: format!("{} · bytes enviados", i.name),
            value: i.tx_bytes,
            meaning: format!(
                "Bytes que salieron por {name} desde que se levantó la interfaz (no siempre coincide con el boot de la PC si la bajaste y subiste).",
                name = i.name
            ),
            source: format!("/proc/net/dev → {} Transmit bytes", i.name),
        });
        out.push(TrafficCounter {
            id: format!("iface_{}_tx_pkts", i.name),
            label: format!("{} · paquetes enviados", i.name),
            value: i.tx_packets,
            meaning: format!("Paquetes transmitidos por {}.", i.name),
            source: format!("/proc/net/dev → {} Transmit packets", i.name),
        });
        out.push(TrafficCounter {
            id: format!("iface_{}_rx_bytes", i.name),
            label: format!("{} · bytes recibidos", i.name),
            value: i.rx_bytes,
            meaning: format!("Bytes que entraron por {}.", i.name),
            source: format!("/proc/net/dev → {} Receive bytes", i.name),
        });
    }
    out
}
