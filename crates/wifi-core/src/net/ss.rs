use super::addr::{is_loopback_addr, is_wildcard_addr};
use super::types::{ConnectionRow, ListenerRow, Reachability};

pub fn parse_ss_sockets(text: &str) -> Vec<ConnectionRow> {
    let mut rows = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || is_ss_header(line) {
            continue;
        }
        if let Some(row) = parse_ss_socket_line(line) {
            rows.push(row);
        }
    }
    rows
}

pub fn parse_ss_listeners(text: &str) -> Vec<ListenerRow> {
    let mut rows = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || is_ss_header(line) {
            continue;
        }
        if let Some(row) = parse_ss_listener_line(line) {
            rows.push(row);
        }
    }
    rows
}

fn is_ss_header(line: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or("");
    matches!(first, "Netid" | "State" | "NetidState")
}

fn parse_ss_socket_line(line: &str) -> Option<ConnectionRow> {
    let parsed = parse_ss_columns(line)?;
    Some(ConnectionRow {
        protocol: parsed.proto,
        local_ip: parsed.local_ip,
        local_port: parsed.local_port,
        remote_ip: parsed.remote_ip,
        remote_port: parsed.remote_port,
        state: normalize_state(&parsed.state),
        process: parsed.process,
        pid: parsed.pid,
        domain: None,
        domain_source: None,
    })
}

fn parse_ss_listener_line(line: &str) -> Option<ListenerRow> {
    let parsed = parse_ss_columns(line)?;
    let reach = classify_reach(&parsed.local_ip);
    Some(ListenerRow {
        protocol: parsed.proto,
        local_ip: parsed.local_ip,
        local_port: parsed.local_port,
        process: parsed.process,
        pid: parsed.pid,
        reach,
        reach_label: reach_label(reach),
        is_new: false,
    })
}

struct ParsedSs {
    proto: String,
    state: String,
    local_ip: String,
    local_port: String,
    remote_ip: String,
    remote_port: String,
    process: Option<String>,
    pid: Option<u32>,
}

fn parse_ss_columns(line: &str) -> Option<ParsedSs> {
    let mut parts: Vec<&str> = Vec::new();
    let mut rest_users = None;
    if let Some(idx) = line.find("users:(") {
        parts.extend(line[..idx].split_whitespace());
        rest_users = Some(line[idx..].trim());
    } else {
        parts.extend(line.split_whitespace());
    }
    if parts.len() < 5 {
        return None;
    }
    let (proto_i, state_i, local_i, peer_i) = if looks_like_proto(parts[0]) {
        if parts.len() >= 6 {
            (0, 1, 4, 5)
        } else {
            (0, 1, 2, 3)
        }
    } else if looks_like_state(parts[0]) {
        // ss -tulpn a veces no imprime Netid
        if parts.len() >= 5 {
            (usize::MAX, 0, 3, 4)
        } else {
            return None;
        }
    } else {
        return None;
    };

    let proto = if proto_i == usize::MAX {
        guess_proto_from_state(parts[state_i], parts.get(local_i).copied().unwrap_or(""))
    } else {
        parts[proto_i].to_ascii_lowercase()
    };
    let state = parts[state_i].to_string();
    let (local_ip, local_port) = split_endpoint(parts[local_i]);
    let (remote_ip, remote_port) = split_endpoint(parts[peer_i]);
    let (process, pid) = rest_users
        .or_else(|| parts.get(6).copied())
        .map(parse_users)
        .unwrap_or((None, None));
    Some(ParsedSs {
        proto,
        state,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        process,
        pid,
    })
}

fn looks_like_proto(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "tcp"
            | "udp"
            | "tcp6"
            | "udp6"
            | "raw"
            | "icmp"
            | "icmp6"
            | "sctp"
            | "dccp"
            | "v_str"
            | "p_udp"
            | "u_dgr"
            | "u_seq"
            | "u_str"
    )
}

fn looks_like_state(s: &str) -> bool {
    matches!(
        s,
        "LISTEN"
            | "ESTAB"
            | "ESTABLISHED"
            | "TIME-WAIT"
            | "TIME_WAIT"
            | "CLOSE-WAIT"
            | "FIN-WAIT-1"
            | "FIN-WAIT-2"
            | "SYN-SENT"
            | "SYN-RECV"
            | "LAST-ACK"
            | "CLOSING"
            | "UNCONN"
            | "CLOSE"
    )
}

fn guess_proto_from_state(state: &str, _local: &str) -> String {
    if state == "UNCONN" {
        "udp".into()
    } else {
        "tcp".into()
    }
}

pub fn split_endpoint(s: &str) -> (String, String) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(idx) = rest.rfind("]:") {
            return (strip_iface(&rest[..idx]), rest[idx + 2..].to_string());
        }
    }
    if let Some(idx) = s.rfind(':') {
        let addr = s[..idx].trim_matches(|c| c == '[' || c == ']');
        return (strip_iface(addr), s[idx + 1..].to_string());
    }
    (strip_iface(s), String::new())
}

fn strip_iface(addr: &str) -> String {
    addr.split('%').next().unwrap_or(addr).to_string()
}

pub fn parse_users(s: &str) -> (Option<String>, Option<u32>) {
    let Some(idx) = s.find("users:((") else {
        return (None, None);
    };
    let rest = s[idx + 8..].trim_start_matches('"');
    let name_end = rest.find("\",pid=").or_else(|| rest.find("\","));
    let Some(name_end) = name_end else {
        return (None, None);
    };
    let name = rest[..name_end].to_string();
    let pid = rest[name_end..].split("pid=").nth(1).and_then(|p| {
        p.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()
    });
    let name = if name.is_empty() { None } else { Some(name) };
    (name, pid)
}

pub fn normalize_state(state: &str) -> String {
    match state {
        "ESTAB" => "ESTABLISHED".into(),
        "TIME-WAIT" => "TIME_WAIT".into(),
        "CLOSE-WAIT" => "CLOSE_WAIT".into(),
        "FIN-WAIT-1" => "FIN_WAIT_1".into(),
        "FIN-WAIT-2" => "FIN_WAIT_2".into(),
        "SYN-SENT" => "SYN_SENT".into(),
        "SYN-RECV" => "SYN_RECV".into(),
        "LAST-ACK" => "LAST_ACK".into(),
        other => other.replace('-', "_"),
    }
}

pub fn classify_reach(local_ip: &str) -> Reachability {
    if is_wildcard_addr(local_ip) {
        Reachability::NetworkAll
    } else if is_loopback_addr(local_ip) {
        Reachability::LocalOnly
    } else {
        Reachability::LanAddress
    }
}

pub fn reach_label(reach: Reachability) -> String {
    match reach {
        Reachability::LocalOnly => "solo local (127.0.0.1 / ::1)".into(),
        Reachability::NetworkAll => "alcanzable desde la red (0.0.0.0 / ::)".into(),
        Reachability::LanAddress => "en una IP de esta PC (LAN)".into(),
    }
}

pub fn listener_key(row: &ListenerRow) -> String {
    format!("{}|{}|{}", row.protocol, row.local_ip, row.local_port)
}
