use super::addr::{is_private_or_local, is_public_ip, parse_ip_opt};
use super::types::{TraceHop, TraceHopKind};

pub fn parse_trace_line(line: &str) -> Option<TraceHop> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("traceroute")
        || lower.starts_with("tracepath")
        || lower.starts_with("resume:")
        || lower.contains("hops max")
        || lower.contains("pmtu") && line.contains("LOCALHOST")
    {
        return parse_tracepath_localhost(line);
    }
    parse_traceroute_hop(line).or_else(|| parse_tracepath_hop(line))
}

fn parse_tracepath_localhost(line: &str) -> Option<TraceHop> {
    let t = line.trim();
    if t.contains("[LOCALHOST]") {
        return Some(TraceHop {
            hop: 0,
            address: Some("127.0.0.1".into()),
            hostname: Some("LOCALHOST".into()),
            rtt_ms: None,
            lost: false,
            kind: TraceHopKind::Localhost,
        });
    }
    None
}

fn parse_traceroute_hop(line: &str) -> Option<TraceHop> {
    let t = line.trim();
    // " 1  192.168.0.1  1.234 ms"
    // " 2  *"
    // " 3  gate.isp.net (181.1.1.1)  12.3 ms"
    let mut toks = t.split_whitespace();
    let hop: u32 = toks.next()?.trim_end_matches(':').parse().ok()?;
    let rest: Vec<&str> = toks.collect();
    if rest.is_empty() {
        return Some(lost_hop(hop));
    }
    let joined = rest.join(" ");
    if rest.iter().all(|x| *x == "*" || *x == "ms") || joined.replace('*', "").trim().is_empty() {
        return Some(lost_hop(hop));
    }
    if rest.contains(&"*")
        && !rest
            .iter()
            .any(|x| parse_ip_opt(x).is_some() || looks_host(x))
    {
        return Some(lost_hop(hop));
    }
    let mut address = None;
    let mut hostname = None;
    for tok in &rest {
        if *tok == "*" || *tok == "ms" {
            continue;
        }
        if tok.parse::<f64>().is_ok() {
            continue;
        }
        let cleaned = tok.trim_matches(|c| c == '(' || c == ')' || c == ',');
        if let Some(ip) = parse_ip_opt(cleaned) {
            address = Some(ip.to_string());
        } else if looks_host(cleaned) && hostname.is_none() {
            hostname = Some(cleaned.to_string());
        }
    }
    let rtt_ms = first_rtt(&rest);
    let lost = address.is_none() && rtt_ms.is_none();
    Some(TraceHop {
        hop,
        address,
        hostname,
        rtt_ms,
        lost,
        kind: if lost {
            TraceHopKind::Lost
        } else {
            TraceHopKind::Transit
        },
    })
}

fn parse_tracepath_hop(line: &str) -> Option<TraceHop> {
    // " 1:  192.168.0.1                                           1.234ms"
    // " 2:  no reply"
    // " 3:  181.x.x.x                                           12.3ms reached"
    let t = line.trim();
    let (num, rest) = t.split_once(':')?;
    let hop: u32 = num.trim().trim_end_matches('?').parse().ok()?;
    let rest = rest.trim();
    if rest.is_empty() || rest.to_ascii_lowercase().contains("no reply") {
        return Some(lost_hop(hop));
    }
    if rest.contains("[LOCALHOST]") {
        return Some(TraceHop {
            hop,
            address: Some("127.0.0.1".into()),
            hostname: Some("LOCALHOST".into()),
            rtt_ms: None,
            lost: false,
            kind: TraceHopKind::Localhost,
        });
    }
    let mut address = None;
    let mut hostname = None;
    for tok in rest.split_whitespace() {
        if tok.eq_ignore_ascii_case("reached") || tok.starts_with("pmtu") {
            continue;
        }
        let cleaned = tok.trim_end_matches("ms");
        if cleaned.parse::<f64>().is_ok() {
            continue;
        }
        if let Some(ip) = parse_ip_opt(tok) {
            address = Some(ip.to_string());
        } else if looks_host(tok) {
            hostname = Some(tok.to_string());
        }
    }
    let rtt_ms = rest.split_whitespace().find_map(|tok| {
        tok.trim_end_matches("ms")
            .parse::<f64>()
            .ok()
            .filter(|n| *n > 0.0 && *n < 60_000.0)
    });
    Some(TraceHop {
        hop,
        address,
        hostname,
        rtt_ms,
        lost: false,
        kind: TraceHopKind::Transit,
    })
}

fn lost_hop(hop: u32) -> TraceHop {
    TraceHop {
        hop,
        address: None,
        hostname: None,
        rtt_ms: None,
        lost: true,
        kind: TraceHopKind::Lost,
    }
}

fn first_rtt(toks: &[&str]) -> Option<f64> {
    let mut prev: Option<f64> = None;
    for tok in toks {
        if tok.eq_ignore_ascii_case("ms") {
            return prev;
        }
        if let Ok(n) = tok.trim_end_matches("ms").parse::<f64>() {
            prev = Some(n);
        }
    }
    prev.filter(|n| *n > 0.0 && *n < 60_000.0)
}

fn looks_host(s: &str) -> bool {
    s.contains('.') && !s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.is_ascii()
}

pub fn classify_hops(hops: &mut [TraceHop], gateway: Option<&str>, dest: &str) {
    let mut saw_public = false;
    for hop in hops.iter_mut() {
        if hop.lost || hop.kind == TraceHopKind::Localhost {
            hop.kind = if hop.kind == TraceHopKind::Localhost {
                TraceHopKind::Localhost
            } else {
                TraceHopKind::Lost
            };
            continue;
        }
        let addr = hop.address.as_deref();
        if dest_matches(addr, dest) {
            hop.kind = TraceHopKind::Destination;
            continue;
        }
        if (gateway.is_some() && addr == gateway)
            || (hop.hop == 1
                && addr.is_some_and(|a| parse_ip_opt(a).is_some_and(is_private_or_local)))
        {
            hop.kind = TraceHopKind::HomeRouter;
            continue;
        }
        if let Some(ip) = addr.and_then(parse_ip_opt) {
            if is_public_ip(ip) {
                if !saw_public {
                    hop.kind = TraceHopKind::IspStart;
                    saw_public = true;
                } else {
                    hop.kind = TraceHopKind::Transit;
                }
            } else {
                hop.kind = TraceHopKind::Private;
            }
        }
    }
}

fn dest_matches(addr: Option<&str>, dest: &str) -> bool {
    let Some(addr) = addr else {
        return false;
    };
    addr == dest || parse_ip_opt(addr) == parse_ip_opt(dest)
}
