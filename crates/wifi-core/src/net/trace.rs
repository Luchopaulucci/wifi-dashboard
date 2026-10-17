use super::addr::{is_private_or_local, is_public_ip, parse_ip_opt};
use super::types::{TraceHop, TraceHopKind};

pub fn parse_trace_line(line: &str) -> Option<TraceHop> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    if is_trace_header(&lower, line) {
        return parse_tracepath_localhost(line);
    }
    // Ubuntu default is tracepath: " 1:", " 1?:". traceroute uses " 1  host".
    if looks_like_tracepath(line) {
        parse_tracepath_hop(line)
    } else {
        parse_traceroute_hop(line)
    }
}

fn is_trace_header(lower: &str, line: &str) -> bool {
    lower.starts_with("traceroute")
        || lower.starts_with("tracepath")
        || lower.starts_with("resume:")
        || lower.contains("hops max")
        || (lower.contains("pmtu") && line.contains("LOCALHOST") && !looks_like_tracepath(line))
}

fn looks_like_tracepath(line: &str) -> bool {
    let t = line.trim();
    let Some((num, _rest)) = t.split_once(':') else {
        return false;
    };
    let num = num.trim().trim_end_matches('?');
    num.parse::<u32>().is_ok()
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
    let hop: u32 = toks.next()?.parse().ok()?;
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
    let (address, hostname) = addr_and_host(&rest);
    let rtt_ms = rtt_from_tokens(&rest);
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
    // " 4:  10.0.0.1                                            8.05ms pmtu 1492"
    // " 5:  181.1.1.1                                          12.3ms asymm  9"
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
    let toks: Vec<&str> = rest.split_whitespace().collect();
    let (address, hostname) = addr_and_host(&toks);
    let rtt_ms = rtt_from_tokens(&toks);
    let lost = address.is_none() && rtt_ms.is_none() && hostname.is_none();
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

fn addr_and_host(toks: &[&str]) -> (Option<String>, Option<String>) {
    let mut address = None;
    let mut hostname = None;
    let mut skip_next = false;
    for tok in toks {
        if skip_next {
            skip_next = false;
            continue;
        }
        if is_meta_keyword(tok) {
            skip_next = true;
            continue;
        }
        if *tok == "*" || tok.eq_ignore_ascii_case("ms") || tok.eq_ignore_ascii_case("reached") {
            continue;
        }
        let cleaned = tok.trim_matches(|c| c == '(' || c == ')' || c == ',');
        if looks_like_rtt_token(cleaned) {
            continue;
        }
        if let Some(ip) = parse_ip_opt(cleaned) {
            address = Some(ip.to_string());
        } else if looks_host(cleaned) && hostname.is_none() {
            hostname = Some(cleaned.to_string());
        }
    }
    (address, hostname)
}

/// RTT only from `12.3ms` or `12.3 ms`. Bare numbers (`pmtu 1492`, `asymm 9`) are not RTT.
fn rtt_from_tokens(toks: &[&str]) -> Option<f64> {
    let mut skip_next = false;
    for (i, tok) in toks.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if is_meta_keyword(tok) {
            skip_next = true;
            continue;
        }
        if tok.eq_ignore_ascii_case("ms") {
            if i > 0 {
                if let Ok(n) = toks[i - 1].parse::<f64>() {
                    if is_plausible_rtt(n) {
                        return Some(n);
                    }
                }
            }
            continue;
        }
        if let Some(n) = parse_ms_token(tok) {
            if is_plausible_rtt(n) {
                return Some(n);
            }
        }
    }
    None
}

fn is_meta_keyword(tok: &str) -> bool {
    matches!(
        tok.to_ascii_lowercase().as_str(),
        "pmtu" | "asymm" | "hops" | "back" | "resume"
    )
}

fn looks_like_rtt_token(tok: &str) -> bool {
    parse_ms_token(tok).is_some() || tok.parse::<f64>().is_ok()
}

fn parse_ms_token(tok: &str) -> Option<f64> {
    let t = tok.trim_end_matches(',').trim();
    let lower = t.to_ascii_lowercase();
    let stripped = lower.strip_suffix("ms")?;
    if stripped.is_empty() {
        return None;
    }
    stripped.parse().ok()
}

fn is_plausible_rtt(n: f64) -> bool {
    n > 0.0 && n < 60_000.0
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

fn looks_host(s: &str) -> bool {
    let s = s.trim_matches(|c| c == '(' || c == ')' || c == ',');
    if s.is_empty() || !s.is_ascii() {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    if is_meta_keyword(s)
        || lower == "reached"
        || lower == "ms"
        || lower == "no"
        || lower == "reply"
        || lower.ends_with("ms")
    {
        return false;
    }
    if parse_ip_opt(s).is_some() {
        return false;
    }
    s.contains('.') && !s.chars().all(|c| c.is_ascii_digit() || c == '.')
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmtu_and_asymm_are_not_rtt() {
        let pmtu = parse_trace_line(
            " 2:  10.0.0.1                                              8.050ms pmtu 1492",
        )
        .unwrap();
        assert_eq!(pmtu.address.as_deref(), Some("10.0.0.1"));
        assert_eq!(pmtu.rtt_ms, Some(8.050));
        assert_ne!(pmtu.rtt_ms, Some(1492.0));
        assert!(pmtu.hostname.is_none());

        let asymm = parse_trace_line(
            " 4:  181.15.1.1                                           12.300ms asymm  9",
        )
        .unwrap();
        assert_eq!(asymm.rtt_ms, Some(12.300));
        assert_ne!(asymm.rtt_ms, Some(9.0));

        let ms_host =
            parse_trace_line(" 1:  192.168.0.1                                           1.234ms")
                .unwrap();
        assert_eq!(ms_host.hostname, None);
        assert_eq!(ms_host.rtt_ms, Some(1.234));
    }

    #[test]
    fn no_reply_is_lost() {
        let hop = parse_trace_line(" 3:  no reply").unwrap();
        assert!(hop.lost);
        assert!(hop.address.is_none());
        assert!(hop.rtt_ms.is_none());
    }
}
