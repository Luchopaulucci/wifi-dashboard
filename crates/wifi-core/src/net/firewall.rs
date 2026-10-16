use super::criollo::explain_rule_criollo;
use super::types::{FirewallChain, FirewallRule, FirewallTable};

pub fn parse_nft_ruleset(text: &str) -> Vec<FirewallTable> {
    let mut tables = Vec::new();
    let mut cur_table: Option<FirewallTable> = None;
    let mut cur_chain: Option<FirewallChain> = None;
    let mut depth = 0i32;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let opens = line.chars().filter(|c| *c == '{').count() as i32;
        let closes = line.chars().filter(|c| *c == '}').count() as i32;

        if let Some(rest) = line.strip_prefix("table ") {
            flush_chain(&mut cur_table, &mut cur_chain);
            if let Some(t) = cur_table.take() {
                tables.push(t);
            }
            let (family, name) = parse_table_header(rest);
            cur_table = Some(FirewallTable {
                name,
                family,
                chains: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("chain ") {
            flush_chain(&mut cur_table, &mut cur_chain);
            let name = rest
                .split_whitespace()
                .next()
                .unwrap_or("?")
                .trim_matches('{')
                .to_string();
            cur_chain = Some(FirewallChain {
                name,
                hook: None,
                policy: None,
                policy_packets: None,
                policy_bytes: None,
                rules: Vec::new(),
            });
        } else if line.starts_with("type ") || (line.contains("hook") && line.contains("policy")) {
            if let Some(ch) = cur_chain.as_mut() {
                ch.hook = extract_after(line, "hook");
                ch.policy =
                    extract_after(line, "policy").map(|s| s.trim_end_matches(';').to_string());
            }
        } else if line == "}" {
            if depth <= 1 {
                flush_chain(&mut cur_table, &mut cur_chain);
            }
        } else if cur_chain.is_some() && !line.starts_with("table ") {
            let cleaned = line.trim_end_matches(';').trim();
            if !cleaned.is_empty() && cleaned != "{" {
                let (packets, bytes) = extract_counter(cleaned);
                let verdict = extract_verdict(cleaned);
                let table_name = cur_table
                    .as_ref()
                    .map(|t| t.name.clone())
                    .unwrap_or_default();
                let family = cur_table.as_ref().and_then(|t| t.family.clone());
                let chain_name = cur_chain
                    .as_ref()
                    .map(|c| c.name.clone())
                    .unwrap_or_default();
                if let Some(ch) = cur_chain.as_mut() {
                    ch.rules.push(FirewallRule {
                        table: table_name,
                        family,
                        chain: chain_name,
                        handle: extract_after(cleaned, "handle"),
                        text: cleaned.to_string(),
                        criollo: explain_rule_criollo(cleaned),
                        packets,
                        bytes,
                        verdict,
                    });
                }
            }
        }

        depth += opens - closes;
        if depth < 0 {
            depth = 0;
        }
    }
    flush_chain(&mut cur_table, &mut cur_chain);
    if let Some(t) = cur_table.take() {
        tables.push(t);
    }
    tables
}

fn flush_chain(table: &mut Option<FirewallTable>, chain: &mut Option<FirewallChain>) {
    if let (Some(t), Some(c)) = (table.as_mut(), chain.take()) {
        t.chains.push(c);
    }
}

fn parse_table_header(rest: &str) -> (Option<String>, String) {
    let rest = rest.trim().trim_end_matches('{').trim();
    let mut parts = rest.split_whitespace();
    let a = parts.next().unwrap_or("filter");
    if let Some(b) = parts.next() {
        (Some(a.to_string()), b.to_string())
    } else {
        (None, a.to_string())
    }
}

fn extract_after(line: &str, key: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find(&key.to_ascii_lowercase())?;
    let after = line[idx + key.len()..].trim_start();
    let tok: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ';' && *c != ',')
        .collect();
    if tok.is_empty() {
        None
    } else {
        Some(tok.trim_matches('"').to_string())
    }
}

pub fn extract_counter(text: &str) -> (Option<u64>, Option<u64>) {
    // nft: counter packets 12 bytes 34
    // iptables-save -c: [12:34]
    if let Some(idx) = text.find('[') {
        if let Some(end) = text[idx + 1..].find(']') {
            let inner = &text[idx + 1..idx + 1 + end];
            if let Some((a, b)) = inner.split_once(':') {
                return (a.trim().parse().ok(), b.trim().parse().ok());
            }
        }
    }
    let packets = find_num_after(text, "packets");
    let bytes = find_num_after(text, "bytes");
    (packets, bytes)
}

fn find_num_after(text: &str, key: &str) -> Option<u64> {
    let lower = text.to_ascii_lowercase();
    let idx = lower.find(key)?;
    let after = text[idx + key.len()..].trim_start();
    after
        .split_whitespace()
        .next()
        .and_then(|s| s.trim_end_matches(',').parse().ok())
}

pub fn extract_verdict(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    for v in [
        "masquerade",
        "redirect",
        "accept",
        "drop",
        "reject",
        "return",
        "dnat",
        "snat",
        "queue",
        "log",
    ] {
        if lower.split_whitespace().any(|w| w.trim_matches(';') == v)
            || lower.contains(&format!("-j {v}"))
            || lower.ends_with(v)
        {
            return Some(v.to_string());
        }
    }
    if let Some(idx) = lower.rfind(" -j ") {
        let t = text[idx + 4..].split_whitespace().next()?;
        return Some(t.to_string());
    }
    None
}

/// iptables-save / iptables-save -c / iptables -S
pub fn parse_iptables_save(text: &str) -> Vec<FirewallTable> {
    let mut tables = Vec::new();
    let mut cur: Option<FirewallTable> = None;
    let mut chain_order: Vec<String> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('*') {
            if let Some(t) = cur.take() {
                tables.push(reorder_table(t, &chain_order));
            }
            chain_order.clear();
            cur = Some(FirewallTable {
                name: name.to_string(),
                family: Some("ip".into()),
                chains: Vec::new(),
            });
        } else if line.starts_with(':') {
            // :INPUT DROP [10:400]
            let rest = line.trim_start_matches(':');
            let mut parts = rest.split_whitespace();
            let name = parts.next().unwrap_or("?").to_string();
            let policy = parts.next().map(|s| s.to_string());
            let counters = parts.next().unwrap_or("");
            let (pkts, bytes) = extract_counter(counters);
            chain_order.push(name.clone());
            if let Some(t) = cur.as_mut() {
                t.chains.push(FirewallChain {
                    name,
                    hook: None,
                    policy,
                    policy_packets: pkts,
                    policy_bytes: bytes,
                    rules: Vec::new(),
                });
            }
        } else if line.eq_ignore_ascii_case("COMMIT") {
            if let Some(t) = cur.take() {
                tables.push(reorder_table(t, &chain_order));
            }
            chain_order.clear();
        } else if line.starts_with("-A ")
            || line.starts_with("-I ")
            || line.starts_with("[")
            || line.starts_with("-P ")
        {
            let (packets, bytes) = extract_counter(line);
            let stripped = strip_counter_prefix(line);
            let chain = iptables_chain_name(&stripped);
            let verdict = extract_verdict(&stripped);
            let family = cur.as_ref().and_then(|t| t.family.clone());
            let table_name = cur.as_ref().map(|t| t.name.clone()).unwrap_or_default();
            let rule = FirewallRule {
                table: table_name,
                family,
                chain: chain.clone(),
                handle: None,
                text: stripped.clone(),
                criollo: explain_rule_criollo(&stripped),
                packets,
                bytes,
                verdict,
            };
            if let Some(t) = cur.as_mut() {
                if let Some(ch) = t.chains.iter_mut().find(|c| c.name == chain) {
                    ch.rules.push(rule);
                } else {
                    t.chains.push(FirewallChain {
                        name: chain,
                        hook: None,
                        policy: None,
                        policy_packets: None,
                        policy_bytes: None,
                        rules: vec![rule],
                    });
                }
            }
        }
    }
    if let Some(t) = cur.take() {
        tables.push(reorder_table(t, &chain_order));
    }
    tables
}

fn strip_counter_prefix(line: &str) -> String {
    let line = line.trim();
    if line.starts_with('[') {
        if let Some(idx) = line.find(']') {
            return line[idx + 1..].trim().to_string();
        }
    }
    line.to_string()
}

fn iptables_chain_name(line: &str) -> String {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("-A") | Some("-I") | Some("-D") => parts.next().unwrap_or("?").to_string(),
        Some("-P") => parts.next().unwrap_or("?").to_string(),
        _ => "?".into(),
    }
}

fn reorder_table(table: FirewallTable, order: &[String]) -> FirewallTable {
    let _ = order;
    table
}

pub fn summarize_verdicts(tables: &[FirewallTable]) -> (u64, u64, u64, u64) {
    let mut acc_p = 0u64;
    let mut acc_b = 0u64;
    let mut drop_p = 0u64;
    let mut drop_b = 0u64;
    for t in tables {
        for c in &t.chains {
            let pol = c.policy.as_deref().unwrap_or("").to_ascii_lowercase();
            if pol == "drop" || pol == "reject" {
                drop_p += c.policy_packets.unwrap_or(0);
                drop_b += c.policy_bytes.unwrap_or(0);
            } else if pol == "accept" {
                acc_p += c.policy_packets.unwrap_or(0);
                acc_b += c.policy_bytes.unwrap_or(0);
            }
            for r in &c.rules {
                let v = r.verdict.as_deref().unwrap_or("").to_ascii_lowercase();
                if v == "accept" {
                    acc_p += r.packets.unwrap_or(0);
                    acc_b += r.bytes.unwrap_or(0);
                } else if v == "drop" || v == "reject" {
                    drop_p += r.packets.unwrap_or(0);
                    drop_b += r.bytes.unwrap_or(0);
                }
            }
        }
    }
    (acc_p, acc_b, drop_p, drop_b)
}
