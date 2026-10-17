use std::collections::HashMap;

use super::talkers::classify_talker;
use super::types::DnsDomainRow;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedStats {
    pub queries_total: Option<u64>,
    pub queries_current: Option<u64>,
    pub timeouts: Option<u64>,
    pub cache_hits: Option<u64>,
    pub cache_misses: Option<u64>,
    pub cache_size: Option<u64>,
}

pub fn parse_resolvectl_statistics(text: &str) -> ResolvedStats {
    let mut s = ResolvedStats::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("queries/transactions") || lower.starts_with("queries") {
            let (cur, tot) = two_trailing_nums(line);
            s.queries_current = cur.or(s.queries_current);
            s.queries_total = tot.or(s.queries_total);
        } else if lower.contains("timeouts") {
            let (cur, tot) = two_trailing_nums(line);
            s.timeouts = tot.or(cur);
        } else if lower.contains("cache hits") {
            s.cache_hits = last_num(line);
        } else if lower.contains("cache misses") {
            s.cache_misses = last_num(line);
        } else if lower.contains("current cache size") || lower.contains("cache size") {
            s.cache_size = last_num(line);
        }
    }
    s
}

fn two_trailing_nums(line: &str) -> (Option<u64>, Option<u64>) {
    let nums: Vec<u64> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    match nums.len() {
        0 => (None, None),
        1 => (None, Some(nums[0])),
        _ => (Some(nums[nums.len() - 2]), Some(nums[nums.len() - 1])),
    }
}

fn last_num(line: &str) -> Option<u64> {
    line.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .next_back()
}

/// Extrae FQDN de journal systemd-resolved / resolvectl monitor.
pub fn parse_journal_resolved(text: &str) -> Vec<DnsDomainRow> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for raw in text.lines() {
        for domain in extract_domains(raw) {
            *counts.entry(domain).or_insert(0) += 1;
        }
    }
    rows_from_counts(counts, "journalctl -u systemd-resolved")
}

pub fn parse_resolvectl_monitor_line(line: &str) -> Vec<String> {
    extract_domains(line)
}

/// `resolvectl show-cache` — mapea A/AAAA a nombres.
pub fn parse_resolvectl_cache(text: &str) -> (Vec<DnsDomainRow>, HashMap<String, String>) {
    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut ip_to_name: HashMap<String, String> = HashMap::new();
    let mut current_name: Option<String> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = looks_like_cache_name(line) {
            current_name = Some(name.clone());
            *counts.entry(name).or_insert(0) += 1;
        }
        if let Some(ref name) = current_name {
            for tok in line.split_whitespace() {
                if tok.parse::<std::net::IpAddr>().is_ok() {
                    ip_to_name.insert(tok.to_string(), name.clone());
                }
            }
        }
        for domain in extract_domains(line) {
            *counts.entry(domain).or_insert(0) += 1;
        }
    }
    (
        rows_from_counts(counts, "resolvectl show-cache"),
        ip_to_name,
    )
}

fn looks_like_cache_name(line: &str) -> Option<String> {
    let t = line.trim().trim_end_matches('.');
    if t.contains(' ') {
        // "www.google.com IN A 142.250.0.1"
        let first = t.split_whitespace().next()?;
        if is_domain(first) {
            return Some(first.trim_end_matches('.').to_ascii_lowercase());
        }
        return None;
    }
    if is_domain(t) {
        Some(t.to_ascii_lowercase())
    } else {
        None
    }
}

fn rows_from_counts(counts: HashMap<String, u64>, source: &str) -> Vec<DnsDomainRow> {
    let mut rows: Vec<DnsDomainRow> = counts
        .into_iter()
        .map(|(domain, count)| {
            let talker = classify_talker(&domain);
            DnsDomainRow {
                domain,
                count,
                source: source.into(),
                talker,
            }
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.domain.cmp(&b.domain)));
    rows
}

fn extract_domains(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in line.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '=' | '<' | '>'
            )
    }) {
        let tok = tok.trim().trim_end_matches('.');
        if is_domain(tok) {
            let d = tok.to_ascii_lowercase();
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    out
}

pub fn is_noise_domain(s: &str) -> bool {
    let d = s.trim_end_matches('.').to_ascii_lowercase();
    d == "arpa"
        || d.ends_with(".arpa")
        || d == "local"
        || d.ends_with(".local")
        || d == "localhost"
        || d.ends_with(".localhost")
        || d == "invalid"
        || d.ends_with(".invalid")
        || d == "home.arpa"
        || d.ends_with(".home.arpa")
}

fn is_domain(s: &str) -> bool {
    if s.len() < 4 || s.len() > 253 || !s.contains('.') {
        return false;
    }
    if s.starts_with('.') || s.contains("..") {
        return false;
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    if is_noise_domain(s) {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = labels.last().copied().unwrap_or("");
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !matches!(tld, "pid" | "fd" | "ms" | "est" | "skb" | "arpa")
}

pub fn merge_domain_rows(mut rows: Vec<DnsDomainRow>) -> Vec<DnsDomainRow> {
    let mut map: HashMap<String, DnsDomainRow> = HashMap::new();
    for row in rows.drain(..) {
        map.entry(row.domain.clone())
            .and_modify(|e| {
                e.count += row.count;
                if !e.source.contains(&row.source) {
                    e.source = format!("{}; {}", e.source, row.source);
                }
                if e.talker.is_none() {
                    e.talker = row.talker.clone();
                }
            })
            .or_insert(row);
    }
    let mut out: Vec<_> = map.into_values().collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.domain.cmp(&b.domain)));
    out
}
