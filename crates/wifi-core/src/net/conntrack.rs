use super::types::NatTranslation;

/// Parsea `conntrack -L` o `/proc/net/nf_conntrack`.
pub fn parse_conntrack(text: &str) -> Vec<NatTranslation> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(row) = parse_conntrack_line(line) {
            out.push(row);
        }
    }
    out
}

fn parse_conntrack_line(line: &str) -> Option<NatTranslation> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 4 {
        return None;
    }
    let mut i = 0;
    // nf_conntrack: ipv4 2 tcp 6 431999 ESTABLISHED src=...
    if tokens[0] == "ipv4" || tokens[0] == "ipv6" {
        i = 2;
    }
    let protocol = tokens.get(i)?.to_ascii_lowercase();
    i += 1;
    if tokens
        .get(i)
        .is_some_and(|t| t.chars().all(|c| c.is_ascii_digit()))
    {
        i += 1; // protonum
    }
    let mut timeout_secs = None;
    if let Some(t) = tokens.get(i) {
        if let Ok(n) = t.parse::<u64>() {
            timeout_secs = Some(n);
            i += 1;
        }
    }
    let mut state = None;
    if let Some(t) = tokens.get(i) {
        if t.chars().all(|c| c.is_ascii_alphabetic() || c == '_') && !t.contains('=') {
            state = Some((*t).to_string());
            i += 1;
        }
    }

    let rest = tokens[i..].join(" ");
    let orig_src = kv(&rest, "src").or_else(|| nth_kv(&rest, "src", 0))?;
    let orig_dst = kv(&rest, "dst").or_else(|| nth_kv(&rest, "dst", 0))?;
    let orig_sport = nth_kv(&rest, "sport", 0).unwrap_or_else(|| "*".into());
    let orig_dport = nth_kv(&rest, "dport", 0).unwrap_or_else(|| "*".into());
    let reply_src = nth_kv(&rest, "src", 1).unwrap_or_else(|| orig_dst.clone());
    let reply_dst = nth_kv(&rest, "dst", 1).unwrap_or_else(|| orig_src.clone());
    let reply_sport = nth_kv(&rest, "sport", 1).unwrap_or_else(|| orig_dport.clone());
    let reply_dport = nth_kv(&rest, "dport", 1).unwrap_or_else(|| orig_sport.clone());

    let snat = orig_src != reply_dst || orig_sport != reply_dport;
    let dnat = orig_dst != reply_src || orig_dport != reply_sport;
    let tagged_snat = rest.contains("[SNAT]");
    let tagged_dnat = rest.contains("[DNAT]");
    let nat_kind = if tagged_snat && tagged_dnat {
        "SNAT+DNAT"
    } else if tagged_snat || snat && !dnat {
        "SNAT"
    } else if tagged_dnat || dnat && !snat {
        "DNAT"
    } else if snat && dnat {
        "SNAT+DNAT"
    } else {
        "ninguno"
    };

    Some(NatTranslation {
        protocol,
        internal_ip: orig_src,
        internal_port: orig_sport,
        translated_ip: reply_dst,
        translated_port: reply_dport,
        dest_ip: orig_dst,
        dest_port: orig_dport,
        state,
        timeout_secs,
        nat_kind: nat_kind.into(),
        assured: rest.contains("[ASSURED]"),
    })
}

fn kv(text: &str, key: &str) -> Option<String> {
    nth_kv(text, key, 0)
}

fn nth_kv(text: &str, key: &str, n: usize) -> Option<String> {
    let needle = format!("{key}=");
    let mut seen = 0usize;
    let mut rest = text;
    loop {
        let idx = rest.find(&needle)?;
        let after = &rest[idx + needle.len()..];
        let val: String = after
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ']')
            .collect();
        if seen == n {
            return Some(val);
        }
        seen += 1;
        rest = after;
    }
}
