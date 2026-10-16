/// Explica una regla nft/iptables en castellano rioplatense, nivel curso de redes.
pub fn explain_rule_criollo(text: &str) -> String {
    let t = text.trim();
    if t.is_empty() {
        return "Regla vacía.".into();
    }
    let lower = t.to_ascii_lowercase();
    let mut bits: Vec<String> = Vec::new();

    if lower.starts_with("-p ") || lower.contains(" -p ") {
        // iptables
    }

    if let Some(pol) = policy_of(&lower) {
        bits.push(format!("Política de la cadena: si nada coincide, {pol}."));
    }

    if lower.contains("ct state")
        || lower.contains("conntrack --ctstate")
        || lower.contains("-m state")
    {
        if lower.contains("established") && lower.contains("related") {
            bits.push("Deja pasar (o mira) lo que ya es una conversación abierta y lo relacionado, tipo FTP helper: la respuesta a algo que pediste vos.".into());
        } else if lower.contains("established") {
            bits.push(
                "Aplica a conexiones que ya están establecidas (el ida y vuelta que ya arrancó)."
                    .into(),
            );
        } else if lower.contains("invalid") {
            bits.push(
                "Caza paquetes que el kernel considera inválidos para el estado de la conexión."
                    .into(),
            );
        } else if lower.contains("new") {
            bits.push("Aplica a conexiones nuevas (el primer paquete, el SYN).".into());
        }
    }

    if lower.contains("iifname")
        || lower.contains("iif \"")
        || lower.contains("iif {")
        || has_flag(&lower, "-i ")
    {
        if lower.contains("lo") || lower.contains("\"lo\"") {
            bits.push("Entra por loopback: la PC hablándose a sí misma.".into());
        } else if let Some(name) = extract_quoted(t, "iifname").or_else(|| extract_quoted(t, "iif"))
        {
            bits.push(format!("Solo si entra por la interfaz {name}."));
        } else {
            bits.push("Filtra por interfaz de entrada.".into());
        }
    }
    if lower.contains("oifname") || lower.contains("oif \"") || has_flag(&lower, "-o ") {
        if let Some(name) = extract_quoted(t, "oifname").or_else(|| extract_quoted(t, "oif")) {
            bits.push(format!("Solo si sale por {name}."));
        } else {
            bits.push("Filtra por interfaz de salida.".into());
        }
    }

    if let Some(port) = dport(&lower, t) {
        let proto = proto_of(&lower);
        bits.push(format!(
            "Puerto de destino {port} ({proto}{}).",
            service_hint(&port)
        ));
    }
    if let Some(port) = sport(&lower, t) {
        bits.push(format!("Puerto de origen {port}."));
    }

    if let Some(cidr) = after_token(t, "saddr").or_else(|| iptables_s(&lower, t)) {
        bits.push(format!("Dirección de origen {cidr}."));
    }
    if let Some(cidr) = after_token(t, "daddr").or_else(|| iptables_d(&lower, t)) {
        bits.push(format!("Dirección de destino {cidr}."));
    }

    if lower.contains("tcp flags") || lower.contains("--tcp-flags") {
        bits.push(
            "Mira flags TCP (SYN/ACK/FIN/RST): típico para detectar el handshake o scans.".into(),
        );
    }
    if lower.contains("limit") || lower.contains("rate") {
        bits.push("Tiene un límite de tasa: no deja que te inunden de paquetes iguales.".into());
    }
    if lower.contains("icmp") || lower.contains("icmpv6") {
        bits.push("Habla de ICMP (ping, 'destination unreachable', etc.).".into());
    }
    if lower.contains("skuid") || lower.contains("--uid-owner") {
        bits.push("Filtra según el usuario de Linux que originó el paquete.".into());
    }
    if lower.contains("fib") {
        bits.push(
            "Consulta la tabla de ruteo (fib) para decidir si esa IP es local, ruteable, etc."
                .into(),
        );
    }
    if lower.contains("masquerade") {
        bits.push("Masquerade/SNAT: cuando sale, disfraza la IP interna con la IP pública de la interfaz. Es el NAT clásico del router.".into());
    } else if lower.contains("snat") {
        bits.push("SNAT: reescribe la IP de origen (cómo te ven afuera).".into());
    }
    if lower.contains("dnat") {
        bits.push("DNAT: reescribe el destino (port-forward: 'este puerto de afuera va a esta IP de adentro').".into());
    }
    if lower.contains("redirect") {
        bits.push(
            "Redirect: manda el paquete a un puerto local (típico de proxies transparentes)."
                .into(),
        );
    }
    if lower.contains("reject") {
        bits.push("Reject: no solo lo tira, avisa con un ICMP o RST. El otro se entera.".into());
    } else if lower.contains("drop") {
        bits.push(
            "Drop: lo tira a la basura, sin avisar. Para el otro es un agujero negro.".into(),
        );
    }
    if lower.contains("accept") && !lower.contains("counter accept") {
        bits.push("Accept: lo deja pasar.".into());
    }
    if lower.contains("return") {
        bits.push("Return: vuelve a la cadena que llamó (como un 'return' de función).".into());
    }
    if lower.contains("jump")
        || lower.contains("goto")
        || lower.contains(" -j ") && looks_like_custom_jump(&lower)
    {
        if let Some(chain) = jump_target(t) {
            bits.push(format!("Salta a la cadena {chain} (subrutina de reglas)."));
        }
    }
    if lower.contains("log") || lower.contains("nflog") {
        bits.push("Log: deja un rastro en el journal/dmesg, no decide solo si pasa o no.".into());
    }
    if lower.contains("counter") || lower.contains("pkts") {
        bits.push(
            "Tiene contador de paquetes/bytes: sirve para ver si la regla se está usando.".into(),
        );
    }
    if lower.contains("comment") {
        if let Some(c) = comment_of(t) {
            bits.push(format!("Comentario de quien la escribió: {c}."));
        }
    }
    if lower.contains("related,established") || lower.contains("established,related") {
        // already covered
    }
    if lower.contains("hook input") {
        bits.push("Gancho input: tráfico que entra a esta máquina.".into());
    }
    if lower.contains("hook output") {
        bits.push("Gancho output: tráfico que sale de esta máquina.".into());
    }
    if lower.contains("hook forward") {
        bits.push("Gancho forward: tráfico que esta máquina rutea (de una interfaz a otra). En una notebook casi no se usa.".into());
    }
    if lower.contains("hook prerouting") {
        bits.push(
            "Gancho prerouting: se aplica antes de decidir el ruteo (ahí vive el DNAT).".into(),
        );
    }
    if lower.contains("hook postrouting") {
        bits.push(
            "Gancho postrouting: se aplica cuando ya va a salir (ahí vive el SNAT/masquerade)."
                .into(),
        );
    }

    if bits.is_empty() {
        bits.push(format!(
            "Regla cruda del firewall: `{t}`. En criollo, es un filtro sobre paquetes; si no reconocemos el dialecto, mirá el texto a la izquierda."
        ));
    }
    bits.join(" ")
}

fn policy_of(lower: &str) -> Option<&'static str> {
    if lower.contains("policy drop")
        || lower.contains("-p drop")
        || lower.contains(": drop")
        || (lower.contains("policy") && lower.contains("drop") && lower.contains("type filter"))
    {
        Some("se descarta (drop)")
    } else if lower.contains("policy accept") {
        Some("se acepta")
    } else {
        None
    }
}

fn proto_of(lower: &str) -> &'static str {
    if lower.contains("udp") {
        "UDP"
    } else if lower.contains("tcp") {
        "TCP"
    } else {
        "IP"
    }
}

fn service_hint(port: &str) -> String {
    match port {
        "22" => " SSH".into(),
        "53" => " DNS".into(),
        "67" | "68" => " DHCP".into(),
        "80" => " HTTP".into(),
        "123" => " NTP".into(),
        "443" => " HTTPS".into(),
        "853" => " DNS-over-TLS".into(),
        "5353" => " mDNS".into(),
        "631" => " CUPS/impresora".into(),
        _ => String::new(),
    }
}

fn dport(lower: &str, orig: &str) -> Option<String> {
    after_token(orig, "dport")
        .or_else(|| after_token(orig, "--dport"))
        .or_else(|| after_flag(lower, orig, "--dport"))
}

fn sport(lower: &str, orig: &str) -> Option<String> {
    after_token(orig, "sport").or_else(|| after_flag(lower, orig, "--sport"))
}

fn after_token(text: &str, key: &str) -> Option<String> {
    let mut search_from = 0;
    let lower = text.to_ascii_lowercase();
    let key_l = key.to_ascii_lowercase();
    loop {
        let rel = lower[search_from..].find(&key_l)?;
        let idx = search_from + rel;
        let after = text[idx + key.len()..].trim_start();
        let after = after.strip_prefix('=').unwrap_or(after).trim_start();
        let tok: String = after
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ',' && *c != ';' && *c != ')')
            .collect();
        if !tok.is_empty() && tok != "{" {
            return Some(tok.trim_matches('"').to_string());
        }
        search_from = idx + key.len();
    }
}

fn after_flag<'a>(lower: &'a str, orig: &'a str, flag: &str) -> Option<String> {
    let idx = lower.find(flag)?;
    let after = orig[idx + flag.len()..].trim_start();
    let tok: String = after.chars().take_while(|c| !c.is_whitespace()).collect();
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

fn extract_quoted(text: &str, key: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let idx = lower.find(&key.to_ascii_lowercase())?;
    let after = text[idx + key.len()..].trim_start();
    if let Some(rest) = after.strip_prefix('"') {
        return rest.split('"').next().map(|s| s.to_string());
    }
    after
        .split_whitespace()
        .next()
        .map(|s| s.trim_matches('"').to_string())
}

fn has_flag(lower: &str, flag: &str) -> bool {
    lower.contains(flag)
}

fn iptables_s(lower: &str, orig: &str) -> Option<String> {
    if lower.contains(" -s ") {
        after_flag(lower, orig, "-s ")
    } else {
        None
    }
}

fn iptables_d(lower: &str, orig: &str) -> Option<String> {
    if lower.contains(" -d ") {
        after_flag(lower, orig, "-d ")
    } else {
        None
    }
}

fn looks_like_custom_jump(lower: &str) -> bool {
    !lower.contains("-j accept")
        && !lower.contains("-j drop")
        && !lower.contains("-j reject")
        && !lower.contains("-j log")
        && !lower.contains("-j masquerade")
        && !lower.contains("-j snat")
        && !lower.contains("-j dnat")
        && !lower.contains("-j return")
        && lower.contains(" -j ")
}

fn jump_target(text: &str) -> Option<String> {
    after_flag(&text.to_ascii_lowercase(), text, "-j ")
        .or_else(|| after_token(text, "jump"))
        .or_else(|| after_token(text, "goto"))
}

fn comment_of(text: &str) -> Option<String> {
    if let Some(idx) = text.find("--comment") {
        let after = text[idx + 9..].trim_start();
        let after = after.strip_prefix('"').unwrap_or(after);
        return Some(after.trim_matches('"').to_string());
    }
    if let Some(idx) = text.find("comment ") {
        let after = text[idx + 8..].trim_start();
        if let Some(rest) = after.strip_prefix('"') {
            return rest.split('"').next().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn established_related() {
        let s = explain_rule_criollo("ct state established,related accept");
        assert!(s.to_ascii_lowercase().contains("conversación") || s.contains("abierta"));
        assert!(s.to_ascii_lowercase().contains("accept") || s.contains("deja pasar"));
    }

    #[test]
    fn ssh_port() {
        let s = explain_rule_criollo("tcp dport 22 accept");
        assert!(s.contains("22"));
        assert!(s.contains("SSH"));
    }

    #[test]
    fn masquerade() {
        let s = explain_rule_criollo(r#"oifname "wlan0" masquerade"#);
        assert!(s.to_ascii_lowercase().contains("nat") || s.contains("disfraza"));
    }

    #[test]
    fn drop_policy() {
        let s = explain_rule_criollo("type filter hook input priority filter; policy drop;");
        assert!(s.to_ascii_lowercase().contains("descarta") || s.contains("drop"));
    }
}
