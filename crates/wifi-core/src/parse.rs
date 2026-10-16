use crate::error::{CoreError, Result};
use crate::types::{
    band_from_freq_mhz, dbm_to_percent, percent_to_dbm, LanDevice, LiveWifi, NearbyNetwork,
};

/// Parte una línea `nmcli -t` respetando `\:`.
pub fn split_nmcli_terse(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                cur.push(next);
            }
        } else if c == ':' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

pub fn parse_nmcli_wifi_list(text: &str) -> Result<Vec<NearbyNetwork>> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let cols = split_nmcli_terse(line);
        // IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY
        if cols.len() < 8 {
            return Err(CoreError::Parse(format!(
                "nmcli wifi list: columnas insuficientes: {line}"
            )));
        }
        let in_use = cols[0] == "*" || cols[0].eq_ignore_ascii_case("yes");
        let bssid = cols[1].trim().to_string();
        if bssid.is_empty() {
            continue;
        }
        let ssid = cols[2].trim().to_string();
        let channel = parse_u32_opt(&cols[3]);
        let frequency_mhz = parse_freq(&cols[4]);
        let rate = empty_to_none(&cols[5]);
        let signal_pct = parse_u8_opt(&cols[6]);
        let security = cols[7].trim().to_string();
        let band = frequency_mhz.and_then(band_from_freq_mhz);
        let signal_dbm = signal_pct.map(percent_to_dbm);
        out.push(NearbyNetwork {
            in_use,
            ssid,
            bssid,
            channel,
            frequency_mhz,
            band,
            signal_dbm,
            signal_pct,
            security,
            rate,
        });
    }
    Ok(out)
}

pub fn parse_nmcli_device_show(text: &str) -> LiveWifi {
    let mut live = LiveWifi {
        iface: String::new(),
        ssid: None,
        bssid: None,
        signal_dbm: None,
        signal_pct: None,
        channel: None,
        frequency_mhz: None,
        band: None,
        tx_mbps: None,
        rx_mbps: None,
        ip: None,
        prefix_len: None,
        gateway: None,
        dns: Vec::new(),
    };
    for raw in text.lines() {
        let line = raw.trim();
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if val.is_empty() {
                continue;
            }
            match key {
                "GENERAL.DEVICE" => live.iface = val.to_string(),
                "GENERAL.CONNECTION" => {
                    if live.ssid.is_none() && val != "--" {
                        live.ssid = Some(val.to_string());
                    }
                }
                "GENERAL.HWADDR" => {}
                k if k.starts_with("IP4.ADDRESS") => {
                    if let Some((ip, prefix)) = val.split_once('/') {
                        live.ip = Some(ip.to_string());
                        live.prefix_len = prefix.parse().ok();
                    } else {
                        live.ip = Some(val.to_string());
                    }
                }
                "IP4.GATEWAY" => live.gateway = Some(val.to_string()),
                k if k.starts_with("IP4.DNS") => live.dns.push(val.to_string()),
                _ => {}
            }
        }
    }
    live
}

pub fn parse_iw_link(text: &str) -> LiveWifi {
    let mut live = empty_live();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("Connected to ") {
            let bssid = rest.split_whitespace().next().unwrap_or("").to_string();
            if !bssid.is_empty() {
                live.bssid = Some(bssid);
            }
        } else if let Some(ssid) = line.strip_prefix("SSID:") {
            live.ssid = Some(ssid.trim().to_string());
        } else if let Some(freq) = line.strip_prefix("freq:") {
            let f = parse_freq(freq.trim());
            live.frequency_mhz = f;
            live.band = f.and_then(band_from_freq_mhz);
        } else if let Some(sig) = line.strip_prefix("signal:") {
            if let Some(dbm) = parse_dbm(sig) {
                live.signal_dbm = Some(dbm);
                live.signal_pct = Some(dbm_to_percent(dbm));
            }
        } else if let Some(rate) = line.strip_prefix("tx bitrate:") {
            live.tx_mbps = parse_mbps(rate);
        } else if let Some(rate) = line.strip_prefix("rx bitrate:") {
            live.rx_mbps = parse_mbps(rate);
        }
    }
    live
}

pub fn parse_iw_info(text: &str) -> LiveWifi {
    let mut live = empty_live();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(name) = line.strip_prefix("Interface ") {
            live.iface = name.trim().to_string();
        } else if let Some(ssid) = line.strip_prefix("ssid ") {
            live.ssid = Some(ssid.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("channel ") {
            // channel 6 (2437 MHz), width: 20 MHz
            let mut parts = rest.split_whitespace();
            live.channel = parts.next().and_then(|p| p.parse().ok());
            if let Some(freq) = rest.split('(').nth(1) {
                live.frequency_mhz = parse_freq(freq);
                live.band = live.frequency_mhz.and_then(band_from_freq_mhz);
            }
        }
    }
    live
}

pub fn parse_proc_wireless(text: &str, iface: Option<&str>) -> Option<(String, i32, u8)> {
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("Inter") || line.starts_with("face") {
            continue;
        }
        let Some((name_part, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name_part.trim();
        if let Some(want) = iface {
            if name != want {
                continue;
            }
        }
        let cols: Vec<&str> = rest.split_whitespace().collect();
        // status link level noise ...
        if cols.len() < 3 {
            continue;
        }
        let level = cols[2].trim_end_matches('.').parse::<f32>().ok()?;
        let dbm = level as i32;
        return Some((name.to_string(), dbm, dbm_to_percent(dbm)));
    }
    None
}

pub fn parse_ip_neigh(text: &str) -> Vec<LanDevice> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let ip = parts[0].to_string();
        if ip.contains(':') && !ip.contains('.') {
            // IPv6: lo saltamos en v1 para no duplicar equipos
            continue;
        }
        let mut mac = None;
        let mut iface = None;
        let mut state = "UNKNOWN".to_string();
        let mut i = 1;
        while i < parts.len() {
            match parts[i] {
                "dev" if i + 1 < parts.len() => {
                    iface = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "lladdr" if i + 1 < parts.len() => {
                    mac = Some(parts[i + 1].to_lowercase());
                    i += 2;
                }
                other if other.chars().all(|c| c.is_ascii_uppercase() || c == '_') => {
                    state = other.to_string();
                    i += 1;
                }
                _ => i += 1,
            }
        }
        if state == "FAILED" && mac.is_none() {
            continue;
        }
        out.push(LanDevice {
            ip,
            mac,
            iface,
            state,
            hostname: None,
            vendor: None,
            is_gateway: false,
        });
    }
    out
}

pub fn parse_ip_route_default(text: &str) -> Option<(String, String)> {
    for raw in text.lines() {
        let line = raw.trim();
        if !line.starts_with("default ") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut gw = None;
        let mut dev = None;
        let mut i = 0;
        while i < parts.len() {
            if parts[i] == "via" && i + 1 < parts.len() {
                gw = Some(parts[i + 1].to_string());
                i += 2;
            } else if parts[i] == "dev" && i + 1 < parts.len() {
                dev = Some(parts[i + 1].to_string());
                i += 2;
            } else {
                i += 1;
            }
        }
        if let (Some(g), Some(d)) = (gw, dev) {
            return Some((g, d));
        }
    }
    None
}

pub fn parse_ip_addr_v4(text: &str) -> Option<(String, u8, String)> {
    // ip -4 -o addr: "3: wlp2s0    inet 192.168.0.24/24 brd ..."
    for raw in text.lines() {
        let line = raw.trim();
        let parts: Vec<&str> = line.split_whitespace().collect();
        let iface = parts.first()?.trim_end_matches(':');
        let inet_idx = parts.iter().position(|p| *p == "inet")?;
        let cidr = parts.get(inet_idx + 1)?;
        let (ip, prefix) = cidr.split_once('/')?;
        let prefix_len = prefix.parse().ok()?;
        if iface == "lo" {
            continue;
        }
        return Some((ip.to_string(), prefix_len, iface.to_string()));
    }
    None
}

pub fn parse_resolv_conf(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("nameserver ")
                .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
                .filter(|s| !s.is_empty())
        })
        .collect()
}

pub fn parse_nmcli_device_status(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let cols = split_nmcli_terse(raw.trim());
        if cols.len() >= 3 {
            out.push((cols[0].clone(), cols[1].clone(), cols[2].clone()));
        }
    }
    out
}

pub fn parse_iw_dev(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        if let Some(name) = raw.trim().strip_prefix("Interface ") {
            out.push(name.trim().to_string());
        }
    }
    out
}

/// Extrae latencia en ms de una línea `time=18.3 ms`. Devuelve None si hubo pérdida.
pub fn parse_ping_latency(text: &str) -> Option<f64> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(idx) = line.find("time=") {
            let rest = &line[idx + 5..];
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(v) = num.parse::<f64>() {
                return Some(v);
            }
        }
    }
    None
}

pub fn parse_ping_stats(text: &str) -> (u32, u32, Option<f64>) {
    // 3 packets transmitted, 2 received, 33% packet loss
    let mut sent = 0u32;
    let mut recv = 0u32;
    let mut avg = None;
    for line in text.lines() {
        let line = line.trim();
        if line.contains("packets transmitted") {
            let parts: Vec<&str> = line.split(',').collect();
            if let Some(s) = parts.first() {
                sent = s
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
            }
            if let Some(r) = parts.get(1) {
                recv = r
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
            }
        }
        if line.starts_with("rtt ") || line.contains("min/avg/max") {
            if let Some(eq) = line.split('=').nth(1) {
                let vals: Vec<&str> = eq.split('/').collect();
                if vals.len() >= 2 {
                    avg = vals[1]
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok());
                }
            }
        }
    }
    (sent, recv, avg)
}

fn empty_live() -> LiveWifi {
    LiveWifi {
        iface: String::new(),
        ssid: None,
        bssid: None,
        signal_dbm: None,
        signal_pct: None,
        channel: None,
        frequency_mhz: None,
        band: None,
        tx_mbps: None,
        rx_mbps: None,
        ip: None,
        prefix_len: None,
        gateway: None,
        dns: Vec::new(),
    }
}

fn empty_to_none(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn parse_u32_opt(s: &str) -> Option<u32> {
    s.split_whitespace().next()?.parse().ok()
}

fn parse_u8_opt(s: &str) -> Option<u8> {
    s.split_whitespace().next()?.parse().ok()
}

fn parse_freq(s: &str) -> Option<u32> {
    let t = s.replace("MHz", "").replace("mhz", "");
    let n = t.split_whitespace().next()?.parse::<f64>().ok()?;
    Some(n.round() as u32)
}

fn parse_dbm(s: &str) -> Option<i32> {
    let t = s.replace("dBm", "").replace("dbm", "");
    t.split_whitespace()
        .next()?
        .parse::<f32>()
        .ok()
        .map(|v| v as i32)
}

fn parse_mbps(s: &str) -> Option<f64> {
    s.split_whitespace().next()?.parse().ok()
}

pub fn merge_live(base: &mut LiveWifi, extra: LiveWifi) {
    if base.iface.is_empty() && !extra.iface.is_empty() {
        base.iface = extra.iface;
    }
    if base.ssid.is_none() {
        base.ssid = extra.ssid;
    }
    if base.bssid.is_none() {
        base.bssid = extra.bssid;
    }
    if base.signal_dbm.is_none() {
        base.signal_dbm = extra.signal_dbm;
        base.signal_pct = extra.signal_pct;
    }
    if base.channel.is_none() {
        base.channel = extra.channel;
    }
    if base.frequency_mhz.is_none() {
        base.frequency_mhz = extra.frequency_mhz;
        base.band = extra.band;
    }
    if base.tx_mbps.is_none() {
        base.tx_mbps = extra.tx_mbps;
    }
    if base.rx_mbps.is_none() {
        base.rx_mbps = extra.rx_mbps;
    }
    if base.ip.is_none() {
        base.ip = extra.ip;
        base.prefix_len = extra.prefix_len;
    }
    if base.gateway.is_none() {
        base.gateway = extra.gateway;
    }
    if base.dns.is_empty() {
        base.dns = extra.dns;
    }
}
