use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::command::{bin_exists, run_cmd, run_cmd_timeout, validate_iface, validate_ipv4};
use crate::congestion::congestion_bars;
use crate::error::{CoreError, Result};
use crate::oui::lookup_vendor;
use crate::parse::{
    merge_live, parse_ip_addr_v4, parse_ip_neigh, parse_ip_route_default, parse_iw_dev,
    parse_iw_info, parse_iw_link, parse_nmcli_device_show, parse_nmcli_device_status,
    parse_nmcli_wifi_list, parse_ping_latency, parse_proc_wireless, parse_resolv_conf,
};
use crate::types::{LanDevice, LiveWifi, NearbyNetwork};

const RESCAN_MIN_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Default)]
pub struct CollectCache {
    last_rescan: Option<Instant>,
    nearby: Vec<NearbyNetwork>,
}

pub fn wifi_interface_present() -> bool {
    if Path::new("/sys/class/net").is_dir() {
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if entry.path().join("wireless").is_dir() {
                    return true;
                }
            }
        }
    }
    if bin_exists("nmcli") {
        if let Ok(text) = run_cmd(
            "nmcli",
            &["-t", "-f", "DEVICE,TYPE,STATE", "device", "status"],
        ) {
            if parse_nmcli_device_status(&text)
                .iter()
                .any(|(_, ty, _)| ty == "wifi")
            {
                return true;
            }
        }
    }
    if bin_exists("iw") {
        if let Ok(text) = run_cmd("iw", &["dev"]) {
            if !parse_iw_dev(&text).is_empty() {
                return true;
            }
        }
    }
    false
}

pub fn should_mock() -> bool {
    match std::env::var("WIFI_DASHBOARD_MOCK") {
        Ok(v) if matches!(v.as_str(), "1" | "true" | "yes") => return true,
        Ok(v) if matches!(v.as_str(), "0" | "false" | "no") => return false,
        _ => {}
    }
    !wifi_interface_present()
}

pub fn collect_live(sources: &mut Vec<String>) -> Result<LiveWifi> {
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

    let iface = detect_wifi_iface();
    if let Some(ref name) = iface {
        live.iface = name.clone();
    }

    if bin_exists("nmcli") {
        if let Some(ref name) = iface {
            if validate_iface(name).is_ok() {
                if let Ok(text) = run_cmd("nmcli", &["-t", "device", "show", name]) {
                    merge_live(&mut live, parse_nmcli_device_show(&text));
                    sources.push("nmcli".into());
                }
            }
        } else if let Ok(text) = run_cmd("nmcli", &["-t", "device", "show"]) {
            merge_live(&mut live, parse_nmcli_device_show(&text));
            sources.push("nmcli".into());
        }
        if let Ok(list) = list_wifi() {
            if let Some(active) = list.into_iter().find(|n| n.in_use) {
                if live.ssid.is_none() {
                    live.ssid = Some(active.ssid);
                }
                if live.bssid.is_none() {
                    live.bssid = Some(active.bssid);
                }
                if live.channel.is_none() {
                    live.channel = active.channel;
                }
                if live.frequency_mhz.is_none() {
                    live.frequency_mhz = active.frequency_mhz;
                    live.band = active.band;
                }
                if live.signal_pct.is_none() {
                    live.signal_pct = active.signal_pct;
                    live.signal_dbm = active.signal_dbm;
                }
            }
        }
    }

    if let Some(ref name) = iface {
        if validate_iface(name).is_ok() && bin_exists("iw") {
            if let Ok(text) = run_cmd("iw", &["dev", name, "link"]) {
                merge_live(&mut live, parse_iw_link(&text));
                sources.push("iw".into());
            }
            if let Ok(text) = run_cmd("iw", &["dev", name, "info"]) {
                merge_live(&mut live, parse_iw_info(&text));
            }
        }
        if let Ok(text) = fs::read_to_string("/proc/net/wireless") {
            if let Some((_, dbm, pct)) = parse_proc_wireless(&text, Some(name)) {
                if live.signal_dbm.is_none() {
                    live.signal_dbm = Some(dbm);
                    live.signal_pct = Some(pct);
                    sources.push("/proc/net/wireless".into());
                }
            }
        }
    }

    if bin_exists("ip") {
        if let Ok(text) = run_cmd("ip", &["-4", "route", "show", "default"]) {
            if let Some((gw, dev)) = parse_ip_route_default(&text) {
                if live.gateway.is_none() {
                    live.gateway = Some(gw);
                }
                if live.iface.is_empty() {
                    live.iface = dev;
                }
                sources.push("ip".into());
            }
        }
        if live.ip.is_none() {
            let args: Vec<&str> = if live.iface.is_empty() {
                vec!["-4", "-o", "addr", "show"]
            } else if validate_iface(&live.iface).is_ok() {
                vec!["-4", "-o", "addr", "show", "dev", live.iface.as_str()]
            } else {
                vec!["-4", "-o", "addr", "show"]
            };
            if let Ok(text) = run_cmd("ip", &args) {
                if let Some((ip, prefix, _dev)) = parse_ip_addr_v4(&text) {
                    live.ip = Some(ip);
                    live.prefix_len = Some(prefix);
                }
            }
        }
    }

    if live.dns.is_empty() {
        if let Ok(text) = fs::read_to_string("/etc/resolv.conf") {
            live.dns = parse_resolv_conf(&text);
        }
    }

    if live.iface.is_empty() && live.ssid.is_none() && live.ip.is_none() {
        return Err(CoreError::Parse("sin datos de WiFi en vivo".into()));
    }
    Ok(live)
}

pub fn list_wifi() -> Result<Vec<NearbyNetwork>> {
    if !bin_exists("nmcli") {
        return Ok(Vec::new());
    }
    let text = run_cmd(
        "nmcli",
        &[
            "-t",
            "-f",
            "IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
        ],
    )?;
    parse_nmcli_wifi_list(&text)
}

pub fn collect_nearby(force_rescan: bool, cache: &mut CollectCache) -> Result<Vec<NearbyNetwork>> {
    if !bin_exists("nmcli") {
        return Ok(cache.nearby.clone());
    }
    let due = cache
        .last_rescan
        .map(|t| t.elapsed() >= RESCAN_MIN_INTERVAL)
        .unwrap_or(true);
    if force_rescan || due {
        if force_rescan || cache.last_rescan.is_some() || cache.nearby.is_empty() {
            let _ = run_cmd_timeout(
                "nmcli",
                &["device", "wifi", "rescan"],
                Duration::from_secs(6),
            );
            cache.last_rescan = Some(Instant::now());
        } else {
            cache.last_rescan = Some(Instant::now());
        }
    }
    let text = run_cmd(
        "nmcli",
        &[
            "-t",
            "-f",
            "IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
        ],
    )?;
    let list = parse_nmcli_wifi_list(&text)?;
    cache.nearby = list.clone();
    Ok(list)
}

pub fn collect_devices(live: &LiveWifi, do_sweep: bool) -> Result<Vec<LanDevice>> {
    if !bin_exists("ip") {
        return Ok(Vec::new());
    }
    let text = run_cmd("ip", &["neigh", "show"])?;
    let mut devices = parse_ip_neigh(&text);
    let subnet = connected_subnet(live);

    if let Some(net) = subnet {
        devices.retain(|d| ip_in_subnet(&d.ip, &net));
    } else {
        // Sin subred conocida no recorremos nada extra; solo vecinos ya vistos.
        devices.retain(|d| is_private_ipv4(&d.ip));
    }

    if do_sweep {
        if let Some(net) = subnet {
            sweep_own_subnet(&net, &mut devices)?;
        }
    }

    let gw = live.gateway.as_deref();
    for d in &mut devices {
        d.is_gateway = gw == Some(d.ip.as_str());
        if let Some(mac) = &d.mac {
            d.vendor = lookup_vendor(mac);
        }
        d.hostname = resolve_hostname(&d.ip);
    }
    devices.sort_by(|a, b| a.ip.cmp(&b.ip));
    Ok(devices)
}

pub fn ping_target(ip: &str) -> Result<Option<f64>> {
    let ip = validate_ipv4(ip)?;
    match run_cmd_timeout(
        "ping",
        &["-c", "1", "-n", "-W", "1", ip],
        Duration::from_secs(3),
    ) {
        Ok(text) => Ok(parse_ping_latency(&text)),
        Err(_) => Ok(None),
    }
}

pub fn snapshot_congestion(nearby: &[NearbyNetwork]) -> Vec<crate::types::ChannelBar> {
    congestion_bars(nearby)
}

fn detect_wifi_iface() -> Option<String> {
    if bin_exists("nmcli") {
        if let Ok(text) = run_cmd(
            "nmcli",
            &["-t", "-f", "DEVICE,TYPE,STATE", "device", "status"],
        ) {
            let rows = parse_nmcli_device_status(&text);
            if let Some((dev, _, _)) = rows
                .iter()
                .find(|(_, ty, state)| ty == "wifi" && state.contains("connected"))
            {
                return Some(dev.clone());
            }
            if let Some((dev, _, _)) = rows.iter().find(|(_, ty, _)| ty == "wifi") {
                return Some(dev.clone());
            }
        }
    }
    if bin_exists("iw") {
        if let Ok(text) = run_cmd("iw", &["dev"]) {
            if let Some(name) = parse_iw_dev(&text).into_iter().next() {
                return Some(name);
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if entry.path().join("wireless").is_dir() {
                return Some(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Subnet {
    pub network: u32,
    pub prefix: u8,
}

pub fn connected_subnet(live: &LiveWifi) -> Option<Ipv4Subnet> {
    let ip: Ipv4Addr = live.ip.as_ref()?.parse().ok()?;
    let mut prefix = live.prefix_len.unwrap_or(24);
    if prefix > 32 {
        return None;
    }
    // Nunca barrer redes más grandes que /24.
    if prefix < 24 {
        prefix = 24;
    }
    let ip_u = u32::from(ip);
    let mask = !0u32 << (32 - prefix);
    Some(Ipv4Subnet {
        network: ip_u & mask,
        prefix,
    })
}

fn ip_in_subnet(ip: &str, net: &Ipv4Subnet) -> bool {
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let mask = if net.prefix == 0 {
        0
    } else {
        !0u32 << (32 - net.prefix)
    };
    (u32::from(addr) & mask) == net.network
}

fn is_private_ipv4(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    addr.is_private()
}

fn sweep_own_subnet(net: &Ipv4Subnet, devices: &mut Vec<LanDevice>) -> Result<()> {
    if net.prefix < 24 {
        return Err(CoreError::Forbidden(
            "el barrido solo se permite en la /24 conectada".into(),
        ));
    }
    let host_bits = 32 - net.prefix;
    let count = 1u32 << host_bits;
    if count > 256 {
        return Err(CoreError::Forbidden("rango demasiado grande".into()));
    }
    let existing: std::collections::HashSet<String> =
        devices.iter().map(|d| d.ip.clone()).collect();
    let mut found = Vec::new();
    for i in 1..count.saturating_sub(1) {
        let addr = Ipv4Addr::from(net.network + i);
        let ip = addr.to_string();
        if existing.contains(&ip) {
            continue;
        }
        if validate_ipv4(&ip).is_err() {
            continue;
        }
        if ping_target(&ip)?.is_some() {
            found.push(LanDevice {
                ip,
                mac: None,
                iface: None,
                state: "PING".into(),
                hostname: None,
                vendor: None,
                is_gateway: false,
            });
        }
    }
    devices.extend(found);
    Ok(())
}

fn resolve_hostname(ip: &str) -> Option<String> {
    if validate_ipv4(ip).is_err() {
        return None;
    }
    if bin_exists("avahi-resolve-address") {
        if let Ok(text) =
            run_cmd_timeout("avahi-resolve-address", &[ip], Duration::from_millis(400))
        {
            for line in text.lines() {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 2 {
                    return Some(cols[1].to_string());
                }
            }
        }
    }
    if let Ok(ipaddr) = ip.parse::<std::net::IpAddr>() {
        if let Ok(name) = dns_lookup::lookup_addr(&ipaddr) {
            if name != ip {
                return Some(name);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_clamps_to_connected_slash24() {
        let live = LiveWifi {
            iface: "wlp0s20f3".into(),
            ssid: None,
            bssid: None,
            signal_dbm: None,
            signal_pct: None,
            channel: None,
            frequency_mhz: None,
            band: None,
            tx_mbps: None,
            rx_mbps: None,
            ip: Some("192.168.10.40".into()),
            prefix_len: Some(16),
            gateway: Some("192.168.10.1".into()),
            dns: vec![],
        };
        let net = connected_subnet(&live).unwrap();
        assert_eq!(net.prefix, 24);
        assert!(ip_in_subnet("192.168.10.1", &net));
        assert!(!ip_in_subnet("192.168.11.1", &net));
        assert!(!ip_in_subnet("10.0.0.1", &net));
    }
}
