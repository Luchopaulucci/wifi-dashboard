use crate::congestion::congestion_bars;
use crate::store::Store;
use crate::types::{now_ms, Band, HistoryRange, LanDevice, LiveWifi, NearbyNetwork, Snapshot};

pub const MOCK_REASON: &str = "No hay interfaz WiFi. Mostramos datos de ejemplo.";

pub fn live() -> LiveWifi {
    LiveWifi {
        iface: "wlp2s0".into(),
        ssid: Some("Fibertel-5G".into()),
        bssid: Some("aa:bb:cc:11:22:33".into()),
        signal_dbm: Some(-52),
        signal_pct: Some(96),
        channel: Some(36),
        frequency_mhz: Some(5180),
        band: Some(Band::Ghz5),
        tx_mbps: Some(866.7),
        rx_mbps: Some(780.0),
        ip: Some("192.168.0.24".into()),
        prefix_len: Some(24),
        gateway: Some("192.168.0.1".into()),
        dns: vec!["192.168.0.1".into(), "1.1.1.1".into()],
    }
}

pub fn nearby() -> Vec<NearbyNetwork> {
    vec![
        NearbyNetwork {
            in_use: true,
            ssid: "Fibertel-5G".into(),
            bssid: "aa:bb:cc:11:22:33".into(),
            channel: Some(36),
            frequency_mhz: Some(5180),
            band: Some(Band::Ghz5),
            signal_dbm: Some(-52),
            signal_pct: Some(96),
            security: "WPA2".into(),
            rate: Some("866 Mbit/s".into()),
        },
        NearbyNetwork {
            in_use: false,
            ssid: "Fibertel-2.4".into(),
            bssid: "aa:bb:cc:11:22:34".into(),
            channel: Some(6),
            frequency_mhz: Some(2437),
            band: Some(Band::Ghz24),
            signal_dbm: Some(-61),
            signal_pct: Some(78),
            security: "WPA2".into(),
            rate: Some("144 Mbit/s".into()),
        },
        NearbyNetwork {
            in_use: false,
            ssid: "Vecino-Claro".into(),
            bssid: "11:22:33:44:55:66".into(),
            channel: Some(1),
            frequency_mhz: Some(2412),
            band: Some(Band::Ghz24),
            signal_dbm: Some(-72),
            signal_pct: Some(56),
            security: "WPA2".into(),
            rate: Some("72 Mbit/s".into()),
        },
        NearbyNetwork {
            in_use: false,
            ssid: "Personal-5G".into(),
            bssid: "22:33:44:55:66:77".into(),
            channel: Some(44),
            frequency_mhz: Some(5220),
            band: Some(Band::Ghz5),
            signal_dbm: Some(-80),
            signal_pct: Some(40),
            security: "WPA3".into(),
            rate: Some("433 Mbit/s".into()),
        },
        NearbyNetwork {
            in_use: false,
            ssid: "Movistar-Fibra".into(),
            bssid: "33:44:55:66:77:88".into(),
            channel: Some(11),
            frequency_mhz: Some(2462),
            band: Some(Band::Ghz24),
            signal_dbm: Some(-68),
            signal_pct: Some(64),
            security: "WPA2".into(),
            rate: Some("144 Mbit/s".into()),
        },
        NearbyNetwork {
            in_use: false,
            ssid: "INVITADOS".into(),
            bssid: "44:55:66:77:88:99".into(),
            channel: Some(6),
            frequency_mhz: Some(2437),
            band: Some(Band::Ghz24),
            signal_dbm: Some(-85),
            signal_pct: Some(30),
            security: "Abierta".into(),
            rate: Some("54 Mbit/s".into()),
        },
        NearbyNetwork {
            in_use: false,
            ssid: "Depto-6G".into(),
            bssid: "55:66:77:88:99:00".into(),
            channel: Some(37),
            frequency_mhz: Some(6135),
            band: Some(Band::Ghz6),
            signal_dbm: Some(-70),
            signal_pct: Some(60),
            security: "WPA3".into(),
            rate: Some("1201 Mbit/s".into()),
        },
    ]
}

pub fn devices() -> Vec<LanDevice> {
    vec![
        LanDevice {
            ip: "192.168.0.1".into(),
            mac: Some("aa:bb:cc:11:22:33".into()),
            iface: Some("wlp2s0".into()),
            state: "REACHABLE".into(),
            hostname: Some("router.local".into()),
            vendor: Some("TP-Link".into()),
            is_gateway: true,
        },
        LanDevice {
            ip: "192.168.0.24".into(),
            mac: Some("3c:22:fb:10:20:30".into()),
            iface: Some("wlp2s0".into()),
            state: "REACHABLE".into(),
            hostname: Some("idea-pad.local".into()),
            vendor: Some("Intel".into()),
            is_gateway: false,
        },
        LanDevice {
            ip: "192.168.0.18".into(),
            mac: Some("f8:a4:5f:aa:bb:cc".into()),
            iface: Some("wlp2s0".into()),
            state: "STALE".into(),
            hostname: Some("celular-lu.local".into()),
            vendor: Some("Xiaomi".into()),
            is_gateway: false,
        },
        LanDevice {
            ip: "192.168.0.40".into(),
            mac: Some("a4:77:33:11:22:33".into()),
            iface: Some("wlp2s0".into()),
            state: "REACHABLE".into(),
            hostname: Some("smart-tv.local".into()),
            vendor: Some("Samsung".into()),
            is_gateway: false,
        },
        LanDevice {
            ip: "192.168.0.55".into(),
            mac: Some("00:1a:11:99:88:77".into()),
            iface: Some("wlp2s0".into()),
            state: "DELAY".into(),
            hostname: Some("nest-mini.local".into()),
            vendor: Some("Google".into()),
            is_gateway: false,
        },
    ]
}

pub fn snapshot(store: &Store) -> Snapshot {
    let nets = nearby();
    Snapshot {
        mock: true,
        mock_reason: Some(MOCK_REASON.into()),
        collected_at_ms: now_ms(),
        live: Some(live()),
        congestion: congestion_bars(&nets),
        nearby: nets,
        devices: devices(),
        probes: vec![
            store
                .instant_stats("192.168.0.1", "Puerta de enlace")
                .unwrap_or_else(|_| empty_probe("192.168.0.1", "Puerta de enlace")),
            store
                .instant_stats("1.1.1.1", "Internet (1.1.1.1)")
                .unwrap_or_else(|_| empty_probe("1.1.1.1", "Internet (1.1.1.1)")),
            store
                .instant_stats("8.8.8.8", "Internet (8.8.8.8)")
                .unwrap_or_else(|_| empty_probe("8.8.8.8", "Internet (8.8.8.8)")),
        ],
        sources: vec!["mock".into()],
    }
}

fn empty_probe(target: &str, label: &str) -> crate::types::ProbeInstant {
    crate::types::ProbeInstant {
        target: target.into(),
        label: label.into(),
        latency_ms: None,
        lost: true,
        jitter_ms: None,
        loss_pct: None,
    }
}

/// Rellena historial sintético para que los gráficos se vean en CI / sin WiFi.
pub fn seed_history(store: &Store) -> crate::error::Result<()> {
    if store.count()? > 12 {
        return Ok(());
    }
    let now = now_ms();
    let step = 2 * 60 * 1000;
    let span = HistoryRange::Week.window_ms();
    let targets = [
        ("192.168.0.1", 4.0, 1.2, 0.01),
        ("1.1.1.1", 18.0, 6.0, 0.03),
        ("8.8.8.8", 22.0, 7.0, 0.04),
    ];
    let mut ts = now.saturating_sub(span);
    let mut i = 0u64;
    while ts <= now {
        for (target, base, amp, loss) in targets {
            let wave = ((i as f64) / 18.0).sin();
            let lost = ((i + target.len() as u64) % 40) as f64 / 40.0 < loss;
            let latency = if lost {
                None
            } else {
                Some((base + amp * wave).max(1.0))
            };
            store.insert_sample(ts, target, latency, lost)?;
        }
        ts += step;
        i += 1;
    }
    Ok(())
}

pub fn append_live_mock_sample(store: &Store) -> crate::error::Result<()> {
    let now = now_ms();
    store.insert_sample(now, "192.168.0.1", Some(3.8), false)?;
    store.insert_sample(now, "1.1.1.1", Some(17.4), false)?;
    store.insert_sample(now, "8.8.8.8", Some(21.1), false)?;
    Ok(())
}
