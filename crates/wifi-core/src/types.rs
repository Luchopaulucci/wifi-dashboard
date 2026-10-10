use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    Ghz24,
    Ghz5,
    Ghz6,
}

impl Band {
    pub fn as_label(self) -> &'static str {
        match self {
            Band::Ghz24 => "2.4 GHz",
            Band::Ghz5 => "5 GHz",
            Band::Ghz6 => "6 GHz",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LiveWifi {
    pub iface: String,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub signal_dbm: Option<i32>,
    pub signal_pct: Option<u8>,
    pub channel: Option<u32>,
    pub frequency_mhz: Option<u32>,
    pub band: Option<Band>,
    pub tx_mbps: Option<f64>,
    pub rx_mbps: Option<f64>,
    pub ip: Option<String>,
    pub prefix_len: Option<u8>,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NearbyNetwork {
    pub in_use: bool,
    pub ssid: String,
    pub bssid: String,
    pub channel: Option<u32>,
    pub frequency_mhz: Option<u32>,
    pub band: Option<Band>,
    pub signal_dbm: Option<i32>,
    pub signal_pct: Option<u8>,
    pub security: String,
    pub rate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LanDevice {
    pub ip: String,
    pub mac: Option<String>,
    pub iface: Option<String>,
    pub state: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub is_gateway: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProbeInstant {
    pub target: String,
    pub label: String,
    pub latency_ms: Option<f64>,
    pub lost: bool,
    pub jitter_ms: Option<f64>,
    pub loss_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryPoint {
    pub ts_ms: u64,
    pub latency_ms: Option<f64>,
    pub loss_pct: f64,
    pub jitter_ms: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryRange {
    Hour,
    Day,
    Week,
}

impl HistoryRange {
    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "hour" => Some(Self::Hour),
            "day" => Some(Self::Day),
            "week" => Some(Self::Week),
            _ => None,
        }
    }

    pub fn window_ms(self) -> u64 {
        match self {
            Self::Hour => 60 * 60 * 1000,
            Self::Day => 24 * 60 * 60 * 1000,
            Self::Week => 7 * 24 * 60 * 60 * 1000,
        }
    }

    pub fn bucket_ms(self) -> u64 {
        match self {
            Self::Hour => 15_000,
            Self::Day => 5 * 60 * 1000,
            Self::Week => 60 * 60 * 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChannelBar {
    pub channel: u32,
    pub band: Band,
    pub count: u32,
    pub overlap: u32,
    pub strongest_pct: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Snapshot {
    pub mock: bool,
    pub mock_reason: Option<String>,
    pub collected_at_ms: u64,
    pub live: Option<LiveWifi>,
    pub nearby: Vec<NearbyNetwork>,
    pub devices: Vec<LanDevice>,
    pub probes: Vec<ProbeInstant>,
    pub congestion: Vec<ChannelBar>,
    pub sources: Vec<String>,
}

pub fn band_from_freq_mhz(freq: u32) -> Option<Band> {
    match freq {
        2400..=2500 => Some(Band::Ghz24),
        4900..=5899 => Some(Band::Ghz5),
        5900..=7125 => Some(Band::Ghz6),
        _ => None,
    }
}

/// Convierte dBm a porcentaje (regla habitual de -100..-50 dBm).
pub fn dbm_to_percent(dbm: i32) -> u8 {
    if dbm >= -50 {
        100
    } else if dbm <= -100 {
        0
    } else {
        (2 * (dbm + 100)) as u8
    }
}

/// Estima dBm a partir de un porcentaje 0-100 (inversa aproximada).
pub fn percent_to_dbm(pct: u8) -> i32 {
    let pct = pct.min(100);
    -100 + (i32::from(pct) / 2)
}

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_from_common_freqs() {
        assert_eq!(band_from_freq_mhz(2437), Some(Band::Ghz24));
        assert_eq!(band_from_freq_mhz(5180), Some(Band::Ghz5));
        assert_eq!(band_from_freq_mhz(6115), Some(Band::Ghz6));
        assert_eq!(band_from_freq_mhz(1000), None);
    }

    #[test]
    fn signal_conversion_round_trip_ish() {
        assert_eq!(dbm_to_percent(-50), 100);
        assert_eq!(dbm_to_percent(-100), 0);
        assert_eq!(dbm_to_percent(-75), 50);
        assert_eq!(percent_to_dbm(50), -75);
    }
}
