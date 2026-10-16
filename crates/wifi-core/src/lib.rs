//! Crate de recolección y almacenamiento de Señal.
//!
//! Independiente del shell Tauri: un agente headless o un módulo MikroTik
//! futuro puede reutilizar estas APIs sin el frontend.

mod collect;
mod command;
mod congestion;
mod engine;
mod error;
mod mock;
pub mod net;
mod oui;
mod parse;
mod store;
pub mod types;

pub use command::{bin_exists, run_cmd, validate_host, validate_iface, validate_ipv4};
pub use congestion::{congestion_bars, overlaps_24};
pub use engine::{AppCore, INTERNET_TARGETS};
pub use error::{CoreError, Result};
pub use mock::MOCK_REASON;
pub use parse::{
    parse_ip_neigh, parse_iw_info, parse_iw_link, parse_nmcli_device_show, parse_nmcli_wifi_list,
    parse_ping_latency, parse_ping_stats, parse_proc_wireless, split_nmcli_terse,
};
pub use store::Store;
pub use types::{
    band_from_freq_mhz, dbm_to_percent, percent_to_dbm, Band, ChannelBar, HistoryPoint,
    HistoryRange, LanDevice, LiveWifi, NearbyNetwork, ProbeInstant, Snapshot,
};
