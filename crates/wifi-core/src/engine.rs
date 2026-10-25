use std::path::Path;
use std::time::{Duration, Instant};

use crate::collect::{
    collect_devices, collect_live, collect_nearby, ping_target, should_mock, snapshot_congestion,
    CollectCache,
};
use crate::error::{CoreError, Result};
use crate::mock;
use crate::store::Store;
use crate::types::{now_ms, HistoryPoint, HistoryRange, LanDevice, ProbeInstant, Snapshot};

pub const INTERNET_TARGETS: &[(&str, &str)] = &[
    ("1.1.1.1", "Internet (1.1.1.1)"),
    ("8.8.8.8", "Internet (8.8.8.8)"),
];

pub struct AppCore {
    store: Store,
    mock: bool,
    cache: CollectCache,
    last_probe: Option<Instant>,
}

/// Resultado de nmcli/ip/ping listo para aplicar bajo un lock corto.
pub struct WifiView {
    sources: Vec<String>,
    live: Option<crate::types::LiveWifi>,
    nearby: Vec<crate::types::NearbyNetwork>,
    devices: Vec<LanDevice>,
    cache: CollectCache,
    probes: Option<Vec<ProbeSample>>,
}

struct ProbeSample {
    at_ms: u64,
    target: String,
    latency_ms: Option<f64>,
}

impl AppCore {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self> {
        Self::open_inner(db_path, should_mock())
    }

    pub fn open_inner(db_path: impl AsRef<Path>, mock: bool) -> Result<Self> {
        let store = Store::open(db_path)?;
        if mock {
            mock::seed_history(&store)?;
        }
        let _ = store.prune();
        Ok(Self {
            store,
            mock,
            cache: CollectCache::default(),
            last_probe: None,
        })
    }

    pub fn is_mock(&self) -> bool {
        self.mock
    }

    pub fn snapshot_inputs(&self) -> (CollectCache, Option<Instant>) {
        (self.cache.clone(), self.last_probe)
    }

    /// I/O de WiFi/LAN/ping sin `AppCore`. El lock solo entra en `finish_snapshot`.
    pub fn collect_view(cache: CollectCache, last_probe: Option<Instant>) -> Result<WifiView> {
        let mut sources = Vec::new();
        let live = collect_live(&mut sources).ok();
        let mut cache = cache;
        let nearby = collect_nearby(false, &mut cache).unwrap_or_default();
        let devices = if let Some(ref live) = live {
            collect_devices(live, false).unwrap_or_default()
        } else {
            Vec::new()
        };
        let probes = Self::collect_probe_samples(live.as_ref(), last_probe)?;
        Ok(WifiView {
            sources,
            live,
            nearby,
            devices,
            cache,
            probes,
        })
    }

    fn collect_probe_samples(
        live: Option<&crate::types::LiveWifi>,
        last_probe: Option<Instant>,
    ) -> Result<Option<Vec<ProbeSample>>> {
        if last_probe
            .map(|t| t.elapsed() < Duration::from_secs(3))
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let now = now_ms();
        let mut samples = Vec::new();
        if let Some(gw) = live.and_then(|l| l.gateway.as_deref()) {
            if crate::command::validate_ipv4(gw).is_ok() {
                let lat = ping_target(gw)?;
                samples.push(ProbeSample {
                    at_ms: now,
                    target: gw.to_string(),
                    latency_ms: lat,
                });
            }
        }
        for (ip, _) in INTERNET_TARGETS {
            let lat = ping_target(ip)?;
            samples.push(ProbeSample {
                at_ms: now,
                target: (*ip).to_string(),
                latency_ms: lat,
            });
        }
        Ok(Some(samples))
    }

    pub fn finish_snapshot(
        &mut self,
        view: WifiView,
        devices: Option<Vec<LanDevice>>,
    ) -> Result<Snapshot> {
        self.cache = view.cache;
        if let Some(samples) = view.probes {
            for sample in samples {
                self.store.insert_sample(
                    sample.at_ms,
                    &sample.target,
                    sample.latency_ms,
                    sample.latency_ms.is_none(),
                )?;
            }
            self.last_probe = Some(Instant::now());
            let _ = self.store.prune();
        }
        let live = view.live;
        let probes = self.probes(live.as_ref())?;
        Ok(Snapshot {
            mock: false,
            mock_reason: None,
            collected_at_ms: now_ms(),
            congestion: snapshot_congestion(&view.nearby),
            live,
            nearby: view.nearby,
            devices: devices.unwrap_or(view.devices),
            probes,
            sources: view.sources,
        })
    }

    pub fn snapshot(&mut self) -> Result<Snapshot> {
        if self.mock {
            let _ = mock::append_live_mock_sample(&self.store);
            return Ok(mock::snapshot(&self.store));
        }
        let (cache, last_probe) = self.snapshot_inputs();
        let view = Self::collect_view(cache, last_probe)?;
        self.finish_snapshot(view, None)
    }

    pub fn rescan(&mut self) -> Result<Snapshot> {
        if self.mock {
            return Ok(mock::snapshot(&self.store));
        }
        let _ = collect_nearby(true, &mut self.cache);
        self.snapshot()
    }

    pub fn collect_lan_sweep() -> Result<Vec<LanDevice>> {
        let mut sources = Vec::new();
        let live = collect_live(&mut sources)?;
        collect_devices(&live, true)
    }

    pub fn snapshot_with_devices(&mut self, devices: Vec<LanDevice>) -> Result<Snapshot> {
        if self.mock {
            return Ok(mock::snapshot(&self.store));
        }
        let (cache, last_probe) = self.snapshot_inputs();
        let view = Self::collect_view(cache, last_probe)?;
        self.finish_snapshot(view, Some(devices))
    }

    pub fn sweep_lan(&mut self) -> Result<Snapshot> {
        if self.mock {
            return Ok(mock::snapshot(&self.store));
        }
        let devices = Self::collect_lan_sweep()?;
        self.snapshot_with_devices(devices)
    }

    pub fn history(&self, target: &str, range: HistoryRange) -> Result<Vec<HistoryPoint>> {
        if target != "192.168.0.1"
            && target != "1.1.1.1"
            && target != "8.8.8.8"
            && !self.is_known_gateway(target)
        {
            return Err(CoreError::InvalidArg(format!("destino: {target}")));
        }
        self.store.history(target, range)
    }

    fn is_known_gateway(&self, target: &str) -> bool {
        crate::command::validate_ipv4(target).is_ok()
    }

    fn probes(&self, live: Option<&crate::types::LiveWifi>) -> Result<Vec<ProbeInstant>> {
        let mut out = Vec::new();
        if let Some(gw) = live.and_then(|l| l.gateway.as_deref()) {
            out.push(self.store.instant_stats(gw, "Puerta de enlace")?);
        }
        for (ip, label) in INTERNET_TARGETS {
            out.push(self.store.instant_stats(ip, label)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_engine_labels_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut core = AppCore::open_inner(dir.path().join("m.db"), true).unwrap();
        let snap = core.snapshot().unwrap();
        assert!(snap.mock);
        assert!(snap
            .mock_reason
            .as_deref()
            .unwrap()
            .contains("interfaz WiFi"));
        assert_eq!(snap.sources, vec!["mock".to_string()]);
        assert!(snap.live.is_some());
        assert!(!snap.nearby.is_empty());
    }

    #[test]
    fn probe_samples_skip_when_fresh() {
        let samples = AppCore::collect_probe_samples(None, Some(Instant::now())).unwrap();
        assert!(samples.is_none());
    }

    #[test]
    fn finish_snapshot_overrides_devices_without_io() {
        let dir = tempfile::tempdir().unwrap();
        let mut core = AppCore::open_inner(dir.path().join("t.db"), false).unwrap();
        let view = WifiView {
            sources: vec!["test".into()],
            live: None,
            nearby: vec![],
            devices: vec![],
            cache: CollectCache::default(),
            probes: None,
        };
        let snap = core
            .finish_snapshot(
                view,
                Some(vec![LanDevice {
                    ip: "192.168.0.10".into(),
                    mac: None,
                    iface: None,
                    state: "REACHABLE".into(),
                    hostname: None,
                    vendor: None,
                    is_gateway: false,
                }]),
            )
            .unwrap();
        assert!(!snap.mock);
        assert_eq!(snap.devices.len(), 1);
        assert_eq!(snap.devices[0].ip, "192.168.0.10");
        assert_eq!(snap.sources, vec!["test".to_string()]);
    }
}
