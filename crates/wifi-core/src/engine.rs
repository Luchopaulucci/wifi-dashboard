use std::path::Path;
use std::time::Instant;

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

    pub fn snapshot(&mut self) -> Result<Snapshot> {
        if self.mock {
            let _ = mock::append_live_mock_sample(&self.store);
            return Ok(mock::snapshot(&self.store));
        }
        let mut sources = Vec::new();
        let live = collect_live(&mut sources).ok();
        self.maybe_probe(live.as_ref())?;
        let nearby = collect_nearby(false, &mut self.cache).unwrap_or_default();
        let devices = if let Some(ref live) = live {
            collect_devices(live, false).unwrap_or_default()
        } else {
            Vec::new()
        };
        let probes = self.probes(live.as_ref())?;
        Ok(Snapshot {
            mock: false,
            mock_reason: None,
            collected_at_ms: now_ms(),
            congestion: snapshot_congestion(&nearby),
            live,
            nearby,
            devices,
            probes,
            sources,
        })
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
        let mut snap = self.snapshot()?;
        snap.devices = devices;
        Ok(snap)
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

    fn maybe_probe(&mut self, live: Option<&crate::types::LiveWifi>) -> Result<()> {
        if self
            .last_probe
            .map(|t| t.elapsed() < std::time::Duration::from_secs(3))
            .unwrap_or(false)
        {
            return Ok(());
        }
        let now = now_ms();
        if let Some(gw) = live.and_then(|l| l.gateway.as_deref()) {
            if crate::command::validate_ipv4(gw).is_ok() {
                let lat = ping_target(gw)?;
                self.store.insert_sample(now, gw, lat, lat.is_none())?;
            }
        }
        for (ip, _) in INTERNET_TARGETS {
            let lat = ping_target(ip)?;
            self.store.insert_sample(now, ip, lat, lat.is_none())?;
        }
        self.last_probe = Some(Instant::now());
        let _ = self.store.prune();
        Ok(())
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
}
