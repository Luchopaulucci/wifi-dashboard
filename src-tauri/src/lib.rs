use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{Emitter, Manager};
use wifi_core::net::{
    alloc_trace_session, collect_boot_traffic, collect_connections, collect_firewall, collect_nat,
    default_gateway, geo_opt_in_denied_message, lookup_ip_external, monitor_rows,
    spawn_dns_monitor, start_trace, BootTrafficReport, ConnectionsReport, DnsMonitorStatus,
    DnsProgramRow, ElevateError, FirewallReport, GeoCache, GeoInfo, ListenerSession,
    ListenersReport, NatReport, PrivilegedAction, PtrCache,
};
use wifi_core::{AppCore, HistoryPoint, HistoryRange, Snapshot};

struct AppState {
    core: Mutex<AppCore>,
    ptr: Arc<Mutex<PtrCache>>,
    geo: Mutex<GeoCache>,
    listeners: Mutex<ListenerSession>,
    trace_cancel: Mutex<Option<Arc<AtomicBool>>>,
    dns_monitor: Arc<Mutex<HashMap<String, u64>>>,
    dns_monitor_status: Arc<Mutex<DnsMonitorStatus>>,
    dns_programs: Mutex<HashMap<String, DnsProgramRow>>,
}

fn map_err(err: wifi_core::CoreError) -> String {
    err.to_string()
}

/// I/O de red fuera del hilo principal, con locks cortos. Misma forma que `sweep_lan`.
struct AsyncNet;

impl AsyncNet {
    async fn blocking<T: Send + 'static>(
        work: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        tauri::async_runtime::spawn_blocking(work)
            .await
            .map_err(|e| e.to_string())?
    }

    fn resolve_ptrs_later(ptr: Arc<Mutex<PtrCache>>, ips: Vec<String>) {
        if ips.is_empty() {
            return;
        }
        tauri::async_runtime::spawn(async move {
            let resolved = match tauri::async_runtime::spawn_blocking(move || {
                ips.into_iter()
                    .map(|ip| {
                        let name = PtrCache::lookup_addr(&ip);
                        (ip, name)
                    })
                    .collect::<Vec<_>>()
            })
            .await
            {
                Ok(v) => v,
                Err(_) => return,
            };
            if let Ok(mut cache) = ptr.lock() {
                for (ip, name) in resolved {
                    cache.remember(ip, name);
                }
            }
        });
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
enum PrivilegedReport {
    Firewall(FirewallReport),
    Nat(NatReport),
    Connections(ConnectionsReport),
    Boot(BootTrafficReport),
}

fn elevate_failure(notes: &[String]) -> Option<String> {
    notes
        .iter()
        .find(|n| ElevateError::is_user_message(n))
        .cloned()
}

#[tauri::command]
async fn get_snapshot(state: tauri::State<'_, AppState>) -> Result<Snapshot, String> {
    let mock = {
        let core = state.core.lock().map_err(|e| e.to_string())?;
        core.is_mock()
    };
    if mock {
        let mut core = state.core.lock().map_err(|e| e.to_string())?;
        return core.snapshot().map_err(map_err);
    }
    let (cache, last_probe) = {
        let core = state.core.lock().map_err(|e| e.to_string())?;
        core.snapshot_inputs()
    };
    let view =
        AsyncNet::blocking(move || AppCore::collect_view(cache, last_probe).map_err(map_err))
            .await?;
    let mut core = state.core.lock().map_err(|e| e.to_string())?;
    core.finish_snapshot(view, None).map_err(map_err)
}

#[tauri::command]
fn rescan_nearby(state: tauri::State<AppState>) -> Result<Snapshot, String> {
    let mut core = state.core.lock().map_err(|e| e.to_string())?;
    core.rescan().map_err(map_err)
}

#[tauri::command]
async fn sweep_lan(state: tauri::State<'_, AppState>) -> Result<Snapshot, String> {
    let mock = {
        let core = state.core.lock().map_err(|e| e.to_string())?;
        core.is_mock()
    };
    if mock {
        let mut core = state.core.lock().map_err(|e| e.to_string())?;
        return core.sweep_lan().map_err(map_err);
    }
    let devices = tauri::async_runtime::spawn_blocking(wifi_core::AppCore::collect_lan_sweep)
        .await
        .map_err(|e| e.to_string())?
        .map_err(map_err)?;
    let (cache, last_probe) = {
        let core = state.core.lock().map_err(|e| e.to_string())?;
        core.snapshot_inputs()
    };
    let view =
        AsyncNet::blocking(move || AppCore::collect_view(cache, last_probe).map_err(map_err))
            .await?;
    let mut core = state.core.lock().map_err(|e| e.to_string())?;
    core.finish_snapshot(view, Some(devices)).map_err(map_err)
}

#[tauri::command]
fn get_history(
    state: tauri::State<AppState>,
    target: String,
    range: String,
) -> Result<Vec<HistoryPoint>, String> {
    let range = HistoryRange::from_key(&range).ok_or_else(|| "rango inválido".to_string())?;
    let core = state.core.lock().map_err(|e| e.to_string())?;
    core.history(&target, range).map_err(map_err)
}

#[tauri::command]
async fn get_connections(state: tauri::State<'_, AppState>) -> Result<ConnectionsReport, String> {
    let cache = {
        let ptr = state.ptr.lock().map_err(|e| e.to_string())?;
        ptr.clone()
    };
    let ptr_slot = state.ptr.clone();
    let (report, pending, updated) = AsyncNet::blocking(move || {
        let mut cache = cache;
        let report = collect_connections(&mut cache, None);
        let pending = cache.pending_public_ips(&report.rows, 6);
        Ok((report, pending, cache))
    })
    .await?;
    {
        let mut ptr = state.ptr.lock().map_err(|e| e.to_string())?;
        ptr.absorb(updated);
    }
    AsyncNet::resolve_ptrs_later(ptr_slot, pending);
    Ok(report)
}

#[tauri::command(async)]
fn get_nat() -> Result<NatReport, String> {
    Ok(collect_nat(None))
}

#[tauri::command(async)]
fn get_firewall() -> Result<FirewallReport, String> {
    Ok(collect_firewall(None))
}

#[tauri::command]
async fn get_boot_traffic(state: tauri::State<'_, AppState>) -> Result<BootTrafficReport, String> {
    let monitor = {
        let map = state.dns_monitor.lock().map_err(|e| e.to_string())?;
        monitor_rows(&map)
    };
    let monitor_status = {
        let s = state.dns_monitor_status.lock().map_err(|e| e.to_string())?;
        s.clone()
    };
    let cache = {
        let ptr = state.ptr.lock().map_err(|e| e.to_string())?;
        ptr.clone()
    };
    let programs = {
        let g = state.dns_programs.lock().map_err(|e| e.to_string())?;
        g.clone()
    };
    let (report, updated_ptr, updated_programs) = AsyncNet::blocking(move || {
        let mut ptr = cache;
        let mut programs = programs;
        let conns = collect_connections(&mut ptr, None);
        let report = collect_boot_traffic(
            &mut ptr,
            &monitor,
            &monitor_status,
            &mut programs,
            &conns.rows,
            None,
        );
        Ok((report, ptr, programs))
    })
    .await?;
    {
        let mut ptr = state.ptr.lock().map_err(|e| e.to_string())?;
        ptr.absorb(updated_ptr);
    }
    {
        let mut g = state.dns_programs.lock().map_err(|e| e.to_string())?;
        for (k, v) in updated_programs {
            g.entry(k).or_insert(v);
        }
    }
    Ok(report)
}

#[tauri::command]
async fn run_privileged(
    state: tauri::State<'_, AppState>,
    action: PrivilegedAction,
) -> Result<PrivilegedReport, String> {
    match action {
        PrivilegedAction::NftList
        | PrivilegedAction::IptablesSave
        | PrivilegedAction::IptablesList => {
            let report =
                AsyncNet::blocking(move || Ok(collect_firewall(Some(action)))).await?;
            if let Some(msg) = elevate_failure(&report.notes) {
                return Err(msg);
            }
            Ok(PrivilegedReport::Firewall(report))
        }
        PrivilegedAction::ConntrackList => {
            let report = AsyncNet::blocking(move || Ok(collect_nat(Some(action)))).await?;
            if let Some(msg) = elevate_failure(&report.notes) {
                return Err(msg);
            }
            Ok(PrivilegedReport::Nat(report))
        }
        PrivilegedAction::SsList => {
            let cache = {
                let ptr = state.ptr.lock().map_err(|e| e.to_string())?;
                ptr.clone()
            };
            let ptr_slot = state.ptr.clone();
            let (report, pending, updated) = AsyncNet::blocking(move || {
                let mut cache = cache;
                let report = collect_connections(&mut cache, Some(action));
                let pending = cache.pending_public_ips(&report.rows, 6);
                Ok((report, pending, cache))
            })
            .await?;
            {
                let mut ptr = state.ptr.lock().map_err(|e| e.to_string())?;
                ptr.absorb(updated);
            }
            AsyncNet::resolve_ptrs_later(ptr_slot, pending);
            if let Some(msg) = elevate_failure(&report.notes) {
                return Err(msg);
            }
            Ok(PrivilegedReport::Connections(report))
        }
        PrivilegedAction::JournalResolved => {
            let monitor = {
                let map = state.dns_monitor.lock().map_err(|e| e.to_string())?;
                monitor_rows(&map)
            };
            let monitor_status = {
                let s = state.dns_monitor_status.lock().map_err(|e| e.to_string())?;
                s.clone()
            };
            let cache = {
                let ptr = state.ptr.lock().map_err(|e| e.to_string())?;
                ptr.clone()
            };
            let programs = {
                let g = state.dns_programs.lock().map_err(|e| e.to_string())?;
                g.clone()
            };
            let (report, updated_ptr, updated_programs) = AsyncNet::blocking(move || {
                let mut ptr = cache;
                let mut programs = programs;
                let conns = collect_connections(&mut ptr, None);
                let report = collect_boot_traffic(
                    &mut ptr,
                    &monitor,
                    &monitor_status,
                    &mut programs,
                    &conns.rows,
                    Some(action),
                );
                Ok((report, ptr, programs))
            })
            .await?;
            {
                let mut ptr = state.ptr.lock().map_err(|e| e.to_string())?;
                ptr.absorb(updated_ptr);
            }
            {
                let mut g = state.dns_programs.lock().map_err(|e| e.to_string())?;
                for (k, v) in updated_programs {
                    g.entry(k).or_insert(v);
                }
            }
            if let Some(msg) = elevate_failure(&report.limitations) {
                return Err(msg);
            }
            Ok(PrivilegedReport::Boot(report))
        }
        PrivilegedAction::Traceroute => Err(
            "La ruta se eleva con el botón del panel (pkexec + traceroute), no con un comando libre."
                .into(),
        ),
    }
}

#[tauri::command]
async fn get_listeners(state: tauri::State<'_, AppState>) -> Result<ListenersReport, String> {
    let scan = AsyncNet::blocking(|| Ok(ListenerSession::collect_rows())).await?;
    let mut session = state.listeners.lock().map_err(|e| e.to_string())?;
    Ok(session.finish_report(scan))
}

#[tauri::command]
fn dismiss_listener(state: tauri::State<AppState>, key: String) -> Result<(), String> {
    let mut session = state.listeners.lock().map_err(|e| e.to_string())?;
    session.dismiss(&key);
    Ok(())
}

#[tauri::command(async)]
fn lookup_remote_ip(
    state: tauri::State<AppState>,
    ip: String,
    allow_external: bool,
) -> Result<GeoInfo, String> {
    if !allow_external {
        return Err(geo_opt_in_denied_message().into());
    }
    let ip = ip.trim().to_string();
    {
        let geo = state.geo.lock().map_err(|e| e.to_string())?;
        if let Some(hit) = geo.get(&ip) {
            return Ok(hit);
        }
    }
    let delay = {
        let mut geo = state.geo.lock().map_err(|e| e.to_string())?;
        geo.take_rate_delay()
    };
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
    {
        let mut geo = state.geo.lock().map_err(|e| e.to_string())?;
        geo.mark_rate();
        if let Some(hit) = geo.get(&ip) {
            return Ok(hit);
        }
    }
    // HTTP fuera de cualquier lock.
    let info = lookup_ip_external(&ip).map_err(map_err)?;
    {
        let mut geo = state.geo.lock().map_err(|e| e.to_string())?;
        geo.insert(ip, info.clone());
    }
    Ok(info)
}

#[tauri::command]
fn start_trace_route(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    destination: String,
    elevated: Option<bool>,
) -> Result<String, String> {
    let (dest, session_id) = alloc_trace_session(&destination).map_err(map_err)?;
    if let Some(flag) = state.trace_cancel.lock().map_err(|e| e.to_string())?.take() {
        flag.store(true, Ordering::Relaxed);
    }
    let cancel = Arc::new(AtomicBool::new(false));
    *state.trace_cancel.lock().map_err(|e| e.to_string())? = Some(cancel.clone());
    let gw = default_gateway();
    let elevate = elevated.unwrap_or(false);
    let sid = session_id.clone();
    std::thread::spawn(move || {
        let _ = start_trace(&dest, gw.as_deref(), cancel, elevate, sid, |ev| {
            let _ = app.emit("trace-progress", ev);
        });
    });
    Ok(session_id)
}

#[tauri::command]
fn cancel_trace_route(state: tauri::State<AppState>) -> Result<(), String> {
    if let Some(flag) = state
        .trace_cancel
        .lock()
        .map_err(|e| e.to_string())?
        .as_ref()
    {
        flag.store(true, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir)?;
            let db = dir.join("senal.db");
            let core = AppCore::open(db).map_err(|e| e.to_string())?;
            let dns_monitor = Arc::new(Mutex::new(HashMap::new()));
            let dns_monitor_status = Arc::new(Mutex::new(DnsMonitorStatus::default()));
            let dns_cancel = Arc::new(AtomicBool::new(false));
            spawn_dns_monitor(dns_monitor.clone(), dns_monitor_status.clone(), dns_cancel);
            app.manage(AppState {
                core: Mutex::new(core),
                ptr: Arc::new(Mutex::new(PtrCache::default())),
                geo: Mutex::new(GeoCache::default()),
                listeners: Mutex::new(ListenerSession::default()),
                trace_cancel: Mutex::new(None),
                dns_monitor,
                dns_monitor_status,
                dns_programs: Mutex::new(HashMap::new()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            rescan_nearby,
            sweep_lan,
            get_history,
            get_connections,
            get_nat,
            get_firewall,
            get_boot_traffic,
            get_listeners,
            dismiss_listener,
            lookup_remote_ip,
            start_trace_route,
            cancel_trace_route,
            run_privileged
        ])
        .run(tauri::generate_context!())
        .expect("error al iniciar Señal");
}
