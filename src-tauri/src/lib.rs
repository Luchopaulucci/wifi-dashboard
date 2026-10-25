use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tauri::{Emitter, Manager};
use wifi_core::net::{
    collect_boot_traffic, collect_connections, collect_firewall, collect_listeners, collect_nat,
    default_gateway, listener_keys, monitor_rows, spawn_dns_monitor, start_trace,
    BootTrafficReport, ConnectionsReport, FirewallReport, GeoCache, GeoInfo, ListenersReport,
    NatReport, PtrCache,
};
use wifi_core::{validate_host, AppCore, HistoryPoint, HistoryRange, Snapshot};

struct AppState {
    core: Mutex<AppCore>,
    ptr: Mutex<PtrCache>,
    geo: Mutex<GeoCache>,
    listeners: Mutex<Option<HashSet<String>>>,
    trace_cancel: Mutex<Option<Arc<AtomicBool>>>,
    dns_monitor: Arc<Mutex<HashMap<String, u64>>>,
}

fn map_err(err: wifi_core::CoreError) -> String {
    err.to_string()
}

#[tauri::command]
fn get_snapshot(state: tauri::State<AppState>) -> Result<Snapshot, String> {
    let mut core = state.core.lock().map_err(|e| e.to_string())?;
    core.snapshot().map_err(map_err)
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
    let mut core = state.core.lock().map_err(|e| e.to_string())?;
    core.snapshot_with_devices(devices).map_err(map_err)
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
fn get_connections(state: tauri::State<AppState>) -> Result<ConnectionsReport, String> {
    let mut ptr = state.ptr.lock().map_err(|e| e.to_string())?;
    Ok(collect_connections(&mut ptr))
}

#[tauri::command]
fn get_nat() -> Result<NatReport, String> {
    Ok(collect_nat())
}

#[tauri::command]
fn get_firewall() -> Result<FirewallReport, String> {
    Ok(collect_firewall())
}

#[tauri::command]
fn get_boot_traffic(state: tauri::State<AppState>) -> Result<BootTrafficReport, String> {
    let monitor = {
        let map = state.dns_monitor.lock().map_err(|e| e.to_string())?;
        monitor_rows(&map)
    };
    let mut ptr = state.ptr.lock().map_err(|e| e.to_string())?;
    let conns = collect_connections(&mut ptr);
    Ok(collect_boot_traffic(&monitor, &conns.rows))
}

#[tauri::command]
fn get_listeners(state: tauri::State<AppState>) -> Result<ListenersReport, String> {
    let mut prev = state.listeners.lock().map_err(|e| e.to_string())?;
    let report = collect_listeners(prev.as_ref());
    *prev = Some(listener_keys(&report.rows));
    Ok(report)
}

#[tauri::command]
fn lookup_remote_ip(state: tauri::State<AppState>, ip: String) -> Result<GeoInfo, String> {
    let mut geo = state.geo.lock().map_err(|e| e.to_string())?;
    geo.get_or_lookup(ip.trim()).map_err(map_err)
}

#[tauri::command]
fn start_trace_route(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    destination: String,
) -> Result<String, String> {
    let dest = validate_host(&destination).map_err(map_err)?;
    if let Some(flag) = state.trace_cancel.lock().map_err(|e| e.to_string())?.take() {
        flag.store(true, Ordering::Relaxed);
    }
    let cancel = Arc::new(AtomicBool::new(false));
    *state.trace_cancel.lock().map_err(|e| e.to_string())? = Some(cancel.clone());
    let gw = default_gateway();
    std::thread::spawn(move || {
        let _ = start_trace(&dest, gw.as_deref(), cancel, |ev| {
            let _ = app.emit("trace-progress", ev);
        });
    });
    Ok("ok".into())
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
            let dns_cancel = Arc::new(AtomicBool::new(false));
            spawn_dns_monitor(dns_monitor.clone(), dns_cancel);
            app.manage(AppState {
                core: Mutex::new(core),
                ptr: Mutex::new(PtrCache::default()),
                geo: Mutex::new(GeoCache::default()),
                listeners: Mutex::new(None),
                trace_cancel: Mutex::new(None),
                dns_monitor,
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
            lookup_remote_ip,
            start_trace_route,
            cancel_trace_route
        ])
        .run(tauri::generate_context!())
        .expect("error al iniciar Señal");
}
