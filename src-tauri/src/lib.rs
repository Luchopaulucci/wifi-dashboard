use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tauri::{Emitter, Manager};
use wifi_core::net::{
    collect_boot_traffic, collect_connections, collect_firewall, collect_listeners, collect_nat,
    default_gateway, geo_opt_in_denied_message, lookup_ip_external, monitor_rows,
    spawn_dns_monitor, start_trace, BootTrafficReport, ConnectionsReport, DnsMonitorStatus,
    DnsProgramRow, FirewallReport, GeoCache, GeoInfo, ListenerSession, ListenersReport, NatReport,
    PtrCache,
};
use wifi_core::{validate_host, AppCore, HistoryPoint, HistoryRange, Snapshot};

struct AppState {
    core: Mutex<AppCore>,
    ptr: Mutex<PtrCache>,
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
fn sweep_lan(state: tauri::State<AppState>) -> Result<Snapshot, String> {
    let mut core = state.core.lock().map_err(|e| e.to_string())?;
    core.sweep_lan().map_err(map_err)
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

#[tauri::command(async)]
fn get_connections(state: tauri::State<AppState>) -> Result<ConnectionsReport, String> {
    let mut ptr = state.ptr.lock().map_err(|e| e.to_string())?;
    Ok(collect_connections(&mut ptr))
}

#[tauri::command(async)]
fn get_nat() -> Result<NatReport, String> {
    Ok(collect_nat())
}

#[tauri::command(async)]
fn get_firewall() -> Result<FirewallReport, String> {
    Ok(collect_firewall())
}

#[tauri::command(async)]
fn get_boot_traffic(state: tauri::State<AppState>) -> Result<BootTrafficReport, String> {
    let monitor = {
        let map = state.dns_monitor.lock().map_err(|e| e.to_string())?;
        monitor_rows(&map)
    };
    let monitor_status = {
        let s = state.dns_monitor_status.lock().map_err(|e| e.to_string())?;
        s.clone()
    };
    let mut ptr = state.ptr.lock().map_err(|e| e.to_string())?;
    let conns = collect_connections(&mut ptr);
    let mut programs = state.dns_programs.lock().map_err(|e| e.to_string())?;
    Ok(collect_boot_traffic(
        &mut ptr,
        &monitor,
        &monitor_status,
        &mut programs,
        &conns.rows,
    ))
}

#[tauri::command(async)]
fn get_listeners(state: tauri::State<AppState>) -> Result<ListenersReport, String> {
    let mut session = state.listeners.lock().map_err(|e| e.to_string())?;
    Ok(collect_listeners(&mut session))
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
            let dns_monitor_status = Arc::new(Mutex::new(DnsMonitorStatus::default()));
            let dns_cancel = Arc::new(AtomicBool::new(false));
            spawn_dns_monitor(dns_monitor.clone(), dns_monitor_status.clone(), dns_cancel);
            app.manage(AppState {
                core: Mutex::new(core),
                ptr: Mutex::new(PtrCache::default()),
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
            cancel_trace_route
        ])
        .run(tauri::generate_context!())
        .expect("error al iniciar Señal");
}
