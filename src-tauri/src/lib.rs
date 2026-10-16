use std::sync::Mutex;

use tauri::Manager;
use wifi_core::{AppCore, HistoryPoint, HistoryRange, Snapshot};

struct AppState {
    core: Mutex<AppCore>,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir)?;
            let db = dir.join("senal.db");
            let core = AppCore::open(db).map_err(|e| e.to_string())?;
            app.manage(AppState {
                core: Mutex::new(core),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            rescan_nearby,
            sweep_lan,
            get_history
        ])
        .run(tauri::generate_context!())
        .expect("error al iniciar Señal");
}
