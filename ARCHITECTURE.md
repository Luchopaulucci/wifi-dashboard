# Arquitectura de Señal

Señal separa la recolección de datos del shell de escritorio para poder crecer sin reescribir el núcleo.

```
src/                  UI web (React + TypeScript + Vite + Tailwind)
                      reusable más adelante como vista web liviana
src-tauri/            Shell Tauri 2: ventana, IPC local, ciclo de vida
crates/wifi-core/     Crate `core`: parsers, colectores, SQLite, OUI, mocks
```

## Hoy (v1)

- `wifi-core` habla con herramientas de usuario (`nmcli`, `iw`, `ip`, `ping`) **sin shell** y con argumentos validados.
- El historial de latencia vive en SQLite local (retención ~8 días).
- Tauri solo expone comandos `get_snapshot`, `rescan_nearby`, `sweep_lan`, `get_history`. No hay servidor HTTP escuchando. El dev server de Vite queda en `127.0.0.1`.
- Si no hay interfaz WiFi (o `WIFI_DASHBOARD_MOCK=1`), el core entrega un snapshot marcado como **modo simulado**.

## Después

1. **Módulo MikroTik (RouterOS API)**  
   Otro colector dentro de `wifi-core` (o `crates/mikrotik`) que lea interfaces, DHCP leases y wireless desde el router. El shell Tauri solo suma una pestaña; la UI web puede reutilizar los mismos tipos.

2. **Agente headless**  
   Un binario `senal-agent` que dependa de `wifi-core`, corra sin GUI y empuje snapshots a una vista web en la nube. El crate ya no depende de Tauri, así que el agente no arrastra WebKit.

3. **Vista web liviana**  
   El frontend de `src/` ya oculta el transporte detrás de `src/lib/client.ts`. Sustituir `invoke` por `fetch` a una API propia alcanza para el modo nube.

## Invariantes

- Nunca root. Si hace falta ICMP raw, documentar `cap_net_raw` sobre `ping`, no `sudo`.
- El barrido de LAN solo cubre la subred conectada, y como máximo una /24.
- Los parsers se testean con fixtures reales (`nmcli` / `iw` / `ip neigh` / `ping`).
