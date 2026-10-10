# Señal

Panel de escritorio para Linux (pensado para una Lenovo IdeaPad con Ubuntu + NetworkManager) que muestra **tu WiFi en vivo**, las **redes de alrededor**, **monitoreo** de latencia y los **equipos de tu LAN**.

Proyecto personal de Luciano. La UI y esta guía están en castellano (Argentina). Más adelante puede ser público.

## Qué hace cada módulo

1. **Tu WiFi en vivo** — SSID, BSSID, señal (dBm y %), canal, banda (2.4 / 5 / 6 GHz), velocidad del enlace, IP, puerta de enlace y DNS. Fuentes: `nmcli`, `iw` y `/proc/net/wireless`. Se refresca cada pocos segundos.
2. **Redes de alrededor** — escaneo (`nmcli dev wifi list`) con rescan limitado a 15 s. Tabla + gráfico de congestión por banda. En 2.4 GHz se dibuja el solapamiento de 20 MHz.
3. **Monitoreo** — ping a la puerta de enlace, `1.1.1.1` y `8.8.8.8`. Historial en SQLite local (última hora / día / semana) con retención de ~8 días.
4. **Equipos en tu red** — vecinos de `ip neigh` y, si lo pedís, un barrido liviano de ping **solo** de la /24 a la que estás conectado. Nombres por mDNS (`avahi-resolve-address`) o DNS inverso. Fabricante vía archivo OUI empaquetado.

## Requisitos (Ubuntu)

```bash
sudo apt update
sudo apt install -y \
  libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev patchelf \
  network-manager iw iproute2 iputils-ping
```

Opcional para resolver nombres .local:

```bash
sudo apt install -y avahi-utils
```

También hace falta **Rust** (stable) y **Node.js 22**.

En otras distros la app degrada: si no está `nmcli` usa `iw` / `ip`; si no hay interfaz WiFi entra en **modo simulado** (marcado en la UI).

## Desarrollo

```bash
git checkout develop
npm install
npm run tauri dev
```

La UI web (sin ventana nativa) también corre con `npm run dev` y queda en `http://127.0.0.1:1420`. Sin Tauri se usan datos de ejemplo, claramente etiquetados como **Modo simulado**.

Forzar mock aunque haya WiFi:

```bash
WIFI_DASHBOARD_MOCK=1 npm run tauri dev
```

Checks locales:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm test
npm run build
cargo build -p senal
# empaquetado (más lento):
npm run tauri build
```

## Empaquetar .deb / AppImage

```bash
npm install
npm run tauri build
```

Los artefactos quedan en `src-tauri/target/release/bundle/deb` y `.../appimage` (o `target/release/bundle/...` si compilás desde el workspace).

## Permisos y seguridad

- **No corre como root.** No uses `sudo` para lanzar Señal.
- Los comandos se ejecutan con `std::process::Command` y una allowlist (`nmcli`, `iw`, `ip`, `ping`, `avahi-resolve-address`). No hay interpolación en shell. Interfaz e IPv4 se validan antes de pasarlas como argumento.
- No hay servidor de red escuchando. El IPC de Tauri es local. Vite en desarrollo escucha solo en `127.0.0.1`.
- El barrido de equipos **nunca** sale de tu subred conectada y se recorta a /24.
- `ping` en Ubuntu suele ser setuid y alcanza para ICMP de usuario. Si en tu distro falla, preferí una capability sobre el binario del sistema, no root:

  ```bash
  # ejemplo, solo si ping no funciona como usuario
  sudo setcap cap_net_raw+ep "$(command -v ping)"
  ```

- Base SQLite en el directorio de datos de la app (no se comparte).

## Rama

El trabajo vivo está en **`develop`**. No se publica ni se hace release desde acá.

## Licencia

MIT. Ver `LICENSE`.
