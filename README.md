# Señal

Panel de escritorio para Linux (pensado para una Lenovo IdeaPad con Ubuntu + NetworkManager) que muestra **tu WiFi en vivo**, las **redes de alrededor**, **monitoreo** de latencia, los **equipos de tu LAN** y pestañas de solo lectura de **conexiones, NAT, firewall, ruta, DNS/tráfico desde el arranque y puertos abiertos**.

Proyecto personal de Luciano. La UI y esta guía están en castellano (Argentina). Más adelante puede ser público.

## Qué hace cada módulo

1. **Tu WiFi en vivo** — SSID, BSSID, señal (dBm y %), canal, banda (2.4 / 5 / 6 GHz), velocidad del enlace, IP, puerta de enlace y DNS. Fuentes: `nmcli`, `iw` y `/proc/net/wireless`. Se refresca cada pocos segundos.
2. **Redes de alrededor** — escaneo (`nmcli dev wifi list`) con rescan limitado a 15 s. Tabla + gráfico de congestión por banda. En 2.4 GHz se dibuja el solapamiento de 20 MHz.
3. **Monitoreo** — ping a la puerta de enlace, `1.1.1.1` y `8.8.8.8`. Historial en SQLite local (última hora / día / semana) con retención de ~8 días.
4. **Equipos en tu red** — vecinos de `ip neigh` y, si lo pedís, un barrido liviano de ping **solo** de la /24 a la que estás conectado. Nombres por mDNS (`avahi-resolve-address`) o DNS inverso. Fabricante vía archivo OUI empaquetado.
5. **Conexiones** — tabla en vivo de `ss -tunap`: proceso, IP + dominio destino (PTR / caché DNS), puerto, protocolo, estado. Filtro por programa. Clic en una fila: país y ASN vía consulta externa cacheada (ip-api.com / RDAP).
6. **NAT** — traducciones de `conntrack -L` o `/proc/net/nf_conntrack`: IP interna, con qué IP sale, destino, timeout restante, SNAT/DNAT.
7. **Firewall** — `nft list ruleset` (fallback `iptables-save -c` / `iptables -S`), reglas por tabla/cadena, explicación en criollo y contadores accept vs drop.
8. **Ruta** — traceroute/tracepath a un destino que elijas, hops con RTT en streaming. Marca router de casa, primer hop público (ISP) y pérdidas (`*`).
9. **Desde que prende** — contadores de `/proc/net/snmp`, `/proc/net/netstat`, `/proc/net/dev`; DNS de `resolvectl statistics` / caché / journal / monitor. Habladores de fondo (updates, telemetría) con lista curada. Cada número dice qué significa y de dónde sale.
10. **Puertos abiertos** — `ss -tulpn`, local-only vs alcanzable desde la red, aviso si aparece un LISTEN nuevo en esta sesión.

En todas esas pestañas hay **Explicame esto** (notas de curso de redes). Si un comando pide root/CAP_NET_ADMIN, la UI abre el diálogo de contraseña del sistema con `pkexec`: **nunca se lanza Señal como root ni se cambia el firewall**.

## Requisitos (Ubuntu / Debian)

Hace falta **Rust** (stable, vía rustup), **Node.js 22** y las libs de Tauri 2.

Rust (no uses el paquete `rustc` de apt: suele estar viejo o incompleto):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

Cerrá y reabrí la terminal, o ejecutá `source ~/.cargo/env` en cada sesión nueva, hasta que `rustc --version` y `cargo --version` respondan.

Libs de Tauri 2:

```bash
sudo apt update
sudo apt install -y build-essential curl wget file libssl-dev libgtk-3-dev \
  libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev
```

Para que los módulos de red funcionen de verdad (no solo el modo simulado):

```bash
sudo apt install -y network-manager iw iproute2 iputils-ping
```

Opcional para las pestañas de diagnóstico (si falta el binario, la pestaña lo dice y no rompe el resto):

```bash
sudo apt install -y conntrack iputils-tracepath traceroute
```

Opcional para resolver nombres `.local`:

```bash
sudo apt install -y avahi-utils
```

En otras distros la app degrada: si no está `nmcli` usa `iw` / `ip`; si no hay interfaz WiFi entra en **modo simulado** (marcado en la UI).

## Desarrollo

```bash
git checkout develop
npm install
npm run tauri dev
```

Ese es el comando correcto: **`npm run tauri dev`** levanta el backend de Rust y la ventana nativa. **`npm run dev` no alcanza**: solo arranca Vite (la UI en `http://127.0.0.1:1420`) **sin el backend**. Ahí no hay `nmcli`/`iw`/SQLite; ves datos de ejemplo etiquetados como **Modo simulado**.

La **primera compilación tarda** (baja y compila Tauri, WebKit bindings y el crate). Las siguientes son más rápidas.

### Troubleshooting

Si ves `failed to run 'cargo metadata' ... No such file or directory` (o `cargo: command not found`), **falta Rust**. Instalá rustup como arriba, corré `source ~/.cargo/env` y volvé a intentar `npm run tauri dev`.

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
- Los comandos se ejecutan con `std::process::Command` y una allowlist (`nmcli`, `iw`, `ip`, `ping`, `avahi-resolve-address`, `ss`, `conntrack`, `nft`, `iptables`, `iptables-save`, `traceroute`, `tracepath`, `resolvectl`, `journalctl`, `pkexec`). No hay interpolación en shell. Interfaz, IPv4 y destinos de traceroute se validan antes de pasarlos como argumento. Nada de eso escribe reglas, flushea conntrack ni captura paquetes.
- No hay servidor de red escuchando. El IPC de Tauri es local. Vite en desarrollo escucha solo en `127.0.0.1`.
- El barrido de equipos **nunca** sale de tu subred conectada y se recorta a /24.
- `ping` en Ubuntu suele ser setuid y alcanza para ICMP de usuario. Si en tu distro falla, preferí una capability sobre el binario del sistema, no root:

  ```bash
  # ejemplo, solo si ping no funciona como usuario
  sudo setcap cap_net_raw+ep "$(command -v ping)"
  ```

- `nft list ruleset` y `conntrack -L` suelen pedir **CAP_NET_ADMIN**. La UI lo explica y, si hace falta, lanza esa acción puntual con `pkexec` (el sistema pide la contraseña). No hay `setcap` ni hay que copiar comandos sudo.

  No hace falta (ni conviene) abrir Señal con sudo. El lookup de país/ASN es una consulta **externa** (ip-api.com), cacheada y limitada.

- Base SQLite en el directorio de datos de la app (no se comparte).

## Rama

El trabajo vivo está en **`develop`**. No se publica ni se hace release desde acá.

## Licencia

MIT. Ver `LICENSE`.
