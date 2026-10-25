import type { TabId } from "./types";

export const EXPLAIN: Record<
  TabId,
  { title: string; body: string[] }
> = {
  live: {
    title: "Tu WiFi, en criollo",
    body: [
      "SSID es el nombre de la red; BSSID es la MAC del access point al que estás asociado (un router puede tener varios).",
      "La señal en dBm es logarítmica: -50 está excelente, -70 va justo, -90 es milagro que ande. El porcentaje es una regla lineal aproximada sobre eso.",
      "Canal y banda: 2.4 GHz llega más lejos y se pisa entre vecinos; 5/6 GHz son más anchos y más locales.",
    ],
  },
  nearby: {
    title: "Redes de alrededor",
    body: [
      "El escaneo lista beacons de WiFi. En 2.4 GHz un AP de 20 MHz no usa un solo canal: pisa ±2 o más, por eso el gráfico de congestión marca solapamiento.",
    ],
  },
  monitor: {
    title: "Latencia",
    body: [
      "Ping mide RTT (ida y vuelta). Jitter es cuánto varía. Pérdida es paquetes que no volvieron. Guardamos historial local en SQLite, no en la nube.",
    ],
  },
  devices: {
    title: "Equipos de la LAN",
    body: [
      "ARP/neigh son vecinos de TU subred. El barrido solo pisa la /24 conectada. No es un port-scan de Internet.",
    ],
  },
  connections: {
    title: "Conexiones (sockets)",
    body: [
      "Cada fila es un socket: un extremo local (tu PC) y uno remoto (la otra punta). TCP tiene estados: ESTABLISHED es la conversación viva; TIME_WAIT es el cierre que todavía espera por si llegó un paquete tardío; LISTEN es 'estoy atendiendo' (eso va a Puertos abiertos).",
      "El proceso/PID lo saca `ss` del inode del socket. Si no hay nombre, o es de otro usuario, o el proceso ya cerró.",
      "El dominio no viaja en el paquete IP: o hacemos DNS inverso (PTR), que a menudo miente o no existe, o lo mapeamos a una respuesta DNS que vimos (caché de systemd-resolved / journal). Por eso a veces ves IP pelada.",
      "País y ASN: no están en tu kernel. Hay un switch opt-in (apagado de fábrica). Si lo prendés y hacés clic, consultamos RDAP por HTTPS (rdap.org) y se envía SOLO esa IP pública. Cacheado, ~1 pedido cada 1,5 s. Es una pista, no una prueba judicial: los anycast y los CGNAT mienten el 'dónde'.",
      "UDP casi no tiene estado: UNCONN es típico de DNS o DHCP.",
    ],
  },
  nat: {
    title: "NAT, traducciones",
    body: [
      "NAT reescribe direcciones. En una notebook 'común' casi no hay NAT propio: lo hace el router. Si esta PC comparte Internet (hotspot, libvirt, Docker, LXD), sí vas a ver SNAT/masquerade.",
      "Tuple original: IP:puerto de adentro → destino. Tuple reply: cómo vuelve el paquete. Si orig.src ≠ reply.dst, alguien reescribió el origen (SNAT). Si orig.dst ≠ reply.src, reescribió el destino (DNAT, port-forward).",
      "El timeout de conntrack no es 'cuánto lleva abierta': es cuántos segundos le quedan de vida si no hay más tráfico. ESTABLISHED/ASSURED dura mucho; UDP, poco.",
      "Leer conntrack pide CAP_NET_ADMIN. Señal no corre como root: el panel pide la contraseña del sistema con pkexec y solo lista. No recomendamos setcap (dejaría reescribir NAT).",
    ],
  },
  firewall: {
    title: "Firewall (nft/iptables)",
    body: [
      "Un firewall es una lista de reglas que se evalúan en orden, por cadena (input = entra a esta máquina, output = sale, forward = la máquina rutea, prerouting/postrouting = NAT).",
      "Política (policy): qué pasa si ninguna regla matchea. DROP = agujero negro; ACCEPT = deja pasar. Las distros desktop suelen ACCEPT en output y filtrar input.",
      "nftables es el backend moderno; iptables en Ubuntu 22.04+ suele ser un traductor encima de nft. Listamos nft, y si no se puede, iptables-save / iptables -S.",
      "Los contadores (packets/bytes) solo existen si la regla tiene `counter` o si vino de `iptables-save -c`. Si ves '—', no es que no hubo tráfico: es que nadie pidió llevar la cuenta.",
      "Accept vs drop del resumen suma esos contadores por veredicto. No es un IDS ni te dice 'esta app fue bloqueada'.",
      "Todo esto es SOLO LECTURA. Señal nunca agrega, borra ni flushea reglas.",
    ],
  },
  route: {
    title: "Ruta (traceroute)",
    body: [
      "Traceroute manda paquetes con TTL 1, 2, 3… Cada router que se le vence el TTL debería devolver ICMP Time Exceeded. Con eso armamos la lista de hops y el RTT.",
      "El primer hop privado suele ser tu router de casa. El primer hop con IP pública es, en la práctica, 'donde arranca el ISP' (el CMTS, el BNG, el primer router de Fibertel/Telecentro/Telecom, etc.).",
      "Un hop con * es pérdida o un router que no responde ICMP (muchos no contestan a propósito). No siempre es 'la red está rota'.",
      "En Ubuntu el default es tracepath (UDP, suele andar sin root); si no está, usamos traceroute. `pmtu 1492` y `asymm 9` no son RTT. Un hop con * o 'no reply' es pérdida o un router que no contesta ICMP. No es un speedtest: es el camino, con una muestra de latencia por hop.",
    ],
  },
  boot: {
    title: "Desde que prende la PC",
    body: [
      "El kernel lleva contadores en /proc/net/snmp y /proc/net/netstat desde que arrancó. Tcp.ActiveOpens ≈ 'cuántas conexiones TCP iniciamos'. Udp.OutDatagrams mezcla DNS, QUIC, mDNS, todo.",
      "systemd-resolved tiene OTRO reloj: `resolvectl statistics` cuenta desde que arrancó el servicio, que puede no coincidir con el boot (si se reinició resolved, vuelve a 0).",
      "Dominio por programa desde el boot NO existe en Linux de forma gratis. Haría falta tcpdump/auditd (root o CAP_NET_RAW) y Señal no va a snifar: si falta permiso, la UI lo dice. Lo que sí hacemos: historial de programas que hablaron con :53/:853 en esta sesión, journal desde el boot (filtrando .arpa / home.arpa), caché de resolved, y `resolvectl monitor` si arranca (si falla sin root, se muestra el error).",
      "Los 'habladores de fondo' se marcan con una lista curada (Ubuntu metrics, snap, telemetría de browsers, NTP, OCSP…). Un falso positivo es posible: un CDN sirve de todo.",
    ],
  },
  ports: {
    title: "Puertos abiertos (LISTEN)",
    body: [
      "Un puerto en LISTEN es un proceso esperando conexiones. `ss -tulpn` los lista (TCP y UDP).",
      "127.0.0.1 / ::1 = solo esta máquina (el resto de la LAN no entra). 0.0.0.0 / :: = en todas las interfaces, o sea alcanzable desde la red local (y desde Internet SOLO si el router hace port-forward o estás expuesto).",
      "Una IP de tu LAN (192.168.x) en LISTEN = alcanzable por tus vecinos de WiFi, no por 'todo Internet' salvo NAT invertido.",
      "El aviso de 'apareció uno nuevo' es contra la foto inicial de esta sesión (no contra el poll anterior). UDP efímero (puertos altos de clientes) se ignora. La alerta queda hasta que la descartes; reabrir el mismo puerto/proceso no vuelve a alertar. Reiniciar Señal olvida esa foto. No es un IDS permanente.",
    ],
  },
};
