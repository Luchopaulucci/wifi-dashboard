import type {
  BootTrafficReport,
  ConnectionsReport,
  FirewallReport,
  GeoInfo,
  ListenersReport,
  NatReport,
  TraceEvent,
} from "./types";

export function mockConnections(): ConnectionsReport {
  return {
    collected_at_ms: Date.now(),
    sources: ["ss -tunap (simulado)"],
    missing: [],
    privilege: null,
    notes: ["Modo simulado: no es el tráfico de tu IdeaPad."],
    rows: [
      {
        protocol: "tcp",
        local_ip: "192.168.0.24",
        local_port: "45678",
        remote_ip: "1.1.1.1",
        remote_port: "443",
        state: "ESTABLISHED",
        process: "firefox",
        pid: 4321,
        domain: "one.one.one.one",
        domain_source: "DNS inverso (PTR)",
      },
      {
        protocol: "tcp",
        local_ip: "192.168.0.24",
        local_port: "45679",
        remote_ip: "142.250.184.14",
        remote_port: "443",
        state: "ESTABLISHED",
        process: "firefox",
        pid: 4321,
        domain: "www.google.com",
        domain_source: "respuesta DNS observada (cache/journal)",
      },
      {
        protocol: "udp",
        local_ip: "192.168.0.24",
        local_port: "53122",
        remote_ip: "1.1.1.1",
        remote_port: "53",
        state: "ESTAB",
        process: "systemd-resolve",
        pid: 612,
        domain: null,
        domain_source: null,
      },
      {
        protocol: "tcp",
        local_ip: "192.168.0.24",
        local_port: "40112",
        remote_ip: "185.199.108.153",
        remote_port: "443",
        state: "TIME_WAIT",
        process: "code",
        pid: 2201,
        domain: "github.com",
        domain_source: "DNS inverso (PTR)",
      },
    ],
  };
}

export function mockNat(): NatReport {
  return {
    collected_at_ms: Date.now(),
    active_count: 3,
    snat_count: 1,
    dnat_count: 1,
    source: "conntrack -L (simulado)",
    missing: [],
    privilege: null,
    notes: [],
    translations: [
      {
        protocol: "tcp",
        internal_ip: "192.168.0.24",
        internal_port: "45678",
        translated_ip: "192.168.0.24",
        translated_port: "45678",
        dest_ip: "1.1.1.1",
        dest_port: "443",
        state: "ESTABLISHED",
        timeout_secs: 431999,
        nat_kind: "ninguno",
        assured: true,
      },
      {
        protocol: "tcp",
        internal_ip: "10.0.0.5",
        internal_port: "12345",
        translated_ip: "181.15.20.30",
        translated_port: "12345",
        dest_ip: "8.8.8.8",
        dest_port: "443",
        state: "ESTABLISHED",
        timeout_secs: 120,
        nat_kind: "SNAT",
        assured: true,
      },
      {
        protocol: "tcp",
        internal_ip: "192.168.0.24",
        internal_port: "40000",
        translated_ip: "192.168.0.24",
        translated_port: "40000",
        dest_ip: "203.0.113.10",
        dest_port: "80",
        state: "ESTABLISHED",
        timeout_secs: 89,
        nat_kind: "DNAT",
        assured: false,
      },
    ],
  };
}

export function mockFirewall(): FirewallReport {
  return {
    collected_at_ms: Date.now(),
    backend: "nft list ruleset (simulado)",
    accepted_packets: 1230,
    accepted_bytes: 456000,
    dropped_packets: 22,
    dropped_bytes: 1240,
    missing: [],
    privilege: null,
    notes: [],
    tables: [
      {
        name: "filter",
        family: "inet",
        chains: [
          {
            name: "input",
            hook: "input",
            policy: "drop",
            policy_packets: 10,
            policy_bytes: 400,
            rules: [
              {
                table: "filter",
                family: "inet",
                chain: "input",
                handle: null,
                text: "ct state established,related accept",
                criollo:
                  "Deja pasar lo que ya es una conversación abierta y lo relacionado. Accept: lo deja pasar.",
                packets: 1230,
                bytes: 456000,
                verdict: "accept",
              },
              {
                table: "filter",
                family: "inet",
                chain: "input",
                handle: null,
                text: 'iif "lo" accept',
                criollo: "Entra por loopback: la PC hablándose a sí misma. Accept: lo deja pasar.",
                packets: 40,
                bytes: 2400,
                verdict: "accept",
              },
              {
                table: "filter",
                family: "inet",
                chain: "input",
                handle: null,
                text: "tcp dport 22 accept",
                criollo: "Puerto de destino 22 (TCP SSH). Accept: lo deja pasar.",
                packets: 2,
                bytes: 120,
                verdict: "accept",
              },
              {
                table: "filter",
                family: "inet",
                chain: "input",
                handle: null,
                text: "counter packets 12 bytes 840 drop",
                criollo: "Drop: lo tira a la basura, sin avisar. Para el otro es un agujero negro.",
                packets: 12,
                bytes: 840,
                verdict: "drop",
              },
            ],
          },
        ],
      },
      {
        name: "nat",
        family: "ip",
        chains: [
          {
            name: "postrouting",
            hook: "postrouting",
            policy: "accept",
            policy_packets: null,
            policy_bytes: null,
            rules: [
              {
                table: "nat",
                family: "ip",
                chain: "postrouting",
                handle: null,
                text: 'oifname "wlan0" masquerade',
                criollo:
                  "Solo si sale por wlan0. Masquerade/SNAT: cuando sale, disfraza la IP interna con la IP pública de la interfaz.",
                packets: 20,
                bytes: 1600,
                verdict: "masquerade",
              },
            ],
          },
        ],
      },
    ],
  };
}

export function mockBootTraffic(): BootTrafficReport {
  return {
    collected_at_ms: Date.now(),
    missing: [],
    privilege: null,
    dns_monitor: {
      running: true,
      error: null,
      needs_privilege: false,
      explanation: "Modo simulado: el monitor DNS aparece como si estuviera corriendo.",
    },
    limitations: [
      "Modo simulado. En la IdeaPad los números salen de /proc/net/* y systemd-resolved.",
      "Linux no guarda dominio×proceso desde el boot sin sniffer; Señal no captura paquetes.",
    ],
    counters: [
      {
        id: "tcp_active_opens",
        label: "Conexiones TCP salientes (ActiveOpens)",
        value: 1500,
        meaning: "TCP que esta PC inició desde el arranque del kernel.",
        source: "/proc/net/snmp → Tcp.ActiveOpens",
      },
      {
        id: "resolved_queries",
        label: "Consultas DNS (systemd-resolved)",
        value: 847,
        meaning: "Desde que arrancó resolved, no necesariamente desde el boot de la PC.",
        source: "resolvectl statistics",
      },
    ],
    domains: [
      {
        domain: "www.google.com",
        count: 12,
        source: "resolvectl show-cache",
        talker: null,
      },
      {
        domain: "metrics.ubuntu.com",
        count: 4,
        source: "journalctl -u systemd-resolved",
        talker: { label: "Telemetría de Ubuntu", kind: "telemetria" },
      },
      {
        domain: "api.snapcraft.io",
        count: 3,
        source: "resolvectl monitor (mientras Señal está abierta)",
        talker: { label: "Snap store / actualizaciones", kind: "updates" },
      },
    ],
    programs: [
      {
        process: "systemd-resolve",
        pid: 612,
        dns_server: "1.1.1.1",
        proto: "udp",
        note: "Socket abierto ahora hacia un puerto DNS.",
      },
    ],
  };
}

export function mockListeners(): ListenersReport {
  return {
    collected_at_ms: Date.now(),
    new_count: 1,
    source: "ss -tulpn (simulado)",
    missing: [],
    notes: [],
    alerts: [
      {
        protocol: "tcp",
        local_ip: "192.168.0.24",
        local_port: "8080",
        process: "python3",
        pid: 4444,
        reach: "lan_address",
        reach_label: "en una IP de esta PC (LAN)",
        key: "tcp|192.168.0.24|8080|python3",
        is_new: true,
      },
    ],
    rows: [
      {
        protocol: "tcp",
        local_ip: "0.0.0.0",
        local_port: "22",
        process: "sshd",
        pid: 1010,
        reach: "network_all",
        reach_label: "alcanzable desde la red (0.0.0.0 / ::)",
        key: "tcp|0.0.0.0|22|sshd",
        is_new: false,
      },
      {
        protocol: "tcp",
        local_ip: "127.0.0.1",
        local_port: "631",
        process: "cupsd",
        pid: 777,
        reach: "local_only",
        reach_label: "solo local (127.0.0.1 / ::1)",
        key: "tcp|127.0.0.1|631|cupsd",
        is_new: false,
      },
      {
        protocol: "tcp",
        local_ip: "192.168.0.24",
        local_port: "8080",
        process: "python3",
        pid: 4444,
        reach: "lan_address",
        reach_label: "en una IP de esta PC (LAN)",
        key: "tcp|192.168.0.24|8080|python3",
        is_new: true,
      },
    ],
  };
}

export function mockGeo(ip: string): GeoInfo {
  if (ip === "1.1.1.1" || ip.startsWith("1.1.1")) {
    return {
      ip,
      country: "Australia",
      country_code: "AU",
      isp: "Cloudflare",
      org: "Cloudflare, Inc.",
      asn: "AS13335",
      as_name: "CLOUDFLARENET",
      source: "rdap.org",
      source_label:
        "consulta externa HTTPS a rdap.org: se envía solo esta IP (quién anunció el bloque / país del registro). Sin API key, cacheada. No se envía tu nombre ni IPs de la LAN.",
    };
  }
  return {
    ip,
    country: "United States",
    country_code: "US",
    isp: "Google LLC",
    org: "Google Public DNS",
    asn: "AS15169",
    as_name: "GOOGLE",
    source: "rdap.org",
    source_label:
      "consulta externa HTTPS a rdap.org: se envía solo esta IP (quién anunció el bloque / país del registro). Sin API key, cacheada. No se envía tu nombre ni IPs de la LAN.",
  };
}

export function mockTraceEvents(destination: string): TraceEvent[] {
  return [
    {
      session_id: "mock",
      kind: "start",
      hop: null,
      message: `tracepath -n -- ${destination}`,
      tool: "tracepath",
      privilege: null,
    },
    {
      session_id: "mock",
      kind: "hop",
      hop: {
        hop: 1,
        address: "192.168.0.1",
        hostname: null,
        rtt_ms: 1.2,
        lost: false,
        kind: "home_router",
      },
      message: null,
      tool: "tracepath",
      privilege: null,
    },
    {
      session_id: "mock",
      kind: "hop",
      hop: {
        hop: 2,
        address: "10.0.0.1",
        hostname: null,
        rtt_ms: 8.1,
        lost: false,
        kind: "private",
      },
      message: null,
      tool: "tracepath",
      privilege: null,
    },
    {
      session_id: "mock",
      kind: "hop",
      hop: {
        hop: 3,
        address: "181.15.1.1",
        hostname: null,
        rtt_ms: 12.4,
        lost: false,
        kind: "isp_start",
      },
      message: null,
      tool: "tracepath",
      privilege: null,
    },
    {
      session_id: "mock",
      kind: "hop",
      hop: {
        hop: 4,
        address: null,
        hostname: null,
        rtt_ms: null,
        lost: true,
        kind: "lost",
      },
      message: null,
      tool: "tracepath",
      privilege: null,
    },
    {
      session_id: "mock",
      kind: "hop",
      hop: {
        hop: 5,
        address: destination.trim() || "8.8.8.8",
        hostname: null,
        rtt_ms: 18.3,
        lost: false,
        kind: "destination",
      },
      message: null,
      tool: "tracepath",
      privilege: null,
    },
    {
      session_id: "mock",
      kind: "done",
      hop: null,
      message: "Listo con tracepath.",
      tool: "tracepath",
      privilege: null,
    },
  ];
}
