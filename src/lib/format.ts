import type { Band } from "./types";

export function bandLabel(band: Band | null | undefined): string {
  switch (band) {
    case "ghz24":
      return "2.4 GHz";
    case "ghz5":
      return "5 GHz";
    case "ghz6":
      return "6 GHz";
    default:
      return "—";
  }
}

export function formatMbps(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  if (value >= 100) return `${value.toFixed(0)} Mbps`;
  return `${value.toFixed(1)} Mbps`;
}

export function formatDbm(value: number | null | undefined): string {
  if (value == null) return "—";
  return `${value} dBm`;
}

export function formatPct(value: number | null | undefined, digits = 0): string {
  if (value == null || Number.isNaN(value)) return "—";
  return `${value.toFixed(digits)} %`;
}

export function formatMs(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  return `${value.toFixed(value >= 20 ? 0 : 1)} ms`;
}

export function hiddenSsid(ssid: string): string {
  return ssid.trim() === "" ? "(oculta)" : ssid;
}

export function signalTone(pct: number | null | undefined): string {
  if (pct == null) return "text-slate-400";
  if (pct >= 70) return "text-teal-300";
  if (pct >= 40) return "text-amber-300";
  return "text-rose-300";
}

export function relativeAgo(fromMs: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - fromMs) / 1000));
  if (sec < 5) return "ahora";
  if (sec < 60) return `hace ${sec} s`;
  const min = Math.round(sec / 60);
  return `hace ${min} min`;
}
