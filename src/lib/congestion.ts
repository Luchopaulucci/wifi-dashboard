import type { Band, ChannelBar, NearbyNetwork } from "./types";

export function overlaps24(center: number, other: number): boolean {
  return Math.abs(center - other) < 5;
}

export function congestionBars(nearby: NearbyNetwork[]): ChannelBar[] {
  const bars: ChannelBar[] = [];
  for (let channel = 1; channel <= 13; channel += 1) {
    let count = 0;
    let overlap = 0;
    let strongest: number | null = null;
    for (const n of nearby) {
      if (n.band !== "ghz24" || n.channel == null) continue;
      if (n.channel === channel) {
        count += 1;
        strongest = Math.max(strongest ?? 0, n.signal_pct ?? 0);
      } else if (overlaps24(channel, n.channel)) {
        overlap += 1;
      }
    }
    if (count > 0 || overlap > 0) {
      bars.push({
        channel,
        band: "ghz24",
        count,
        overlap,
        strongest_pct: strongest,
      });
    }
  }
  for (const band of ["ghz5", "ghz6"] as Band[]) {
    const channels = [
      ...new Set(
        nearby.filter((n) => n.band === band && n.channel != null).map((n) => n.channel as number),
      ),
    ].sort((a, b) => a - b);
    for (const channel of channels) {
      const nets = nearby.filter((n) => n.band === band && n.channel === channel);
      bars.push({
        channel,
        band,
        count: nets.length,
        overlap: 0,
        strongest_pct: nets.reduce<number | null>((acc, n) => {
          if (n.signal_pct == null) return acc;
          return Math.max(acc ?? 0, n.signal_pct);
        }, null),
      });
    }
  }
  return bars;
}
