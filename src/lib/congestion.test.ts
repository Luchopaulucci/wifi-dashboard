import { describe, expect, it } from "vitest";
import { congestionBars, overlaps24 } from "./congestion";
import type { NearbyNetwork } from "./types";

function net(channel: number, band: NearbyNetwork["band"], pct: number): NearbyNetwork {
  return {
    in_use: false,
    ssid: `n${channel}`,
    bssid: `aa:bb:cc:dd:ee:${channel.toString(16).padStart(2, "0")}`,
    channel,
    frequency_mhz: null,
    band,
    signal_dbm: null,
    signal_pct: pct,
    security: "WPA2",
    rate: null,
  };
}

describe("congestion", () => {
  it("calcula solape de 2.4 GHz", () => {
    expect(overlaps24(1, 5)).toBe(true);
    expect(overlaps24(1, 6)).toBe(false);
  });

  it("arma barras con overlap", () => {
    const bars = congestionBars([
      net(1, "ghz24", 80),
      net(5, "ghz24", 40),
      net(36, "ghz5", 70),
    ]);
    const ch1 = bars.find((b) => b.channel === 1 && b.band === "ghz24");
    expect(ch1?.count).toBe(1);
    expect(ch1?.overlap).toBeGreaterThanOrEqual(1);
    expect(bars.find((b) => b.channel === 36)?.overlap).toBe(0);
  });
});
