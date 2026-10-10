import { describe, expect, it } from "vitest";
import { bandLabel, formatMbps, formatMs, hiddenSsid, relativeAgo, signalTone } from "./format";

describe("format", () => {
  it("nombra bandas", () => {
    expect(bandLabel("ghz24")).toBe("2.4 GHz");
    expect(bandLabel("ghz5")).toBe("5 GHz");
    expect(bandLabel("ghz6")).toBe("6 GHz");
    expect(bandLabel(null)).toBe("—");
  });

  it("formatea velocidades y tiempos", () => {
    expect(formatMbps(866.7)).toBe("867 Mbps");
    expect(formatMbps(12.34)).toBe("12.3 Mbps");
    expect(formatMbps(null)).toBe("—");
    expect(formatMs(3.8)).toBe("3.8 ms");
    expect(formatMs(22.2)).toBe("22 ms");
  });

  it("oculta SSID vacío", () => {
    expect(hiddenSsid("")).toBe("(oculta)");
    expect(hiddenSsid("Casa")).toBe("Casa");
  });

  it("colorea la señal", () => {
    expect(signalTone(90)).toContain("teal");
    expect(signalTone(50)).toContain("amber");
    expect(signalTone(10)).toContain("rose");
  });

  it("relativo", () => {
    expect(relativeAgo(1000, 1000)).toBe("ahora");
    expect(relativeAgo(1000, 9000)).toBe("hace 8 s");
  });
});
