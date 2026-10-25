import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { mockSnapshot } from "./lib/mock";

const snapshot = vi.hoisted(() => vi.fn());

vi.mock("./lib/client", () => ({
  getClient: async () => ({
    snapshot,
    rescan: async () => mockSnapshot(),
    sweepLan: async () => mockSnapshot(),
  }),
}));

describe("App snapshot poll", () => {
  beforeEach(() => {
    snapshot.mockReset();
    snapshot.mockResolvedValue(mockSnapshot());
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("carga el WiFi en vivo", async () => {
    render(<App />);
    expect(await screen.findByText("Fibertel-5G")).toBeInTheDocument();
    expect(snapshot).toHaveBeenCalled();
  });
});
