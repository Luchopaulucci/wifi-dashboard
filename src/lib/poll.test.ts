import { renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useSafePoll } from "./poll";

describe("useSafePoll", () => {
  afterEach(() => {
    vi.useRealTimers();
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "visible",
    });
  });

  it("no superpone un tick si el anterior sigue en curso", async () => {
    vi.useFakeTimers();
    let resolveFirst: (() => void) | undefined;
    const tick = vi.fn().mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          if (!resolveFirst) {
            resolveFirst = resolve;
            return;
          }
          resolve();
        }),
    );
    renderHook(() => useSafePoll(tick, 100, true));
    expect(tick).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(250);
    expect(tick).toHaveBeenCalledTimes(1);
    resolveFirst?.();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(100);
    expect(tick).toHaveBeenCalledTimes(2);
  });

  it("omite el intervalo si la pestaña no está visible", async () => {
    vi.useFakeTimers();
    const tick = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    renderHook(() => useSafePoll(tick, 100, true));
    expect(tick).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(300);
    expect(tick).not.toHaveBeenCalled();
  });
});
