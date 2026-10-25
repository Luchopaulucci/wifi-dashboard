import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GeoOptIn } from "./GeoOptIn";

describe("GeoOptIn", () => {
  it("explica qué se envía y arranca apagado", () => {
    const calls: boolean[] = [];
    render(<GeoOptIn enabled={false} onChange={(v) => calls.push(v)} />);
    const box = screen.getByTestId("geo-opt-in");
    expect(box).toHaveTextContent("apagadas por defecto");
    expect(box).toHaveTextContent("rdap.org");
    expect(box).toHaveTextContent("solo esa IP pública");
    const input = box.querySelector("input") as HTMLInputElement;
    expect(input.checked).toBe(false);
    fireEvent.click(input);
    expect(calls).toEqual([true]);
  });
});
