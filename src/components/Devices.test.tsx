import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { mockSnapshot } from "../lib/mock";
import { DevicesView } from "./Devices";

describe("DevicesView", () => {
  it("muestra Buscando y el error del barrido", () => {
    render(
      <DevicesView
        snapshot={mockSnapshot()}
        onSweep={vi.fn()}
        busy
        error="No se pudo buscar equipos: tiempo de espera agotado"
      />,
    );
    expect(screen.getByRole("button")).toHaveTextContent("Buscando…");
    expect(screen.getByRole("button")).toBeDisabled();
    expect(screen.getByTestId("devices-error")).toHaveTextContent(
      "No se pudo buscar equipos: tiempo de espera agotado",
    );
  });
});
