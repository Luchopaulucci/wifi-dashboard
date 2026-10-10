import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MockBanner } from "./MockBanner";

describe("MockBanner", () => {
  it("deja claro que es modo simulado", () => {
    render(<MockBanner reason="No hay interfaz WiFi. Mostramos datos de ejemplo." />);
    expect(screen.getByTestId("mock-banner")).toHaveTextContent("Modo simulado");
    expect(screen.getByTestId("mock-banner")).toHaveTextContent("No hay interfaz WiFi");
  });
});
