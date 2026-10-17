import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PortsView } from "./PortsView";

describe("PortsView", () => {
  it("muestra la alerta de listener nuevo y permite descartarla", async () => {
    render(<PortsView />);
    const alert = await screen.findByTestId("new-listener-alert");
    expect(alert).toHaveTextContent("python3");
    expect(alert).toHaveTextContent("Descartar");
    fireEvent.click(screen.getByRole("button", { name: "Descartar" }));
    expect(screen.queryByTestId("new-listener-alert")).toBeNull();
  });
});
