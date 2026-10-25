import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConnectionsView } from "./ConnectionsView";
import type { ConnectionRow } from "../../lib/types";

const rows: ConnectionRow[] = Array.from({ length: 80 }, (_, i) => ({
  protocol: "tcp",
  local_ip: "127.0.0.1",
  local_port: String(10000 + i),
  remote_ip: "1.1.1.1",
  remote_port: "443",
  state: "ESTABLISHED",
  process: i < 3 ? "firefox" : `proc${i}`,
  pid: i,
  domain: null,
  domain_source: null,
}));

vi.mock("../../lib/client", () => ({
  getClient: async () => ({
    connections: async () => ({
      collected_at_ms: 1,
      sources: ["ss"],
      missing: [],
      privilege: null,
      notes: [],
      rows,
    }),
    lookupIp: async () => {
      throw new Error("no");
    },
  }),
}));

describe("ConnectionsView", () => {
  it("pagina las filas y el filtro sigue andando", async () => {
    render(<ConnectionsView pageSize={2} />);
    expect(await screen.findByText("pid 0")).toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(3); // header + 2
    fireEvent.click(screen.getByTestId("show-more-connections"));
    expect(screen.getAllByRole("row")).toHaveLength(5);
    fireEvent.change(screen.getByPlaceholderText("Filtrar por programa…"), {
      target: { value: "firefox" },
    });
    expect(screen.getAllByRole("row")).toHaveLength(3);
    expect(screen.getByTestId("show-more-connections")).toHaveTextContent("1 restantes");
  });

  it("con el tamaño por defecto no monta las 80 filas de una", async () => {
    const start = performance.now();
    render(<ConnectionsView />);
    await screen.findByText("proc3");
    const ms = performance.now() - start;
    expect(screen.getAllByRole("row")).toHaveLength(41);
    expect(screen.getByTestId("show-more-connections")).toHaveTextContent("40 restantes");
    // eslint-disable-next-line no-console
    console.log(`MEASURE connections first paint (80 rows, page 40): ${ms.toFixed(1)}ms`);
  });
});
