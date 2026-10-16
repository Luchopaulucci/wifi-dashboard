import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ExplainButton } from "./ExplainButton";

describe("ExplainButton", () => {
  it("abre notas de estudio en castellano", () => {
    render(<ExplainButton tab="firewall" />);
    fireEvent.click(screen.getByTestId("explain-button"));
    const dlg = screen.getByTestId("explain-dialog");
    expect(dlg).toHaveTextContent("nftables");
    expect(dlg).toHaveTextContent("SOLO LECTURA");
  });
});
