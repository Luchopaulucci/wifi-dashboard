import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PrivilegePanel } from "./PrivilegePanel";

describe("PrivilegePanel", () => {
  it("explica por qué y el comando exacto", () => {
    render(
      <PrivilegePanel
        hint={{
          binary: "nft",
          capability: "CAP_NET_ADMIN",
          why: "Leer nft list ruleset habla con nf_tables vía netlink.",
          commands: ["sudo nft list ruleset"],
          polkit_note: "No hace falta abrir Señal con sudo.",
        }}
      />,
    );
    const panel = screen.getByTestId("privilege-panel");
    expect(panel).toHaveTextContent("CAP_NET_ADMIN");
    expect(panel).toHaveTextContent("sudo nft list ruleset");
    expect(panel).not.toHaveTextContent("setcap");
    expect(panel).toHaveTextContent("no corre como root");
  });
});
