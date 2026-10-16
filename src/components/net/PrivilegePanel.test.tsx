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
          commands: ['sudo setcap cap_net_admin+ep "$(command -v nft)"', "sudo nft list ruleset"],
          polkit_note: "No hace falta abrir Señal con sudo.",
        }}
      />,
    );
    const panel = screen.getByTestId("privilege-panel");
    expect(panel).toHaveTextContent("CAP_NET_ADMIN");
    expect(panel).toHaveTextContent("sudo setcap cap_net_admin+ep");
    expect(panel).toHaveTextContent("no corre como root");
  });
});
