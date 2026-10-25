import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PrivilegePanel } from "./PrivilegePanel";

const nftHint = {
  binary: "nft",
  capability: "CAP_NET_ADMIN",
  why: "Leer nft list ruleset habla con nf_tables vía netlink.",
  action: "nft_list" as const,
  polkit_note: "Un clic abre el diálogo de contraseña del sistema (pkexec).",
};

describe("PrivilegePanel", () => {
  it("explica por qué y no pide copiar sudo/setcap", () => {
    render(<PrivilegePanel hint={nftHint} onElevate={() => undefined} />);
    const panel = screen.getByTestId("privilege-panel");
    expect(panel).toHaveTextContent("CAP_NET_ADMIN");
    expect(panel).toHaveTextContent("no corre como root");
    expect(panel).toHaveTextContent("Ver con permisos de administrador");
    expect(panel).not.toHaveTextContent("sudo setcap");
    expect(panel).not.toHaveTextContent("sudo nft");
  });

  it("dispara la elevación al hacer clic", () => {
    const onElevate = vi.fn();
    render(<PrivilegePanel hint={nftHint} onElevate={onElevate} />);
    fireEvent.click(screen.getByTestId("privilege-elevate"));
    expect(onElevate).toHaveBeenCalledTimes(1);
  });

  it("muestra cancelación de pkexec sin romper el panel", () => {
    render(
      <PrivilegePanel
        hint={nftHint}
        onElevate={() => undefined}
        error="Cancelaste el diálogo de contraseña. No se ejecutó nada."
      />,
    );
    expect(screen.getByTestId("privilege-error")).toHaveTextContent(
      "Cancelaste el diálogo de contraseña",
    );
    expect(screen.getByTestId("privilege-elevate")).toBeEnabled();
  });

  it("deshabilita el botón mientras espera la contraseña", () => {
    render(<PrivilegePanel hint={nftHint} onElevate={() => undefined} busy />);
    expect(screen.getByTestId("privilege-elevate")).toBeDisabled();
    expect(screen.getByTestId("privilege-panel")).toHaveTextContent("Esperando contraseña");
  });

  it("muestra aviso si pkexec falla con un código que no es 0/126/127", () => {
    render(
      <PrivilegePanel
        hint={nftHint}
        onElevate={() => undefined}
        error="El comando elevado falló (código 1). No se cambió nada en el sistema. syntax error"
      />,
    );
    expect(screen.getByTestId("privilege-error")).toHaveTextContent("El comando elevado falló");
    expect(screen.getByTestId("privilege-error")).toHaveTextContent("código 1");
    expect(screen.getByTestId("privilege-elevate")).toBeEnabled();
  });
});
