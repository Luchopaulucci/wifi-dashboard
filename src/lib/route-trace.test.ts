import { describe, expect, it } from "vitest";
import {
  applyTraceEvent,
  beginRouteSession,
  bindRouteSession,
  emptyRouteTraceState,
} from "./route-trace";
import type { TraceEvent, TraceHop } from "./types";

function ev(partial: Partial<TraceEvent> & Pick<TraceEvent, "session_id" | "kind">): TraceEvent {
  return {
    hop: null,
    message: null,
    tool: null,
    privilege: null,
    ...partial,
  };
}

const hop: TraceHop = {
  hop: 1,
  address: "192.168.0.1",
  hostname: null,
  rtt_ms: 1,
  lost: false,
  kind: "home_router",
};

describe("applyTraceEvent", () => {
  it("ignora cancelled de una sesión anterior cuando ya hay una nueva", () => {
    let state = emptyRouteTraceState();
    state = beginRouteSession(state, "Trazando…");
    expect(state.busy).toBe(true);
    expect(state.sessionId).toBeNull();

    state = applyTraceEvent(state, ev({ session_id: "old", kind: "cancelled", message: "viejo" }));
    expect(state.busy).toBe(true);
    expect(state.status).toBe("Trazando…");

    state = applyTraceEvent(
      state,
      ev({ session_id: "new", kind: "start", message: "traceroute -n", tool: "traceroute" }),
    );
    expect(state.sessionId).toBe("new");
    expect(state.busy).toBe(true);

    state = applyTraceEvent(state, ev({ session_id: "old", kind: "cancelled", message: "viejo" }));
    expect(state.busy).toBe(true);
    expect(state.status).toBe("traceroute -n");
    expect(state.sessionId).toBe("new");

    state = applyTraceEvent(state, ev({ session_id: "new", kind: "hop", hop }));
    expect(state.hops).toHaveLength(1);

    state = applyTraceEvent(state, ev({ session_id: "old", kind: "done", message: "Listo viejo" }));
    expect(state.busy).toBe(true);
    expect(state.hops).toHaveLength(1);
  });

  it("un error sin privilegio no llena elevateError", () => {
    let state = applyTraceEvent(
      emptyRouteTraceState(),
      ev({ session_id: "s1", kind: "start", message: "tracepath -n" }),
    );
    state = applyTraceEvent(
      state,
      ev({
        session_id: "s1",
        kind: "error",
        message: "tracepath no dio hops (código 0).",
      }),
    );
    expect(state.busy).toBe(false);
    expect(state.status).toBe("tracepath no dio hops (código 0).");
    expect(state.elevateError).toBeNull();
  });

  it("pkexec_missing sin start no deja busy trabado si el front fija el session_id", () => {
    const pkexecMissing =
      "No está `pkexec`. En Ubuntu: sudo apt install policykit-1. Señal no corre como root.";
    let state = beginRouteSession(emptyRouteTraceState(), "Pidiendo permisos…");
    expect(state.busy).toBe(true);
    expect(state.sessionId).toBeNull();
    expect(state.status).toBe("Pidiendo permisos…");

    const dropped = applyTraceEvent(
      state,
      ev({ session_id: "s-pkexec", kind: "error", message: pkexecMissing }),
    );
    expect(dropped.busy).toBe(true);
    expect(dropped.status).toBe("Pidiendo permisos…");

    state = bindRouteSession(state, "s-pkexec");
    state = applyTraceEvent(
      state,
      ev({ session_id: "s-pkexec", kind: "error", message: pkexecMissing }),
    );
    expect(state.busy).toBe(false);
    expect(state.status).toBe(pkexecMissing);
    expect(state.elevateError).toBeNull();
  });

  it("un start ajeno no pisa el sessionId ya fijado y el done de B apaga busy", () => {
    let state = beginRouteSession(emptyRouteTraceState(), "Trazando…");
    state = bindRouteSession(state, "B");
    expect(state.sessionId).toBe("B");
    expect(state.busy).toBe(true);

    state = applyTraceEvent(
      state,
      ev({ session_id: "A", kind: "start", message: "Pidiendo permisos…", tool: "traceroute" }),
    );
    expect(state.sessionId).toBe("B");
    expect(state.busy).toBe(true);
    expect(state.status).toBe("Trazando…");

    state = applyTraceEvent(state, ev({ session_id: "B", kind: "done", message: "Listo con traceroute." }));
    expect(state.sessionId).toBe("B");
    expect(state.busy).toBe(false);
    expect(state.status).toBe("Listo con traceroute.");
  });

  it("ningún evento cambia sessionId una vez fijado", () => {
    let state = bindRouteSession(beginRouteSession(emptyRouteTraceState(), "Trazando…"), "B");

    state = applyTraceEvent(state, ev({ session_id: "A", kind: "hop", hop }));
    state = applyTraceEvent(state, ev({ session_id: "A", kind: "done", message: "done A" }));
    state = applyTraceEvent(state, ev({ session_id: "A", kind: "cancelled", message: "cancel A" }));
    state = applyTraceEvent(
      state,
      ev({ session_id: "A", kind: "error", message: "error A", privilege: null }),
    );
    expect(state.sessionId).toBe("B");
    expect(state.busy).toBe(true);
    expect(state.hops).toHaveLength(0);

    state = applyTraceEvent(state, ev({ session_id: "B", kind: "hop", hop }));
    expect(state.sessionId).toBe("B");
    expect(state.hops).toHaveLength(1);

    state = applyTraceEvent(
      state,
      ev({ session_id: "B", kind: "start", message: "traceroute -n", tool: "traceroute" }),
    );
    expect(state.sessionId).toBe("B");
    expect(state.busy).toBe(true);
  });

  it("una ruta sin elevar con código distinto de 0 no llena elevateError", () => {
    let state = beginRouteSession(emptyRouteTraceState(), "Trazando…");
    state = bindRouteSession(state, "s-unelev");
    state = applyTraceEvent(
      state,
      ev({ session_id: "s-unelev", kind: "start", message: "Trazando…" }),
    );
    state = applyTraceEvent(
      state,
      ev({
        session_id: "s-unelev",
        kind: "error",
        message: "tracepath no dio hops (código 1). send: network unreachable",
      }),
    );
    expect(state.busy).toBe(false);
    expect(state.status).toBe("tracepath no dio hops (código 1). send: network unreachable");
    expect(state.elevateError).toBeNull();
    expect(state.privilege).toBeNull();
  });
});
