import { describe, expect, it } from "vitest";
import { applyTraceEvent, beginRouteSession, emptyRouteTraceState } from "./route-trace";
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
});
