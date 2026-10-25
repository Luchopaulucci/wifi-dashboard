import type { PrivilegeHint, TraceEvent, TraceHop } from "./types";

export interface RouteTraceState {
  sessionId: string | null;
  hops: TraceHop[];
  status: string;
  tool: string | null;
  privilege: PrivilegeHint | null;
  busy: boolean;
  elevateError: string | null;
}

export function emptyRouteTraceState(status = "Escribí un destino y dale a Trazar."): RouteTraceState {
  return {
    sessionId: null,
    hops: [],
    status,
    tool: null,
    privilege: null,
    busy: false,
    elevateError: null,
  };
}

/** Invalida la sesión previa: un `cancelled` viejo no apaga el busy nuevo. */
export function beginRouteSession(state: RouteTraceState, status: string): RouteTraceState {
  return {
    ...state,
    sessionId: null,
    hops: [],
    status,
    busy: true,
    elevateError: null,
  };
}

/** Fija el session_id que devolvió `start_trace_route` antes de aplicar eventos. */
export function bindRouteSession(state: RouteTraceState, sessionId: string): RouteTraceState {
  return { ...state, sessionId };
}

export function applyTraceEvent(state: RouteTraceState, ev: TraceEvent): RouteTraceState {
  if (state.sessionId != null && ev.session_id !== state.sessionId) {
    return state;
  }
  if (ev.kind === "start") {
    return {
      ...state,
      sessionId: state.sessionId ?? ev.session_id,
      hops: [],
      status: ev.message ?? "Trazando…",
      tool: ev.tool ?? state.tool,
      privilege: ev.privilege ?? null,
      busy: true,
    };
  }
  if (state.sessionId == null) {
    return state;
  }
  if (ev.kind === "hop" && ev.hop) {
    const next = state.hops.filter((h) => h.hop !== ev.hop!.hop);
    next.push(ev.hop);
    next.sort((a, b) => a.hop - b.hop);
    return { ...state, hops: next, tool: ev.tool ?? state.tool };
  }
  if (ev.kind === "done") {
    return { ...state, busy: false, status: ev.message ?? "Listo.", tool: ev.tool ?? state.tool };
  }
  if (ev.kind === "cancelled") {
    return { ...state, busy: false, status: ev.message ?? "Cancelado.", tool: ev.tool ?? state.tool };
  }
  if (ev.kind === "error") {
    const elevateError =
      ev.privilege && ev.message ? ev.message : state.elevateError;
    return {
      ...state,
      busy: false,
      status: ev.message ?? "No se pudo trazar.",
      tool: ev.tool ?? state.tool,
      privilege: ev.privilege ?? state.privilege,
      elevateError,
    };
  }
  return state;
}
