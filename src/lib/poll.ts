import { useEffect, useRef } from "react";

export const CONNECTIONS_POLL_MS = 8_000;
export const PORTS_POLL_MS = 8_000;
export const SNAPSHOT_POLL_MS = 4_000;
export const TABLE_PAGE_SIZE = 40;

/** Un tick a la vez: si el anterior sigue, se salta. Pausa con la pestaña oculta. */
export function useSafePoll(
  tick: () => Promise<void>,
  intervalMs: number,
  enabled = true,
): void {
  const inflight = useRef(false);
  const tickRef = useRef(tick);
  tickRef.current = tick;

  useEffect(() => {
    const run = () => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") {
        return;
      }
      if (inflight.current) {
        return;
      }
      inflight.current = true;
      void tickRef.current().finally(() => {
        inflight.current = false;
      });
    };

    run();
    if (!enabled) {
      return;
    }
    const id = window.setInterval(run, intervalMs);
    const onVis = () => {
      if (document.visibilityState === "visible") {
        run();
      }
    };
    document.addEventListener("visibilitychange", onVis);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [enabled, intervalMs]);
}
