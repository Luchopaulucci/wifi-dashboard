import { useCallback, useState } from "react";
import { getClient } from "./client";
import type { PrivilegedAction, PrivilegedReport } from "./types";

export function useElevate<T>(kind: PrivilegedReport["kind"], apply: (data: T) => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const elevate = useCallback(
    async (action: PrivilegedAction) => {
      setBusy(true);
      setError(null);
      try {
        const client = await getClient();
        const report = await client.runPrivileged(action);
        if (report.kind !== kind) {
          setError("La acción no corresponde a esta pestaña.");
          return;
        }
        apply(report.data as T);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
    },
    [apply, kind],
  );

  return { elevate, busy, error };
}
