"use client";

import { clsx } from "clsx";
import { useConnectionState } from "@/hooks/useQueries";
import { useI18n } from "@/lib/i18n";

/** Tri-state connection pill driven by the live cores query. */
export function ConnectionIndicator() {
  const state = useConnectionState();
  const { t } = useI18n();

  const color =
    state === "connected"
      ? "bg-accent-emerald/20 text-accent-emerald"
      : state === "reconnecting"
        ? "bg-accent-amber/20 text-accent-amber"
        : "bg-accent-crimson/20 text-accent-crimson";

  const label = t.status[state];

  return (
    <span
      className={clsx(
        "inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium",
        color,
      )}
      role="status"
      aria-live="polite"
    >
      <span
        className={clsx(
          "h-2 w-2 rounded-full",
          state === "connected"
            ? "bg-accent-emerald animate-pulse-soft"
            : state === "reconnecting"
              ? "bg-accent-amber"
              : "bg-accent-crimson",
        )}
      />
      {label}
    </span>
  );
}
