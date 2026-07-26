"use client";

import { clsx } from "clsx";
import { Route, Search } from "lucide-react";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { useRoute } from "@/hooks/useQueries";
import { useI18n } from "@/lib/i18n";
import type { RouteActionLabel } from "@/types/api";

function actionColor(action: RouteActionLabel | undefined): string {
  switch (action) {
    case "DIRECT":
      return "text-accent-emerald";
    case "PROXY":
      return "text-accent-cyan";
    case "BLOCK":
      return "text-accent-crimson";
    default:
      return "text-noc-muted";
  }
}

const VALIDATORS = ["Data Plane", "gRPC", "MCP", "REST"] as const;

export function RouteQueryWidget() {
  const { t } = useI18n();
  const [dest, setDest] = useState("");
  const route = useRoute(dest);

  return (
    <Card title={t.routing.title} icon={<Route size={16} />}>
      <div className="flex gap-2">
        <input
          value={dest}
          onChange={(e) => setDest(e.target.value)}
          placeholder={t.routing.domainPlaceholder}
          className="min-w-0 flex-1 rounded-md border border-noc-edge/60 bg-noc-bg/50 px-2 py-1.5 font-mono text-xs text-noc-fg outline-none focus:border-accent-cyan/70"
          aria-label={t.routing.domainPlaceholder}
        />
        <button
          className="inline-flex items-center gap-1 rounded-md bg-accent-cyan/15 px-3 py-1.5 text-xs text-accent-cyan hover:bg-accent-cyan/25"
          aria-label={t.routing.query}
        >
          <Search size={12} />
        </button>
      </div>

      <div className="flex items-center justify-between rounded-lg border border-noc-edge/40 bg-noc-bg/30 px-3 py-2">
        <span className="text-xs text-noc-muted">{t.routing.decision}</span>
        <span className={clsx("font-mono text-lg font-bold", actionColor(route.data?.action))}>
          {route.data?.action ?? (dest.trim() ? "…" : "—")}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-1.5 text-[10px] text-noc-muted">
        <span>{t.routing.validatedBy}:</span>
        {VALIDATORS.map((v) => (
          <span key={v} className="rounded-full bg-noc-edge/40 px-2 py-0.5">
            {v}
          </span>
        ))}
      </div>
    </Card>
  );
}
