"use client";

import { clsx } from "clsx";
import { useMutation } from "@tanstack/react-query";
import { Layers, RefreshCw } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { useCores } from "@/hooks/useQueries";
import { switchCore } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { CoreInstance, CoreStatus } from "@/types/api";

function statusColor(status: CoreStatus): string {
  switch (status) {
    case "CORE_STATUS_RUNNING":
      return "text-accent-emerald";
    case "CORE_STATUS_DEGRADED":
    case "CORE_STATUS_DRAINING":
      return "text-accent-amber";
    case "CORE_STATUS_FAILED":
    case "CORE_STATUS_STOPPED":
      return "text-accent-crimson";
    default:
      return "text-noc-muted";
  }
}

const FALLBACK_PROTOCOLS = ["hysteria2", "tuic-v5", "shadowtls-v3"] as const;

export function CoreManagerWidget() {
  const { data: cores, isLoading } = useCores();
  const { t } = useI18n();

  const swap = useMutation({
    mutationFn: (input: { instance: string; protocol: string }) =>
      switchCore(input.instance, input.protocol),
  });

  return (
    <Card title={t.cores.title} icon={<Layers size={16} />}>
      {isLoading && <p className="text-xs text-noc-muted">…</p>}
      {!isLoading && (cores?.length ?? 0) === 0 && (
        <p className="text-xs text-noc-muted">{t.cores.empty}</p>
      )}
      <ul className="space-y-2">
        {cores?.map((c: CoreInstance) => (
          <li
            key={c.instance_id}
            className="flex items-center justify-between rounded-lg border border-noc-edge/50 bg-noc-bg/40 px-3 py-2"
          >
            <div className="min-w-0">
              <p className="truncate font-mono text-sm text-noc-fg">{c.instance_id}</p>
              <p className="truncate text-xs text-noc-muted">
                {t.cores.protocol}: <span className="text-noc-fg">{c.protocol_id}</span>
                {" · "}
                {t.cores.restarts}: <span className="text-noc-fg">{c.restart_count}</span>
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className={clsx("font-mono text-xs", statusColor(c.status))}>
                {c.status.replace("CORE_STATUS_", "")}
              </span>
              <button
                data-testid="hot-swap"
                onClick={() =>
                  swap.mutate({
                    instance: c.instance_id,
                    protocol: FALLBACK_PROTOCOLS[0]!,
                  })
                }
                disabled={swap.isPending}
                className="inline-flex items-center gap-1 rounded-md bg-accent-cyan/15 px-2 py-1 text-xs text-accent-cyan hover:bg-accent-cyan/25 disabled:opacity-50"
              >
                <RefreshCw size={12} className={swap.isPending ? "animate-spin" : ""} />
                {t.cores.hotSwap}
              </button>
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}
