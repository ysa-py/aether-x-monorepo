"use client";

import { clsx } from "clsx";
import { motion } from "framer-motion";
import { Activity, Ban, WifiOff, Zap } from "lucide-react";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { useI18n } from "@/lib/i18n";

/** The canonical fallback cascade the supervisor FSM learns/refines. */
const CASCADE = [
  "reality-vision",
  "hysteria2",
  "tuic-v5",
  "shadowtls-v3",
  "amneziawg",
] as const;

type Attack = "rst" | "drop" | "tls";

interface SimStep {
  protocol: string;
  outcome: "blocked" | "pass";
}

/**
 * Deterministic client-side simulator: applying an attack advances the FSM
 * through the cascade until a protocol "survives". Mirrors the behavior of
 * core-supervisor's policy.rs FallbackEngine for demonstration.
 */
function simulate(attack: Attack): SimStep[] {
  const steps: SimStep[] = [];
  for (let i = 0; i < CASCADE.length; i++) {
    const proto = CASCADE[i]!;
    // Each attack type fails the first N protocols deterministically.
    const failsUpTo = attack === "tls" ? 2 : attack === "rst" ? 1 : 3;
    const blocked = i < failsUpTo;
    steps.push({ protocol: proto, outcome: blocked ? "blocked" : "pass" });
    if (!blocked) break;
  }
  return steps;
}

export function DpiSimulatorWidget() {
  const { t } = useI18n();
  const [steps, setSteps] = useState<SimStep[]>([]);

  const run = (attack: Attack) => setSteps(simulate(attack));

  return (
    <Card title={t.dpi.title} icon={<Activity size={16} />}>
      <div className="grid grid-cols-3 gap-2">
        <SimButton icon={<Zap size={14} />} label={t.dpi.injectRst} onClick={() => run("rst")} tone="amber" />
        <SimButton icon={<WifiOff size={14} />} label={t.dpi.dropPackets} onClick={() => run("drop")} tone="crimson" />
        <SimButton icon={<Ban size={14} />} label={t.dpi.blockTls} onClick={() => run("tls")} tone="crimson" />
      </div>

      <div className="space-y-1.5">
        {steps.length === 0 && (
          <p className="text-xs text-noc-muted">{t.dpi.cleared}</p>
        )}
        {steps.map((s, i) => (
          <motion.div
            key={`${s.protocol}-${i}`}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.08 }}
            className="flex items-center justify-between rounded-md border border-noc-edge/40 bg-noc-bg/40 px-2 py-1"
          >
            <span className="font-mono text-xs text-noc-fg">{s.protocol}</span>
            <span
              className={clsx(
                "text-[10px] font-semibold uppercase",
                s.outcome === "blocked" ? "text-accent-crimson" : "text-accent-emerald",
              )}
            >
              {s.outcome}
            </span>
          </motion.div>
        ))}
      </div>
    </Card>
  );
}

function SimButton({
  icon,
  label,
  onClick,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
  tone: "amber" | "crimson";
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "flex flex-col items-center gap-1 rounded-lg border px-2 py-2 text-[10px] font-medium",
        tone === "amber"
          ? "border-accent-amber/40 text-accent-amber hover:bg-accent-amber/10"
          : "border-accent-crimson/40 text-accent-crimson hover:bg-accent-crimson/10",
      )}
    >
      {icon}
      {label}
    </button>
  );
}
