"use client";

import { clsx } from "clsx";
import { motion } from "framer-motion";
import { Cpu, MemoryStick, Plug } from "lucide-react";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Drawer } from "@/components/ui/Drawer";
import { useI18n } from "@/lib/i18n";

type NodeKind = "control" | "supervisor" | "proxy" | "isp";

interface TopoNode {
  id: string;
  label: string;
  kind: NodeKind;
  x: number;
  y: number;
}

const NODES: TopoNode[] = [
  { id: "control", label: "control", kind: "control", x: 44, y: 140 },
  { id: "supervisor", label: "supervisor", kind: "supervisor", x: 150, y: 140 },
  { id: "xray", label: "xray", kind: "proxy", x: 268, y: 70 },
  { id: "singbox", label: "sing-box", kind: "proxy", x: 268, y: 140 },
  { id: "persis", label: "persis-core", kind: "proxy", x: 268, y: 210 },
  { id: "mci", label: "MCI", kind: "isp", x: 360, y: 90 },
  { id: "irancell", label: "Irancell", kind: "isp", x: 360, y: 190 },
];

/** Curved edges (SVG path data) along which particles flow. */
const EDGES: { d: string }[] = [
  { d: "M58 140 C 100 140, 110 140, 136 140" },
  { d: "M164 120 C 210 90, 220 75, 254 70" },
  { d: "M164 140 C 210 140, 220 140, 254 140" },
  { d: "M164 160 C 210 190, 220 205, 254 210" },
  { d: "M286 70 C 320 78, 330 84, 346 90" },
  { d: "M286 200 C 320 195, 330 188, 346 190" },
];

function kindColor(kind: NodeKind): string {
  switch (kind) {
    case "control":
      return "var(--accent-cyan)";
    case "supervisor":
      return "var(--accent-emerald)";
    case "proxy":
      return "var(--accent-amber)";
    case "isp":
      return "var(--accent-crimson)";
  }
}

/**
 * Particle count + duration derived from latency. Higher latency => fewer,
 * slower particles. Under packet loss the stream shifts crimson.
 */
function particleSpec(latencyMs: number, packetLoss: boolean) {
  const count = Math.max(2, Math.round(8 - latencyMs / 60));
  const duration = Math.max(0.8, latencyMs / 350);
  const color = packetLoss ? "var(--accent-crimson)" : "var(--accent-cyan)";
  return { count, duration, color };
}

export function TopologyVisualizer({
  latencyMs = 120,
  packetLoss = false,
}: {
  latencyMs?: number;
  packetLoss?: boolean;
}) {
  const { t } = useI18n();
  const [selected, setSelected] = useState<TopoNode | null>(null);
  const spec = particleSpec(latencyMs, packetLoss);

  return (
    <Card title={t.topology.title} icon={<Cpu size={16} />}>
      <div className="mb-1 flex items-center gap-2 text-[10px] text-noc-muted">
        <span className="font-mono">{latencyMs}ms</span>
        <span>·</span>
        <span className={clsx(packetLoss ? "text-accent-crimson" : "text-accent-emerald")}>
          {packetLoss ? "loss" : "ok"}
        </span>
      </div>

      <svg viewBox="0 0 404 260" className="h-full w-full" role="img" aria-label={t.topology.title}>
        <defs>
          {EDGES.map((e, i) => (
            <path
              key={`edge-${i}`}
              id={`edge-${i}`}
              d={e.d}
              fill="none"
              stroke={packetLoss ? "rgb(var(--accent-crimson) / 0.5)" : "rgb(var(--noc-edge))"}
              strokeWidth={1.5}
            />
          ))}
        </defs>

        {/* Particles flowing along edges — speed/count/color reflect live telemetry. */}
        {EDGES.map((e, i) =>
          Array.from({ length: spec.count }, (_, p) => (
            <circle
              key={`p-${i}-${p}`}
              r={2.4}
              fill={spec.color}
              className="particle"
              style={
                {
                  "--particle-path": `path('${e.d}')`,
                  "--particle-duration": `${spec.duration}s`,
                  "--particle-delay": `${(p / spec.count) * spec.duration}s`,
                } as React.CSSProperties
              }
            />
          )),
        )}

        {/* Nodes. */}
        {NODES.map((n) => (
          <g
            key={n.id}
            transform={`translate(${n.x} ${n.y})`}
            className="cursor-pointer"
            onClick={() => setSelected(n)}
            role="button"
            aria-label={n.label}
          >
            <motion.circle
              r={13}
              fill="rgb(var(--noc-panel))"
              stroke={kindColor(n.kind)}
              strokeWidth={2}
              whileHover={{ scale: 1.15 }}
            />
            <circle r={4} fill={kindColor(n.kind)} />
            <text x={0} y={30} textAnchor="middle" className="fill-noc-muted" style={{ fontSize: 10 }}>
              {n.label}
            </text>
          </g>
        ))}
      </svg>

      <Drawer open={selected !== null} onClose={() => setSelected(null)} title={selected?.label ?? ""}>
        {selected && <NodeMetrics node={selected} />}
      </Drawer>
    </Card>
  );
}

function NodeMetrics({ node }: { node: TopoNode }) {
  // Deterministic pseudo-metrics from the node id (live values would come from
  // the supervisor once per-node telemetry RPCs are wired).
  const seed = [...node.id].reduce((a, c) => a + c.charCodeAt(0), 0);
  const cpu = (seed % 70) + 5;
  const ram = ((seed * 7) % 60) + 10;
  const sockets = (seed * 3) % 500;
  return (
    <div className="space-y-3 text-xs">
      <Metric icon={<Cpu size={14} />} label="CPU" value={`${cpu}%`} pct={cpu} />
      <Metric icon={<MemoryStick size={14} />} label="RAM" value={`${ram}%`} pct={ram} />
      <div className="flex items-center gap-2 text-noc-muted">
        <Plug size={14} />
        <span>active sockets</span>
        <span className="font-mono text-noc-fg">{sockets}</span>
      </div>
      <p className="pt-2 text-noc-muted">
        {clsx(node.kind)} · {node.label}
      </p>
    </div>
  );
}

function Metric({ icon, label, value, pct }: { icon: React.ReactNode; label: string; value: string; pct: number }) {
  return (
    <div>
      <div className="flex items-center justify-between text-noc-muted">
        <span className="flex items-center gap-1">
          {icon}
          {label}
        </span>
        <span className="font-mono text-noc-fg">{value}</span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-noc-edge/50">
        <div className="h-full rounded-full bg-accent-cyan/70" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
