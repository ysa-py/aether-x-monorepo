"use client";

import { CoreManagerWidget } from "@/components/widgets/CoreManagerWidget";
import { DpiSimulatorWidget } from "@/components/widgets/DpiSimulatorWidget";
import { RouteQueryWidget } from "@/components/widgets/RouteQueryWidget";
import { TokenInspectorWidget } from "@/components/widgets/TokenInspectorWidget";
import { TopologyVisualizer } from "@/components/widgets/TopologyVisualizer";
import { useTelemetryStream } from "@/hooks/useTelemetryStream";

const STREAM_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "http://localhost:8080";

/**
 * Responsive Bento-grid dashboard. The topology canvas consumes the live SSE
 * telemetry stream so particle speed/count/color reflect real latency + loss.
 */
export function BentoGrid() {
  const { pulse } = useTelemetryStream(`${STREAM_BASE}/v1/telemetry/stream`);

  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
      <div className="md:col-span-2 xl:col-span-2 xl:row-span-2 min-h-[320px]">
        <TopologyVisualizer
          latencyMs={pulse?.latency_ms ?? 120}
          packetLoss={pulse?.packet_loss ?? false}
        />
      </div>
      <CoreManagerWidget />
      <RouteQueryWidget />
      <div className="md:col-span-2 xl:col-span-2">
        <TokenInspectorWidget />
      </div>
      <DpiSimulatorWidget />
    </div>
  );
}
