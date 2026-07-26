"use client";

import { useEffect, useRef, useState } from "react";

/** One live telemetry sample broadcast from the SSE hub. */
export interface TelemetryPulse {
  node_id: string;
  protocol: string;
  isp: string;
  kind: string;
  latency_ms: number;
  packet_loss: boolean;
  rst: boolean;
  ts: string;
}

export type StreamState = "connecting" | "open" | "reconnecting" | "closed";

interface UseTelemetryStreamResult {
  pulse: TelemetryPulse | null;
  state: StreamState;
}

/**
 * Subscribes to the Go control-plane SSE stream at `url` (GET
 * /v1/telemetry/stream) with automatic exponential-backoff reconnection.
 * Returns the latest pulse + connection state for UI indicators.
 */
export function useTelemetryStream(url: string): UseTelemetryStreamResult {
  const [pulse, setPulse] = useState<TelemetryPulse | null>(null);
  const [state, setState] = useState<StreamState>("connecting");

  // Keep the latest URL in a ref so the effect only binds once.
  const urlRef = useRef(url);
  urlRef.current = url;

  useEffect(() => {
    let es: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;
    let stopped = false;

    const connect = () => {
      setState((prev) => (prev === "open" ? "connecting" : prev));
      es = new EventSource(urlRef.current);

      es.addEventListener("open", () => {
        attempt = 0;
        setState("open");
      });

      es.onmessage = (ev: MessageEvent<string>) => {
        try {
          const parsed = JSON.parse(ev.data) as TelemetryPulse;
          setPulse(parsed);
        } catch {
          // ignore malformed payloads
        }
      };

      es.onerror = () => {
        es?.close();
        es = null;
        if (stopped) return;
        setState("reconnecting");
        // Exponential backoff capped at 15s.
        attempt += 1;
        const delay = Math.min(1000 * 2 ** attempt, 15000);
        reconnectTimer = setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      stopped = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      es?.close();
      setState("closed");
    };
  }, []);

  return { pulse, state };
}
