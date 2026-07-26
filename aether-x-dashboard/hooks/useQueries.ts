"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import {
  getAuditRoot,
  getCores,
  getRoute,
  issueToken,
  verifyToken,
} from "@/lib/api";
import type { ConnectionState } from "@/types/api";

/** Poll cores every 2s (live NOC). */
export function useCores() {
  return useQuery({
    queryKey: ["cores"],
    queryFn: getCores,
    refetchInterval: 2000,
    select: (data) => data.instances,
  });
}

/** Derive a connection state from the cores query. */
export function useConnectionState(): ConnectionState {
  const q = useCores();
  if (q.status === "success") return "connected";
  if (q.isFetching) return "reconnecting";
  return "offline";
}

/** Audit-log commitments, polled. */
export function useAuditRoot() {
  return useQuery({
    queryKey: ["audit-root"],
    queryFn: getAuditRoot,
    refetchInterval: 4000,
  });
}

/** Route decision (only fetched when a destination is provided). */
export function useRoute(destination: string) {
  const trimmed = destination.trim();
  return useQuery({
    queryKey: ["route", trimmed],
    queryFn: () => getRoute(trimmed),
    enabled: trimmed.length > 0,
    staleTime: 5000,
  });
}

export function useVerifyToken() {
  return useMutation({
    mutationFn: (token: string) => verifyToken(token),
  });
}

export function useIssueToken() {
  return useMutation({
    mutationFn: issueToken,
  });
}
