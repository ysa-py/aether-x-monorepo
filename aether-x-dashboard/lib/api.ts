import type {
  AuditRootResponse,
  IssueTokenResponse,
  ListCoresResponse,
  RouteResponse,
  VerifyTokenResponse,
} from "@/types/api";

/**
 * Type-safe REST client for the Aether-X Go control plane. The base URL is
 * configurable via NEXT_PUBLIC_API_BASE (defaults to the local dev server).
 * Every method throws on non-2xx so TanStack Query can surface errors + drive
 * the connection-state indicator.
 */
const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "http://localhost:8080";

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
      // Never cache live NOC data.
      cache: "no-store",
    });
  } catch (err) {
    // Network failure (backend offline) -> normalized error.
    throw new ApiError(
      err instanceof Error ? err.message : "network error",
      0,
    );
  }
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = body.error;
    } catch {
      // ignore non-JSON error bodies
    }
    throw new ApiError(message, res.status);
  }
  return (await res.json()) as T;
}

/** GET /v1/cores */
export function getCores(): Promise<ListCoresResponse> {
  return request<ListCoresResponse>("/v1/cores");
}

/** POST /v1/cores/switch (hot-swap a core's active protocol). */
export function switchCore(
  instanceId: string,
  protocolId: string,
  drainMs = 250,
): Promise<{ migrated: boolean }> {
  // The control plane currently exposes hot-swap via the MCP tools; the REST
  // path is reserved under /v1/cores/switch for the dashboard.
  return request<{ migrated: boolean }>("/v1/cores/switch", {
    method: "POST",
    body: JSON.stringify({ instance_id: instanceId, protocol_id: protocolId, drain_ms: drainMs }),
  }).catch((err: unknown) => {
    // Surface a structured error; the caller decides UX.
    throw err instanceof ApiError ? err : new ApiError(String(err), 0);
  });
}

/** GET /v1/route?domain=&ip= */
export function getRoute(domain: string, ip = ""): Promise<RouteResponse> {
  const qs = new URLSearchParams({ domain, ip });
  return request<RouteResponse>(`/v1/route?${qs.toString()}`);
}

/** POST /v1/subscriptions/verify */
export function verifyToken(token: string, nowUnix = 0): Promise<VerifyTokenResponse> {
  return request<VerifyTokenResponse>("/v1/subscriptions/verify", {
    method: "POST",
    body: JSON.stringify({ token, now_unix: nowUnix }),
  });
}

/** POST /v1/subscriptions/issue */
export function issueToken(input: {
  subscription_id: string;
  user_id: string;
  bytes_total: number;
  bytes_used?: number;
  expires_unix: number;
}): Promise<IssueTokenResponse> {
  return request<IssueTokenResponse>("/v1/subscriptions/issue", {
    method: "POST",
    body: JSON.stringify({ bytes_used: 0, ...input }),
  });
}

/** GET /v1/subscriptions/audit-root */
export function getAuditRoot(): Promise<AuditRootResponse> {
  return request<AuditRootResponse>("/v1/subscriptions/audit-root");
}
