import type { Page, Route } from "@playwright/test";

/** Shared network mocks so E2E never needs the Go control plane running. */

const CORS = { "Access-Control-Allow-Origin": "*" };

export function mockCores(page: Page, instances: unknown[] = defaultCores()) {
  return page.route("**/v1/cores", (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: CORS,
      body: JSON.stringify({ instances }),
    }),
  );
}

export function defaultCores() {
  return [
    {
      instance_id: "edge-1",
      protocol_id: "reality-vision",
      status: "CORE_STATUS_RUNNING",
      restart_count: 0,
    },
    {
      instance_id: "edge-2",
      protocol_id: "hysteria2",
      status: "CORE_STATUS_DEGRADED",
      restart_count: 2,
    },
  ];
}

/** Mock the audit-root (drives the Merkle tree leaf count). */
export function mockAuditRoot(page: Page, count = 7) {
  return page.route("**/v1/subscriptions/audit-root", (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: CORS,
      body: JSON.stringify({
        merkle_root: "a".repeat(64),
        chain_root: "b".repeat(64),
        count,
      }),
    }),
  );
}

/** Mock token verification. */
export function mockVerifyToken(page: Page, signatureValid = true) {
  return page.route("**/v1/subscriptions/verify", (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: CORS,
      body: JSON.stringify({
        signature_valid: signatureValid,
        expired: false,
        quota_exhausted: false,
        is_live: signatureValid,
        claims: {
          subscription_id: "sub-1",
          user_id: "u-1",
          bytes_total: 1000,
          bytes_used: 0,
          expires_unix: 2_000_000_000,
          issued_unix: 1_000_000_000,
          nonce: "n",
        },
      }),
    }),
  );
}

/** Mock the SSE telemetry stream with one pulse of the given shape. */
export function mockTelemetryStream(
  page: Page,
  pulse: Record<string, unknown> = { latency_ms: 220, packet_loss: true, protocol: "x" },
) {
  return page.route("**/v1/telemetry/stream", (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      headers: { ...CORS, Connection: "keep-alive" },
      body: `data: ${JSON.stringify(pulse)}\n\n`,
    }),
  );
}

/** Mock GET /v1/me/subscription (authenticated subscriber status). */
export function mockMeSubscription(page: Page, overrides: Partial<MeSubscription> = {}) {
  const base: MeSubscription = {
    subscription_id: "sub-pro-001",
    user_id: "user-pro",
    bytes_used: 12_500_000_000,
    bytes_total: 50_000_000_000,
    bytes_remaining: 37_500_000_000,
    expires_at: "2027-07-24T00:00:00Z",
    expires_unix: Math.floor(Date.now() / 1000) + 30 * 86400,
    days_remaining: 30,
    usage_percent: 25,
    plan_type: "pro",
    plan_name: "Pro",
    is_live: true,
    is_expired: false,
    is_quota_exhausted: false,
    is_revoked: false,
    devices: [],
    mirror_urls: [],
    sub_url: "https://sub.aether-x.local/sub/tok-pro-live-001",
    ...overrides,
  };
  return page.route("**/v1/me/subscription", (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: CORS,
      body: JSON.stringify(base),
    }),
  );
}

/** Mock GET /v1/sub/clients — returns the built-in client scheme catalog. */
export function mockSubClients(page: Page) {
  const clients = [
    { name: "Sing-box", platform: "all", uri: "sing-box://import-remote-profile?url={{SUB_URL_ENCODED}}&name={{REMARK}}", icon: "singbox", priority: 10 },
    { name: "v2rayNG", platform: "android", uri: "v2rayng://install-sub?url={{SUB_URL_ENCODED}}&name={{REMARK}}", icon: "v2rayng", priority: 20 },
    { name: "Shadowrocket", platform: "ios", uri: "shadowrocket://add/sub://{{SUB_URL_BASE64}}", icon: "shadowrocket", priority: 15 },
    { name: "FlClash", platform: "all", uri: "clash://install-config?url={{SUB_URL_ENCODED}}&name={{REMARK}}", icon: "flclash", priority: 30 },
  ];
  return page.route("**/v1/sub/clients**", (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: CORS,
      body: JSON.stringify({ version: "1.0", platform: "all", clients }),
    }),
  );
}

export interface MeSubscription {
  subscription_id: string;
  user_id: string;
  bytes_used: number;
  bytes_total: number;
  bytes_remaining: number;
  expires_at: string;
  expires_unix: number;
  days_remaining: number;
  usage_percent: number;
  plan_type: string;
  plan_name: string;
  is_live: boolean;
  is_expired: boolean;
  is_quota_exhausted: boolean;
  is_revoked: boolean;
  devices: { device_id: string; fingerprint: string; platform: string; last_seen: string }[];
  mirror_urls: string[];
  sub_url: string;
}

/** Mock GET /v1/transports — the Transport Network catalog (admin builder). */
export function mockTransports(page: Page) {
  const catalog = {
    version: "1.0",
    protocols: [
      { id: "vless", name: "VLESS", name_fa: "VLESS" },
      { id: "vmess", name: "VMess", name_fa: "VMess" },
      { id: "trojan", name: "Trojan", name_fa: "تروجان" },
      { id: "shadowsocks", name: "Shadowsocks", name_fa: "شادوساکس" },
    ],
    transports: [
      { id: "xhttp", name: "XHTTP", name_fa: "XHTTP", family: "http", needs_path: true, needs_host: true, needs_mode: true, modes: ["packet-up", "stream-up", "stream-one"], needs_service: false, description: "Newest Xray transport.", newest: true, legacy: false },
      { id: "httpupgrade", name: "HTTPUpgrade", name_fa: "HTTPUpgrade", family: "websocket", needs_path: true, needs_host: true, needs_mode: false, needs_service: false, description: "HTTP Upgrade.", newest: true, legacy: false },
      { id: "grpc", name: "gRPC", name_fa: "gRPC", family: "grpc", needs_path: false, needs_host: false, needs_mode: false, needs_service: true, description: "gRPC streams.", newest: false, legacy: false },
      { id: "h2", name: "HTTP/2", name_fa: "HTTP/2", family: "http", needs_path: true, needs_host: true, needs_mode: false, needs_service: false, description: "HTTP/2.", newest: false, legacy: false },
      { id: "ws", name: "WebSocket", name_fa: "وب‌سوکت", family: "websocket", needs_path: true, needs_host: true, needs_mode: false, needs_service: false, description: "WebSocket.", newest: false, legacy: false },
      { id: "kcp", name: "mKCP", name_fa: "mKCP", family: "udp", needs_path: false, needs_host: false, needs_mode: true, modes: ["none", "srtp", "utp", "wechat-video", "dtls", "wireguard"], needs_service: false, description: "mKCP.", newest: false, legacy: false },
      { id: "tcp", name: "TCP", name_fa: "TCP", family: "stream", needs_path: false, needs_host: false, needs_mode: false, needs_service: false, description: "Raw TCP.", newest: false, legacy: false },
      { id: "quic", name: "QUIC", name_fa: "QUIC", family: "udp", needs_path: false, needs_host: true, needs_mode: false, needs_service: false, description: "QUIC.", newest: true, legacy: false },
    ],
  };
  return page.route("**/v1/transports", (route: Route) =>
    route.fulfill({ status: 200, contentType: "application/json", headers: CORS, body: JSON.stringify(catalog) }),
  );
}

/**
 * Mock POST /v1/admin/build-config. DYNAMIC: reflects the requested protocol +
 * transport into the generated share link so tests can assert the selection
 * actually flows through to the output.
 */
export function mockBuildConfig(page: Page) {
  return page.route("**/v1/admin/build-config", async (route: Route) => {
    const body = (route.request().postDataJSON() ?? {}) as { protocol?: string; transport?: string };
    const proto = body.protocol ?? "vless";
    const tr = body.transport ?? "xhttp";
    const share = `${proto}://0d1f@node.aether-x.example:443?type=${tr}&security=tls#Aether-X`;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: CORS,
      body: JSON.stringify({
        share_link: share,
        clash: "proxies:\n  - name: Aether-X\n    network: " + tr,
        singbox: '{\n  "outbounds": [\n    {"type": "' + proto + '", "transport": {"type": "' + tr + '"}}\n  ]\n}',
        base64: btoa(share),
        protocol: proto,
        transport: tr,
      }),
    });
  });
}


/** Mock the AI client-registry workflow (Part 2 §6). DYNAMIC: the draft
 *  endpoint reflects the pasted docs_url into the drafted name; confirm flips
 *  status to "confirmed". A closure queue is shared across draft/list/confirm. */
export function mockClientDraftWorkflow(page: Page) {
  type QEntry = { name: string; platform: string; uri: string; status: string; note?: string };
  const queue: QEntry[] = [];

  const deriveName = (url: string): string => {
    const seg = url.split("/").filter(Boolean).pop() ?? "DraftedClient";
    return seg.charAt(0).toUpperCase() + seg.slice(1);
  };

  // POST /v1/admin/clients/draft — reflect URL into name + seed the queue.
  page.route("**/v1/admin/clients/draft", async (route: Route) => {
    const body = (route.request().postDataJSON() ?? {}) as { docs_url?: string };
    const name = deriveName(body.docs_url ?? "");
    if (!queue.some((d) => d.name === name)) {
      queue.push({ name, platform: "all", uri: "", status: "ai-drafted-pending-review", note: `AI draft from ${body.docs_url ?? ""} — verify deep-link scheme before confirming.` });
    }
    await route.fulfill({
      status: 200, contentType: "application/json", headers: CORS,
      body: JSON.stringify({ status: "drafted", draft: { name, platform: "all", uri: "", icon: "📦", priority: 99, status: "ai-drafted-pending-review", sourceCheckedAt: "2026-07-24T00:00:00Z", note: "AI draft — verify before confirming." } }),
    });
  });

  // GET /v1/admin/clients/drafts — return the shared queue.
  page.route("**/v1/admin/clients/drafts", (route: Route) =>
    route.fulfill({ status: 200, contentType: "application/json", headers: CORS, body: JSON.stringify({ drafts: queue }) }),
  );

  // POST /v1/admin/clients/confirm — flip status to "confirmed".
  page.route("**/v1/admin/clients/confirm", async (route: Route) => {
    const body = (route.request().postDataJSON() ?? {}) as { name?: string };
    const target = queue.find((d) => d.name === body.name);
    if (target) target.status = "confirmed";
    await route.fulfill({ status: 200, contentType: "application/json", headers: CORS, body: JSON.stringify({ status: "confirmed", client: target ?? null }) });
  });
}

/** Collect uncaught page errors for the "no console errors" assertions. */
export function collectPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  return errors;
}
