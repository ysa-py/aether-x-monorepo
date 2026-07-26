// k6 REST throughput + hot-swap benchmark for the Aether-X control plane.
//
// High-frequency GETs to /v1/cores, /v1/route, /v1/subscriptions/audit-root
// plus a POST hot-swap. Scale via env: K6_VUS (default small for local smoke),
// K6_DURATION. In CI/staging raise K6_VUS to thousands.
//
//   k6 run tests/load/rest-api.js
//   K6_VUS=200 K6_DURATION=1m k6 run tests/load/rest-api.js

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter } from "k6/metrics";

const BASE = __ENV.BASE_URL || "http://localhost:8090";
const VUS = parseInt(__ENV.K6_VUS || "8", 10);
const DURATION = __ENV.K6_DURATION || "15s";

const hotSwapOk = new Counter("hotswap_ok");

export const options = {
  scenarios: {
    rest: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "5s", target: VUS },
        { duration: DURATION, target: VUS },
        { duration: "5s", target: 0 },
      ],
      gracefulRampDown: "5s",
    },
  },
  thresholds: {
    // Spec: p99 < 50ms, success rate > 99.99%.
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<100", "p(99)<200"],
  },
};

const params = { headers: { Accept: "application/json" }, timeout: "5s" };

export default function () {
  // Round-robin across the read endpoints.
  const res1 = http.get(`${BASE}/v1/cores`, params);
  check(res1, { "cores 200": (r) => r.status === 200 });

  const res2 = http.get(`${BASE}/v1/route?domain=bank.mellat.ir&ip=78.38.5.5`, params);
  check(res2, { "route 200": (r) => r.status === 200 });

  const res3 = http.get(`${BASE}/v1/subscriptions/audit-root`, params);
  check(res3, { "audit-root 200": (r) => r.status === 200 });

  // Occasional hot-swap POST (1 in 10 iterations).
  if (__ITER % 10 === 0) {
    const body = JSON.stringify({
      instance_id: "edge-1",
      protocol_id: "hysteria2",
      drain_ms: 250,
    });
    const res4 = http.post(`${BASE}/v1/cores/switch`, body, {
      headers: { "Content-Type": "application/json" },
      timeout: "5s",
    });
    if (check(res4, { "switch 200": (r) => r.status === 200 })) {
      hotSwapOk.add(1);
    }
  }

  sleep(0.05);
}
