// k6 SSE stream stress test for the Aether-X control-plane broadcaster.
//
// Each VU opens /v1/telemetry/stream, reads the initial events, asserts a 200
// + payload, then releases. Scale via K6_VUS / K6_DURATION.
//
//   k6 run tests/load/sse-stream.js
//   K6_VUS=1000 K6_DURATION=1m k6 run tests/load/sse-stream.js
//
// NOTE: k6's HTTP client consumes a finite response body; the stub/real server
// is expected to flush an initial `event: open` + at least one `data:` line so
// the connection is observable without holding it open forever.

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter } from "k6/metrics";

const BASE = __ENV.BASE_URL || "http://localhost:8090";
const VUS = parseInt(__ENV.K6_VUS || "8", 10);
const DURATION = __ENV.K6_DURATION || "15s";

const streamsOpened = new Counter("sse_streams_opened");

export const options = {
  scenarios: {
    sse: {
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
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<150"],
  },
};

export default function () {
  const res = http.get(`${BASE}/v1/telemetry/stream`, {
    headers: { Accept: "text/event-stream" },
    timeout: "5s",
  });

  const ok = check(res, {
    "stream 200": (r) => r.status === 200,
    "stream has data": (r) => typeof r.body === "string" && r.body.includes("data:"),
  });

  if (ok) {
    streamsOpened.add(1);
  }

  sleep(0.1);
}
