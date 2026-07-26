#!/usr/bin/env python3
"""Lightweight stub of the Aether-X control plane for k6 load tests.

Serves canned JSON for the REST endpoints and a *finite* SSE response so k6's
HTTP client can consume it without holding the connection open forever. This is
NOT the real Go server — it exists purely so `make load-test` is hermetic.

    python3 tests/load/stub.py          # listens on :8090
    BASE_URL=http://localhost:8090 k6 run tests/load/rest-api.js
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CORS = {"Access-Control-Allow-Origin": "*", "Cache-Control": "no-store"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _sse(self):
        payload = (
            "event: open\ndata: {}\n\n"
            + "data: "
            + json.dumps(
                {
                    "node_id": "n1",
                    "protocol": "reality-vision",
                    "isp": "MCI",
                    "kind": "EVENT_CONNECT_SUCCESS",
                    "latency_ms": 120,
                    "packet_loss": False,
                    "rst": False,
                    "ts": "2026-01-01T00:00:00Z",
                }
            )
            + "\n\n"
        )
        body = payload.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/healthz", "/readyz"):
            self._json({"status": "ok", "build": "stub"})
        elif path == "/v1/cores":
            self._json(
                {
                    "instances": [
                        {"instance_id": "edge-1", "protocol_id": "reality-vision",
                         "status": "CORE_STATUS_RUNNING", "restart_count": 0},
                    ]
                }
            )
        elif path == "/v1/route":
            self._json({"action": "DIRECT", "domain": "bank.mellat.ir", "ip": "78.38.5.5"})
        elif path == "/v1/subscriptions/audit-root":
            self._json({"merkle_root": "a" * 64, "chain_root": "b" * 64, "count": 7})
        elif path == "/v1/telemetry/stream":
            self._sse()
        else:
            self._json({})

    def do_POST(self):
        path = self.path.split("?")[0]
        # drain body
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        if path == "/v1/cores/switch":
            self._json({"migrated": True})
        elif path == "/v1/subscriptions/verify":
            self._json({"signature_valid": True, "expired": False,
                        "quota_exhausted": False, "is_live": True})
        elif path == "/v1/subscriptions/issue":
            self._json({"token": "tok-stub", "audit_seq": 1,
                        "audit_hash": "c" * 64, "verifying_key": "d" * 64})
        else:
            self._json({})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, *args):  # silence
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8090), Handler)
    print("stub control plane on :8090")
    server.serve_forever()
