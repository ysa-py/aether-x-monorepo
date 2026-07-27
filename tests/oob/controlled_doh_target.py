#!/usr/bin/env python3
"""Controlled HTTPS DNS-JSON target for out-of-band probe verification.

This is a test fixture only. It listens on loopback, logs request metadata an
observer at the controlled endpoint would see, and returns a deterministic
DNS-JSON response for `example.test`. It is not a public resolver and is never
part of a production image.
"""

from __future__ import annotations

import argparse
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


class DohHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - HTTP handler API
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        observer_record = {
            "method": self.command,
            "path": parsed.path,
            "query_keys": sorted(query),
            "name": query.get("name", [""])[0],
            "type": query.get("type", [""])[0],
            "accept": self.headers.get("accept", ""),
            "user_agent": self.headers.get("user-agent", ""),
            "content_length": self.headers.get("content-length", ""),
        }
        self.server.observer_log.write(json.dumps(observer_record, sort_keys=True) + "\n")
        self.server.observer_log.flush()

        if parsed.path != "/dns-query" or query.get("name") != ["example.test"]:
            self.send_error(404)
            return
        body = json.dumps(
            {
                "Status": 0,
                "Question": [{"name": "example.test.", "type": 1}],
                "Answer": [{"name": "example.test.", "type": 1, "TTL": 30, "data": "192.0.2.53"}],
            },
            separators=(",", ":"),
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/dns-json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--observer-log", type=Path, required=True)
    args = parser.parse_args()

    with args.observer_log.open("a", encoding="utf-8") as observer_log:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), DohHandler)
        server.observer_log = observer_log
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.certificate, args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
