#!/usr/bin/env bash
# Run a real loopback TCP/TLS/HTTPS DNS-JSON transaction against a controlled
# target. It creates no production artifact and does not contact an ISP.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workdir="$(mktemp -d)"
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  rm -rf "$workdir"
}
trap cleanup EXIT

port="$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=localhost' \
  -keyout "$workdir/key.pem" -out "$workdir/cert.pem" >/dev/null 2>&1
python3 "$root/tests/oob/controlled_doh_target.py" \
  --port "$port" --certificate "$workdir/cert.pem" --key "$workdir/key.pem" \
  --observer-log "$workdir/observer.ndjson" &
server_pid=$!

for _ in $(seq 1 50); do
  if ss -ltn "sport = :$port" | grep -q LISTEN; then break; fi
  sleep 0.02
done

curl --silent --show-error --fail --cacert "$workdir/cert.pem" \
  --trace-ascii "$workdir/curl.trace" \
  --header 'accept: application/dns-json' \
  "https://localhost:$port/dns-query?name=example.test&type=A" >"$workdir/response.json"
python3 - "$workdir/response.json" <<'PY'
import json, sys
response=json.load(open(sys.argv[1]))
assert response["Status"] == 0
assert response["Answer"][0]["data"] == "192.0.2.53"
print("controlled_doh_response=PASS")
PY
printf '%s\n' '--- controlled observer record ---'
cat "$workdir/observer.ndjson"
printf '%s\n' '--- client HTTPS trace (application-visible) ---'
grep -E '^=> Send header|^GET |^Host:|^accept:|^<= Recv header|^HTTP/' "$workdir/curl.trace" || true
printf '%s\n' 'controlled_doh_probe=PASS'
