#!/usr/bin/env bash
# Start an isolated, loopback-only coturn instance for WebRTC relay tests.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required to provision the isolated coturn test service" >&2
  exit 2
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin is required" >&2
  exit 2
fi

docker compose -f "$root/docker-compose.yml" up --build --detach --wait
container_id="$(docker compose -f "$root/docker-compose.yml" ps -q turn)"
docker cp "$container_id:/run/aether-turn/credentials.env" "$root/runtime-credentials.env"
chmod 0600 "$root/runtime-credentials.env"
echo "TURN provisioned on loopback; ephemeral credentials: $root/runtime-credentials.env"
echo "Run '$root/teardown.sh' after the isolated relay drill."
