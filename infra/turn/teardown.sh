#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required to tear down the isolated coturn test service" >&2
  exit 2
fi
docker compose -f "$root/docker-compose.yml" down --volumes --remove-orphans
rm -f "$root/runtime-credentials.env"
echo "isolated coturn test service removed"
