#!/usr/bin/env bash
# Run from the Compose project directory after authenticating to the registry.
set -euo pipefail

# Serialize deployments on this host too, including manual invocations.
exec 9>.deploy.lock
flock -w 300 9

docker compose pull backend web
log=$(mktemp)
trap 'rm -f "$log"' EXIT
if docker compose up -d --remove-orphans >"$log" 2>&1; then
  cat "$log"
  exit 0
else
  status=$?
  cat "$log" >&2
fi

# A failed Compose recreation can leave a hash-prefixed service container.
# Recover only this project's application services, and only for that conflict.
if ! grep -Eq 'Conflict\. The container name "/([[:xdigit:]]+_)?soc-(backend|web)-[0-9]+"' "$log"; then
  exit "$status"
fi

echo 'Recovering conflicting SOC application containers; retrying once.' >&2
# Named database, Redis, Keycloak, and report volumes are left in place.
docker compose rm --stop --force backend web
docker compose up -d --remove-orphans
