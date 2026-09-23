#!/usr/bin/env bash
# Run on the demo host after synchronizing the exact release source tree.
# The database dump is retained for manual recovery; automatic rollback only
# restores the gateway binary because schema changes may be irreversible.
set -euo pipefail
umask 077

if [[ $# -ne 1 || ! $1 =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: deploy-systemd-demo.sh <40-character commit SHA>" >&2
  exit 2
fi

release_commit=$1
app_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
backup_root=${DLP_BACKUP_ROOT:-"${app_dir}-backups"}
service_name=${DLP_GATEWAY_SERVICE:-dlp-agent-gateway.service}
postgres_container=${DLP_POSTGRES_CONTAINER:-dlp-agent-postgres}
backup_dir="${backup_root}/$(date -u +%Y%m%dT%H%M%SZ)-${release_commit:0:8}"

cd "$app_dir"
if [[ ! -f .env || ! -x bin/dlp-gateway || ! -f DEPLOYED_COMMIT ]]; then
  echo "missing private config, current binary, or deployment marker" >&2
  exit 2
fi
if ! systemctl --user is-active --quiet "$service_name"; then
  echo "gateway service is not active before deployment" >&2
  exit 2
fi

mkdir -p -- "$backup_dir"
chmod 700 -- "$backup_dir"
cp -p -- bin/dlp-gateway "$backup_dir/dlp-gateway.previous"
cp -p -- DEPLOYED_COMMIT "$backup_dir/DEPLOYED_COMMIT.previous"
docker exec "$postgres_container" pg_dump -U dlp -d dlp -Fc > "$backup_dir/postgres.dump"
test -s "$backup_dir/postgres.dump"
chmod 600 -- "$backup_dir/postgres.dump"

go test ./...
go build -trimpath -o "$backup_dir/dlp-gateway.next" ./cmd/dlp-gateway
go build -trimpath -o "$backup_dir/dlp-feishu-audit-sync.next" ./cmd/dlp-feishu-audit-sync
install -m 700 -- "$backup_dir/dlp-gateway.next" bin/dlp-gateway.next
install -m 700 -- "$backup_dir/dlp-feishu-audit-sync.next" bin/dlp-feishu-audit-sync
activated=0
restore_on_error() {
  failure_status=$?
  if [[ $activated -eq 1 ]]; then
    echo "deployment command failed; restoring previous gateway" >&2
    install -m 700 -- "$backup_dir/dlp-gateway.previous" bin/dlp-gateway
    cp -p -- "$backup_dir/DEPLOYED_COMMIT.previous" DEPLOYED_COMMIT
    systemctl --user restart "$service_name" || true
  fi
  exit "$failure_status"
}
trap restore_on_error ERR
mv -f -- bin/dlp-gateway.next bin/dlp-gateway
activated=1
printf '%s\n' "$release_commit" > DEPLOYED_COMMIT.next
chmod 600 -- DEPLOYED_COMMIT.next
mv -f -- DEPLOYED_COMMIT.next DEPLOYED_COMMIT

if systemctl --user restart "$service_name"; then
  for attempt in {1..20}; do
    if systemctl --user is-active --quiet "$service_name" &&
      curl --silent --show-error --fail --max-time 2 http://127.0.0.1:18080/ready >/dev/null; then
      activated=0
      trap - ERR
      echo "deployed ${release_commit}; backup: ${backup_dir}"
      exit 0
    fi
    sleep 1
  done
fi

echo "readiness failed; restoring previous gateway binary and marker" >&2
install -m 700 -- "$backup_dir/dlp-gateway.previous" bin/dlp-gateway
cp -p -- "$backup_dir/DEPLOYED_COMMIT.previous" DEPLOYED_COMMIT
systemctl --user restart "$service_name"
if ! curl --silent --show-error --fail --max-time 3 http://127.0.0.1:18080/ready >/dev/null; then
  echo "rollback also failed; inspect service and database backup: ${backup_dir}" >&2
fi
exit 1
