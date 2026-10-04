#!/bin/sh
# Creates buckets. `raw` is created with Object Lock (implies versioning) and a
# default retention. The prototype defaults to GOVERNANCE mode with a short period
# so a dev stack can be wiped; production uses COMPLIANCE for 15 years
# (plan.md section 12, milestone M8).
set -eu

# The MinIO image has no shell or curl for a healthcheck, so wait here instead.
i=0
until mc alias set local "http://minio:9000" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1 \
      && mc ready local >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -ge 60 ] && { echo "minio not ready after 120s"; exit 1; }
  sleep 2
done

if ! mc ls local/raw >/dev/null 2>&1; then
  mc mb --with-lock local/raw
fi
mc retention set --default "${RAW_LOCK_MODE:-GOVERNANCE}" "${RAW_LOCK_PERIOD:-1d}" local/raw

for b in incoming quarantine warehouse index; do
  mc mb --ignore-existing "local/$b"
done
mc version enable local/incoming

# Archive tier (plan.md 12.2): a second MinIO stands in for deep archive. The raw
# bucket's lifecycle rule transitions ONLY objects tagged sealed=true, so an
# unsealed partition can never reach the archive (the seal manager sets the tag).
if [ -n "${ARCHIVE_ENDPOINT:-}" ]; then
  i=0
  until mc alias set archive "$ARCHIVE_ENDPOINT" "$ARCHIVE_USER" "$ARCHIVE_PASSWORD" >/dev/null 2>&1 \
        && mc ready archive >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -ge 60 ] && { echo "archive tier not ready"; exit 1; }; sleep 2
  done
  mc mb --ignore-existing archive/raw-archive
  if ! mc ilm tier ls local 2>/dev/null | grep -q "${ARCHIVE_TIER:-ARCHIVE}"; then
    mc ilm tier add minio local "${ARCHIVE_TIER:-ARCHIVE}" --endpoint "$ARCHIVE_ENDPOINT" \
      --access-key "$ARCHIVE_USER" --secret-key "$ARCHIVE_PASSWORD" --bucket raw-archive
  fi
  if ! mc ilm rule ls local/raw 2>/dev/null | grep -q "${ARCHIVE_TIER:-ARCHIVE}"; then
    mc ilm rule add local/raw --transition-days "${ARCHIVE_AFTER_DAYS:-1}" \
      --transition-tier "${ARCHIVE_TIER:-ARCHIVE}" --tags "sealed=true"
  fi
  mc ilm rule ls local/raw
fi

mc ls local
echo "minio-init done"
