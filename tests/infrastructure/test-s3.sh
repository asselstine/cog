#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
compose="$root/tests/infrastructure/compose.yml"
cd "$root"
docker compose -f "$compose" up -d --wait minio
trap 'docker compose -f "$compose" down -v' EXIT
docker compose -f "$compose" run --rm create-bucket
if [[ "${COG_COVERAGE:-0}" == "1" ]]; then
  cargo llvm-cov --no-clean --test s3 -- --ignored
else
  cargo test --test s3 -- --ignored
fi
