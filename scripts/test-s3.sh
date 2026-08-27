#!/usr/bin/env bash
set -euo pipefail
docker compose -f compose.test.yml up -d --wait minio
trap 'docker compose -f compose.test.yml down -v' EXIT
docker compose -f compose.test.yml run --rm create-bucket
if [[ "${COG_COVERAGE:-0}" == "1" ]]; then
  cargo llvm-cov --no-clean --test s3 -- --ignored
else
  cargo test --test s3 -- --ignored
fi
