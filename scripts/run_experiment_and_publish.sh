#!/usr/bin/env bash
set -uo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <results-directory> <command> [args ...]" >&2
  exit 2
fi

results_dir="$1"
shift
repo_root="$(git rev-parse --show-toplevel)"
mkdir -p "$results_dir"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
"$@" 2>&1 | tee "$results_dir/experiment.log"
experiment_status=${PIPESTATUS[0]}
set -e
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - "$results_dir/run_status.json" "$started_at" "$finished_at" "$experiment_status" <<'PY'
import json
import sys
from pathlib import Path

path, started_at, finished_at, status = sys.argv[1:]
Path(path).write_text(
    json.dumps(
        {
            "started_at": started_at,
            "finished_at": finished_at,
            "exit_code": int(status),
            "completed": int(status) == 0,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

"$repo_root/scripts/publish_experiment_results.sh" "$results_dir"
publish_status=$?

if [[ $experiment_status -ne 0 ]]; then
  echo "Experiment failed with exit code $experiment_status." >&2
  exit "$experiment_status"
fi
exit "$publish_status"
