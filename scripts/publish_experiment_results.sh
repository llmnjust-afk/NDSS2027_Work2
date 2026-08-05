#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <results-directory>" >&2
  exit 2
fi

results_dir="$1"
repo_root="$(git rev-parse --show-toplevel)"
results_abs="$(realpath -m "$results_dir")"
auth_file="$repo_root/.git/paperguru-auth.env"
askpass_file="$repo_root/.git/paperguru-askpass.sh"

cleanup() {
  rm -f "$askpass_file"
}
trap cleanup EXIT

if [[ -f "$auth_file" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$auth_file"
  set +a
  if [[ -z "${PAT:-}" ]]; then
    echo "PAT is missing from $auth_file" >&2
    exit 2
  fi
  cat >"$askpass_file" <<'SH'
#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' "${GITHUB_USERNAME:-llmnjust-afk}" ;;
  *Password*) printf '%s\n' "$PAT" ;;
  *) exit 1 ;;
esac
SH
  chmod 700 "$askpass_file"
  export GIT_ASKPASS="$askpass_file" GIT_TERMINAL_PROMPT=0
fi

case "$results_abs" in
  "$repo_root"/*) ;;
  *)
    echo "Results directory must be inside the Git repository." >&2
    exit 2
    ;;
esac

if [[ ! -d "$results_abs" ]]; then
  echo "Results directory does not exist: $results_abs" >&2
  exit 2
fi

results_rel="${results_abs#"$repo_root"/}"
git -C "$repo_root" add -f -- "$results_rel"

if git -C "$repo_root" diff --cached --quiet -- "$results_rel"; then
  echo "No new experiment results to publish."
  exit 0
fi

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
git -C "$repo_root" commit -m "Record EffectGuard experiment results ($timestamp)" -- "$results_rel"

for attempt in 1 2 3; do
  if git -C "$repo_root" push origin HEAD:main; then
    rm -f "$auth_file"
    echo "Published experiment results to origin/main."
    exit 0
  fi
  echo "Push attempt $attempt failed; retrying in $((attempt * 10)) seconds." >&2
  sleep "$((attempt * 10))"
done

echo "Results are committed locally but could not be pushed." >&2
exit 1
