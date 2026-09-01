#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${SHANNON_SMOKE_URL:-}" || -z "${SHANNON_SMOKE_REPO:-}" ]]; then
  printf '%s\n' 'Set SHANNON_SMOKE_URL to an authorized live target and SHANNON_SMOKE_REPO to its repository path.' >&2
  exit 2
fi

if [[ ! -d "$SHANNON_SMOKE_REPO" ]]; then
  printf 'Repository does not exist: %s\n' "$SHANNON_SMOKE_REPO" >&2
  exit 2
fi

stamp="$(date +%s)"
url_workspace="docker-url-only-${stamp}"
source_workspace="docker-source-assisted-${stamp}"
timeout_seconds="${SHANNON_SMOKE_TIMEOUT_SECONDS:-1800}"

wait_for_session() {
  local workspace="$1"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    local session="workspaces/${workspace}/.shannon/session.json"
    if [[ -f "$session" ]]; then
      local status
      status="$(node -e "const f=require('fs');const s=JSON.parse(f.readFileSync(process.argv[1],'utf8'));process.stdout.write(s.session.status)" "$session")"
      case "$status" in
        completed) return 0 ;;
        failed|cancelled)
          printf '%s finished with status %s\n' "$workspace" "$status" >&2
          return 1
          ;;
      esac
    fi
    sleep 2
  done
  printf '%s did not complete within %s seconds\n' "$workspace" "$timeout_seconds" >&2
  return 1
}

pnpm build

./shannon start --url "$SHANNON_SMOKE_URL" --workspace "$url_workspace" --pipeline-testing
node -e "const f=require('fs');const r=JSON.parse(f.readFileSync(process.argv[1],'utf8'));if(r.kind!=='managed'||r.version!==1||r.snapshot.sourceMode!=='url-only'||'repoPath'in r.snapshot)process.exit(1)" "workspaces/${url_workspace}/.shannon/run.json"
wait_for_session "$url_workspace"

./shannon start --url "$SHANNON_SMOKE_URL" --repo "$SHANNON_SMOKE_REPO" --workspace "$source_workspace" --pipeline-testing
node -e "const f=require('fs');const r=JSON.parse(f.readFileSync(process.argv[1],'utf8'));if(r.kind!=='managed'||r.version!==1||r.snapshot.sourceMode!=='source-assisted'||!r.snapshot.repoPath)process.exit(1)" "workspaces/${source_workspace}/.shannon/run.json"
wait_for_session "$source_workspace"

printf 'Docker pipeline smoke passed: %s and %s\n' "$url_workspace" "$source_workspace"
