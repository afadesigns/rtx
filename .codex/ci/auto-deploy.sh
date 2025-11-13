#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

log() {
  printf '[codex-cd] %s\n' "$1"
}

truthy() {
  local value="${1:-}"
  value="${value,,}"
  case "$value" in
    1|true|yes|on|enable|enabled) return 0 ;;
  esac
  return 1
}

CD_ROOT=${CODEX_CD_ROOT:-.codex/ci}
CD_PROFILE_PATH=${CODEX_CI_PROFILE_PATH:-$CD_ROOT/profile.resolved.json}
CD_CONFIG_PATH=${CODEX_CI_CONFIG_PATH:-$CD_ROOT/config.json}

CD_CFG_DEPLOY_ENABLE=1
CD_CFG_HOOKS_DEPLOY=1
CD_CFG_REQUIRED_SECRETS=""
CD_CFG_CONFIG_LOADED=0

if [[ -f $CD_CONFIG_PATH ]]; then
  if command -v python3 >/dev/null 2>&1; then
    eval "$(
      CD_CONFIG_PATH="$CD_CONFIG_PATH" python3 <<'PY'
import json
import os

path = os.environ["CD_CONFIG_PATH"]
try:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
except Exception as exc:
    msg = f"[codex-cd] config: failed to parse {path}: {exc}"
    print(f'echo {json.dumps(msg)} >&2')
else:
    def bool_opt(path_keys, default):
        data = cfg
        for part in path_keys.split("."):
            if isinstance(data, dict):
                data = data.get(part)
            else:
                data = None
        if isinstance(data, bool):
            return data
        return default

    def emit_bool(name, value):
        print(f'export {name}="{1 if value else 0}"')

    emit_bool("CD_CFG_DEPLOY_ENABLE", bool_opt("deploy.enable", True))
    emit_bool("CD_CFG_HOOKS_DEPLOY", bool_opt("hooks.deploy", True))

    required = []
    secrets = cfg.get("secrets", {})
    if isinstance(secrets, dict):
        req = secrets.get("required", [])
        if isinstance(req, list):
            required = [str(item) for item in req if isinstance(item, str)]
    print(f'export CD_CFG_REQUIRED_SECRETS="{",".join(required)}"')
    print('export CD_CFG_CONFIG_LOADED="1"')
    msg = f"[codex-cd] config: loaded {path}"
    print(f'echo {json.dumps(msg)} >&2')
PY
    )" || true
  elif command -v jq >/dev/null 2>&1; then
    eval "$(
      jq -r '
        def boolopt($keys; $default):
          reduce ($keys | split(".")) as $seg (.; if type=="object" then .[$seg] else null end) // $default
          | if type=="boolean" then (if . then 1 else 0 end) else (if $default then 1 else 0 end) end;
        "export CD_CFG_DEPLOY_ENABLE=\"\(boolopt(\"deploy.enable\"; true))\"",
        "export CD_CFG_HOOKS_DEPLOY=\"\(boolopt(\"hooks.deploy\"; true))\"",
        "export CD_CFG_REQUIRED_SECRETS=\"\((.secrets.required // [] | map(tostring)) | join(\",\"))\"",
        "export CD_CFG_CONFIG_LOADED=\"1\"",
        "echo \"[codex-cd] config: loaded " + (input_filename) + "\" >&2"
      ' "$CD_CONFIG_PATH"
    )" || true
  else
    log "config: $CD_CONFIG_PATH present but no python3 or jq available; using defaults"
  fi
fi

if [[ -z ${CD_CFG_REQUIRED_SECRETS:-} && -n ${CODEX_CI_REQUIRED_SECRETS:-} ]]; then
  CD_CFG_REQUIRED_SECRETS=${CODEX_CI_REQUIRED_SECRETS}
fi

CD_CHANGED_FILES_JSON=${CODEX_CHANGED_FILES_JSON:-"[]"}
export CD_CHANGED_FILES_JSON
log "deploy: changed files json ${CD_CHANGED_FILES_JSON}"
if [[ -n ${CODEX_SKIP_REASON:-} ]]; then
  log "deploy: upstream CI skip reason '${CODEX_SKIP_REASON}'"
fi
if [[ -n ${CODEX_PRUNED_LANGUAGES_JSON:-} ]]; then
  log "deploy: pruned languages ${CODEX_PRUNED_LANGUAGES_JSON}"
fi
if [[ -n ${CODEX_TOTAL_DURATION_SECONDS:-} ]]; then
  log "deploy: total CI duration ${CODEX_TOTAL_DURATION_SECONDS}s"
fi
if [[ -n ${CODEX_FLAKY_STEPS_JSON:-} ]]; then
  log "deploy: flaky steps detected ${CODEX_FLAKY_STEPS_JSON}"
fi

declare -ag CD_STEP_ORDER=()
declare -Ag CD_STEP_STATUS=()
declare -Ag CD_STEP_RC=()
declare -Ag CD_STEP_NOTES=()

record_step() {
  local label=$1 status=$2 rc=${3:-0} note=${4:-}
  CD_STEP_ORDER+=("$label")
  CD_STEP_STATUS["$label"]=$status
  CD_STEP_RC["$label"]=$rc
  CD_STEP_NOTES["$label"]=$note
}

run_step() {
  local label="$1"
  shift || true
  local rc=0
  if "$@"; then
    record_step "$label" "success" 0 ""
    log "$label: success"
    return 0
  else
    rc=$?
    record_step "$label" "failure" "$rc" ""
    log "$label: failed (rc=$rc)"
    return "$rc"
  fi
}

emit_cd_report() {
  local exit_status=$?
  trap - EXIT
  set +e
  set +u
  set +o pipefail

  mkdir -p "$CD_ROOT"
  local steps_file
  steps_file=$(mktemp)
  for label in "${CD_STEP_ORDER[@]}"; do
    printf '%s|%s|%s|%s\n' "$label" "${CD_STEP_STATUS[$label]-unknown}" "${CD_STEP_RC[$label]-0}" "${CD_STEP_NOTES[$label]-}" >>"$steps_file"
  done

  local timestamp
  timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  export CD_TIMESTAMP="$timestamp"
  export CD_STEPS_FILE="$steps_file"
  export CD_REPORT_JSON="$CD_ROOT/deploy-report.json"
  export CD_REPORT_MD="$CD_ROOT/deploy-report.md"
  export CD_PROFILE_PATH
  export CD_EXIT_STATUS="$exit_status"
  export CD_TARGET="${CODEX_CD_TARGET:-}"
  export CD_BRANCH="${CODEX_CD_BRANCH:-}"
  export CD_REF="${GITHUB_REF:-}"
  export CD_ENABLED="${CODEX_CD_ENABLED:-}"

  local py_bin="python3"
  if ! command -v "$py_bin" >/dev/null 2>&1; then
    if command -v python >/dev/null 2>&1; then
      py_bin="python"
    else
      py_bin=""
    fi
  fi

  if [[ -n $py_bin ]]; then
    "$py_bin" <<'PY'
import json
import os
import pathlib

steps_file = pathlib.Path(os.environ["CD_STEPS_FILE"])
steps: list[dict] = []
if steps_file.exists():
    for line in steps_file.read_text(encoding="utf-8").splitlines():
        parts = line.split("|", 4)
        if len(parts) != 4:
            continue
        name, status, rc, note = parts
        step = {"name": name, "status": status, "rc": int(rc)}
        if note:
            step["note"] = note
        steps.append(step)

profile_path = pathlib.Path(os.environ.get("CD_PROFILE_PATH", ""))
profile = {}
if profile_path.is_file():
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except Exception:
        profile = {}

overall = "success"
for step in steps:
    if step["status"] not in ("success", "skipped"):
        overall = "failed"
        break

report = {
    "timestamp": os.environ["CD_TIMESTAMP"],
    "exit_status": int(os.environ["CD_EXIT_STATUS"]),
    "overall_status": overall,
    "target": os.environ.get("CD_TARGET", ""),
    "branch": os.environ.get("CD_BRANCH", ""),
    "ref": os.environ.get("CD_REF", ""),
    "enabled": os.environ.get("CD_ENABLED", ""),
    "steps": steps,
    "profile": profile,
}
report_path = pathlib.Path(os.environ["CD_REPORT_JSON"])
report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

md_lines = [
    "# Codex Deploy Summary",
    "",
    f"*Status:* **{overall.upper()}** (exit {report['exit_status']})",
]
if report["target"]:
    md_lines.append(f"*Target:* {report['target']}")
if report["branch"]:
    md_lines.append(f"*Branch:* {report['branch']}")
if report["ref"]:
    md_lines.append(f"*Ref:* {report['ref']}")
md_lines.extend([
    "",
    "| Step | Status | RC | Note |",
    "| --- | --- | --- | --- |",
])
for step in steps:
    note = step.get("note", "")
    note = note.replace("|", "\\|")
    md_lines.append(f"| {step['name']} | {step['status']} | {step['rc']} | {note} |")
md_lines.append("")
md_path = pathlib.Path(os.environ["CD_REPORT_MD"])
md_path.write_text("\n".join(md_lines), encoding="utf-8")
PY
    local py_status=$?
    if [[ $py_status -ne 0 ]]; then
      log "report: failed to build deployment summary"
    fi
  else
    log "report: python interpreter not available; skipping deployment summary"
  fi

  rm -f "$steps_file"

  if [[ $exit_status -eq 0 ]]; then
    log "deploy harness complete"
  else
    log "deploy harness failed (rc=$exit_status)"
  fi

  exit "$exit_status"
}

mkdir -p "$CD_ROOT"
trap 'emit_cd_report' EXIT

if [[ ${CD_CFG_DEPLOY_ENABLE:-1} != "1" ]]; then
  log "deploy: disabled via config"
  record_step "gate:config" "skipped" 0 "config disabled"
  exit 0
fi
record_step "gate:config" "success" 0 "config enabled"

if [[ -n ${CD_CFG_REQUIRED_SECRETS:-} ]]; then
  missing=()
  for raw in ${CD_CFG_REQUIRED_SECRETS//,/ }; do
    name=${raw//[[:space:]]/}
    [[ -z $name ]] && continue
    if [[ -z ${!name:-} ]]; then
      missing+=("$name")
    fi
  done
  if ((${#missing[@]})); then
    record_step "gate:secrets" "failure" 1 "missing: ${missing[*]}"
    log "deploy: missing secrets ${missing[*]}"
    exit 1
  else
    record_step "gate:secrets" "success" 0 "all required secrets present"
  fi
else
  record_step "gate:secrets" "skipped" 0 "no required secrets configured"
fi

if ! truthy "${CODEX_CD_ENABLED:-}"; then
  log "deploy: CODEX_CD_ENABLED is not true; skipping deployment"
  record_step "gate:cd-enabled" "skipped" 0 "CODEX_CD_ENABLED not true"
  exit 0
fi
record_step "gate:cd-enabled" "success" 0 "deployment enabled"

current_ref=${GITHUB_REF:-}
allowed_branch=${CODEX_CD_BRANCH:-}
allow_tags=${CODEX_CD_ALLOW_TAGS:-true}

if [[ -n $allowed_branch ]]; then
  if [[ $current_ref == "refs/heads/$allowed_branch" ]]; then
    record_step "gate:branch" "success" 0 "branch matches $allowed_branch"
  elif [[ $current_ref == refs/tags/* ]]; then
    if truthy "$allow_tags"; then
      record_step "gate:branch" "success" 0 "tag ${current_ref#refs/tags/}"
    else
      record_step "gate:branch" "skipped" 0 "tags disabled for deployment"
      exit 0
    fi
  else
    record_step "gate:branch" "skipped" 0 "current ref $current_ref"
    log "deploy: branch gating prevented deployment (expected $allowed_branch)"
    exit 0
  fi
else
  record_step "gate:branch" "skipped" 0 "no branch constraint"
fi

if [[ ${CD_CFG_HOOKS_DEPLOY:-1} != "1" ]]; then
  record_step "deploy:hooks" "skipped" 0 "disabled via config"
  log "deploy: hooks disabled via config"
  exit 0
fi

hooks=()
if [[ -f "$CD_ROOT/deploy.sh" ]]; then
  hooks+=("$CD_ROOT/deploy.sh")
fi
if [[ -f "$CD_ROOT/auto-deploy.local.sh" ]]; then
  hooks+=("$CD_ROOT/auto-deploy.local.sh")
fi
if compgen -G "$CD_ROOT/deploy.d/*.sh" >/dev/null 2>&1; then
  for hook in "$CD_ROOT"/deploy.d/*.sh; do
    [[ -f $hook ]] && hooks+=("$hook")
  done
fi

if [[ ${#hooks[@]} -eq 0 ]]; then
  record_step "deploy:hooks" "skipped" 0 "no deployment hooks defined"
  log "deploy: no deployment hooks found; nothing to do"
  exit 0
fi

record_step "deploy:hooks" "success" 0 "${#hooks[@]} hook(s) registered"

for hook in "${hooks[@]}"; do
  base=$(basename "$hook")
  if [[ -x $hook ]]; then
    run_step "deploy:${base}" "$hook"
  else
    run_step "deploy:${base}" bash "$hook"
  fi
done
