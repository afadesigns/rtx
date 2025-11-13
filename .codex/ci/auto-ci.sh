#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

log() {
  printf '[codex-ci] %s\n' "$1"
}

truthy() {
  local value="${1:-}"
  value="${value,,}"
  case "$value" in
    1|true|yes|on|enable|enabled) return 0 ;;
  esac
  return 1
}

CI_ROOT=${CODEX_CI_ROOT:-.codex/ci}
CI_PROFILE_PATH=${CODEX_CI_PROFILE_PATH:-$CI_ROOT/profile.resolved.json}
CI_CONFIG_PATH=${CODEX_CI_CONFIG_PATH:-$CI_ROOT/config.json}

CI_CFG_PYTHON_ENABLE=1
CI_CFG_PYTHON_TESTS=1
CI_CFG_NODE_ENABLE=1
CI_CFG_NODE_LINT=1
CI_CFG_NODE_TESTS=1
CI_CFG_GO_ENABLE=1
CI_CFG_RUST_ENABLE=1
CI_CFG_TERRAFORM_ENABLE=1
CI_CFG_DOCKER_LINT=1
CI_CFG_HOOKS_CI=1
CI_CFG_REQUIRED_SECRETS=""
CI_CFG_CONFIG_LOADED=0
CI_SCRIPT_START_NS=$(date +%s%N)
CI_STEP_STATE_FILE=$(mktemp)
export CI_STEP_STATE_FILE

if [[ -f $CI_CONFIG_PATH ]]; then
  if command -v python3 >/dev/null 2>&1; then
    eval "$(
      CI_CONFIG_PATH="$CI_CONFIG_PATH" python3 <<'PY'
import json
import os

path = os.environ["CI_CONFIG_PATH"]
try:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
except Exception as exc:
    msg = f"[codex-ci] config: failed to parse {path}: {exc}"
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

    emit_bool("CI_CFG_PYTHON_ENABLE", bool_opt("python.enable", True))
    emit_bool("CI_CFG_PYTHON_TESTS", bool_opt("python.tests", True))
    emit_bool("CI_CFG_NODE_ENABLE", bool_opt("node.enable", True))
    emit_bool("CI_CFG_NODE_LINT", bool_opt("node.lint", True))
    emit_bool("CI_CFG_NODE_TESTS", bool_opt("node.tests", True))
    emit_bool("CI_CFG_GO_ENABLE", bool_opt("go.enable", True))
    emit_bool("CI_CFG_RUST_ENABLE", bool_opt("rust.enable", True))
    emit_bool("CI_CFG_TERRAFORM_ENABLE", bool_opt("terraform.enable", True))
    emit_bool("CI_CFG_DOCKER_LINT", bool_opt("docker.lint", True))
    emit_bool("CI_CFG_HOOKS_CI", bool_opt("hooks.ci", True))

    required = []
    secrets = cfg.get("secrets", {})
    if isinstance(secrets, dict):
        req = secrets.get("required", [])
        if isinstance(req, list):
            required = [str(item) for item in req if isinstance(item, str)]
    print(f'export CI_CFG_REQUIRED_SECRETS="{",".join(required)}"')
    print('export CI_CFG_CONFIG_LOADED="1"')
    msg = f"[codex-ci] config: loaded {path}"
    print(f'echo {json.dumps(msg)} >&2')
PY
    )" || true
  elif command -v jq >/dev/null 2>&1; then
    eval "$(
      jq -r '
        def boolopt($keys; $default):
          reduce ($keys | split(".")) as $seg (.; if type=="object" then .[$seg] else null end) // $default
          | if type=="boolean" then (if . then 1 else 0 end) else (if $default then 1 else 0 end) end;
        "export CI_CFG_PYTHON_ENABLE=\"\(boolopt(\"python.enable\"; true))\"",
        "export CI_CFG_PYTHON_TESTS=\"\(boolopt(\"python.tests\"; true))\"",
        "export CI_CFG_NODE_ENABLE=\"\(boolopt(\"node.enable\"; true))\"",
        "export CI_CFG_NODE_LINT=\"\(boolopt(\"node.lint\"; true))\"",
        "export CI_CFG_NODE_TESTS=\"\(boolopt(\"node.tests\"; true))\"",
        "export CI_CFG_GO_ENABLE=\"\(boolopt(\"go.enable\"; true))\"",
        "export CI_CFG_RUST_ENABLE=\"\(boolopt(\"rust.enable\"; true))\"",
        "export CI_CFG_TERRAFORM_ENABLE=\"\(boolopt(\"terraform.enable\"; true))\"",
        "export CI_CFG_DOCKER_LINT=\"\(boolopt(\"docker.lint\"; true))\"",
        "export CI_CFG_HOOKS_CI=\"\(boolopt(\"hooks.ci\"; true))\"",
        "export CI_CFG_REQUIRED_SECRETS=\"\((.secrets.required // [] | map(tostring)) | join(\",\"))\"",
        "export CI_CFG_CONFIG_LOADED=\"1\"",
        "echo \"[codex-ci] config: loaded " + (input_filename) + "\" >&2"
      ' "$CI_CONFIG_PATH"
    )" || true
  else
    log "config: $CI_CONFIG_PATH present but no python3 or jq available; using defaults"
  fi
fi

if [[ -z ${CI_CFG_REQUIRED_SECRETS:-} && -n ${CODEX_CI_REQUIRED_SECRETS:-} ]]; then
  CI_CFG_REQUIRED_SECRETS=${CODEX_CI_REQUIRED_SECRETS}
fi

CI_CHANGED_FILES_JSON=${CODEX_CHANGED_FILES_JSON:-"[]"}
export CI_CHANGED_FILES_JSON
log "matrix: changed files json ${CI_CHANGED_FILES_JSON}"
export CI_PYTHON_TOUCHED=${CODEX_CI_PYTHON_TOUCHED:-"false"}
export CI_NODE_TOUCHED=${CODEX_CI_NODE_TOUCHED:-"false"}
export CI_GO_TOUCHED=${CODEX_CI_GO_TOUCHED:-"false"}
export CI_RUST_TOUCHED=${CODEX_CI_RUST_TOUCHED:-"false"}
export CI_TERRAFORM_TOUCHED=${CODEX_CI_TERRAFORM_TOUCHED:-"false"}
export CI_DOCKER_TOUCHED=${CODEX_CI_DOCKER_TOUCHED:-"false"}
export CI_FORCE_CI=${CODEX_CI_FORCE_CI:-"false"}
export CI_PRUNED_LANGUAGES=${CODEX_CI_PRUNED_LANGUAGES:-"[]"}
export CI_SKIP_REASON=${CODEX_CI_SKIP_REASON:-""}

if [[ ${CI_FORCE_CI} == "true" ]]; then
  log "matrix: forced execution override active"
fi
if [[ ${CI_PRUNED_LANGUAGES} != "[]" && ${CI_PRUNED_LANGUAGES} != "" ]]; then
  log "matrix: pruned languages ${CI_PRUNED_LANGUAGES}"
fi
if [[ -n ${CI_SKIP_REASON} ]]; then
  log "matrix: skip reason context '${CI_SKIP_REASON}'"
fi

declare -ag CI_STEP_ORDER=()
declare -Ag CI_STEP_STATUS=()
declare -Ag CI_STEP_RC=()
declare -Ag CI_STEP_NOTES=()
declare -Ag CI_STEP_DURATION=()
CI_LAST_STEP_LABEL=""

record_step() {
  local label=$1 status=$2 rc=${3:-0} note=${4:-}
  CI_STEP_ORDER+=("$label")
  CI_STEP_STATUS["$label"]=$status
  CI_STEP_RC["$label"]=$rc
  CI_STEP_NOTES["$label"]=$note
  CI_LAST_STEP_LABEL="$label"
}

annotate_last_step() {
  local note=${1:-}
  local label=${CI_LAST_STEP_LABEL:-}
  [[ -z $label || -z $note ]] && return 0
  if [[ -n ${CI_STEP_NOTES[$label]} ]]; then
    CI_STEP_NOTES["$label"]="${CI_STEP_NOTES[$label]}; ${note}"
  else
    CI_STEP_NOTES["$label"]="$note"
  fi
}

run_step() {
  local label="$1"
  shift || true
  local start_ns end_ns duration_ms rc
  start_ns=$(date +%s%N)
  "$@"
  rc=$?
  end_ns=$(date +%s%N)
  duration_ms=$(( (end_ns - start_ns) / 1000000 ))
  CI_STEP_DURATION["$label"]=$duration_ms
  if (( rc == 0 )); then
    record_step "$label" "success" 0 ""
    log "$label: success (${duration_ms}ms)"
  else
    record_step "$label" "failure" "$rc" ""
    log "$label: failed (${duration_ms}ms, rc=$rc)"
  fi
  return "$rc"
}

build_step_state_file() {
  : >"$CI_STEP_STATE_FILE"
  for label in "${CI_STEP_ORDER[@]}"; do
    local duration=${CI_STEP_DURATION[$label]:-0}
    printf '%s|%s|%s|%s|%s\n' "$label" "${CI_STEP_STATUS[$label]-unknown}" "${CI_STEP_RC[$label]-0}" "${CI_STEP_NOTES[$label]-}" "$duration" >>"$CI_STEP_STATE_FILE"
  done
}

generate_step_telemetry() {
  build_step_state_file
  if command -v python3 >/dev/null 2>&1; then
    CI_STEP_DURATION_JSON=$(python3 <<'PY'
import json, os
path = os.environ["CI_STEP_STATE_FILE"]
mapping = {}
if os.path.exists(path):
    for line in open(path, encoding="utf-8"):
        parts = line.rstrip("\n").split("|", 4)
        if len(parts) < 5:
            continue
        name, status, rc, note, duration = parts
        try:
            mapping[name] = int(duration)
        except ValueError:
            mapping[name] = 0
print(json.dumps(mapping))
PY
    )
    export CI_STEP_DURATION_JSON
    CI_TELEMETRY_PATH="$CI_ROOT/telemetry.json"
    python3 <<'PY' >"$CI_TELEMETRY_PATH"
import json, os, sys
path = os.environ["CI_STEP_STATE_FILE"]
steps = []
if os.path.exists(path):
    for line in open(path, encoding="utf-8"):
        parts = line.rstrip("\n").split("|", 4)
        if len(parts) < 5:
            continue
        name, status, rc, note, duration = parts
        step = {
            "name": name,
            "status": status,
            "rc": int(rc),
            "duration_ms": int(duration),
            "note": note or ""
        }
        steps.append(step)
json.dump({"steps": steps}, sys.stdout, indent=2)
PY
    export CI_TELEMETRY_PATH
    local telemetry_dir="$CI_ROOT/telemetry"
    mkdir -p "$telemetry_dir"
    local telemetry_label="${CODEX_CI_MATRIX_LABEL:-default}"
    cp "$CI_TELEMETRY_PATH" "$telemetry_dir/run-${telemetry_label}.json" 2>/dev/null || true
  fi
}

emit_report() {
  local exit_status=$?
  trap - EXIT
  set +e
  set +u
  set +o pipefail

  mkdir -p "$CI_ROOT"
  build_step_state_file
  local steps_file="$CI_STEP_STATE_FILE"

  local script_end_ns
  script_end_ns=$(date +%s%N)
  local script_duration_ms=$(( (script_end_ns - CI_SCRIPT_START_NS) / 1000000 ))
  export CI_DURATION_MS=$script_duration_ms

  local timestamp
  timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  export CI_TIMESTAMP="$timestamp"
  export CI_STEPS_FILE="$steps_file"
  export CI_REPORT_JSON="$CI_ROOT/report.json"
  export CI_REPORT_MD="$CI_ROOT/report.md"
  export CI_PROFILE_PATH
  export CI_EXIT_STATUS="$exit_status"
  export CI_LANGUAGES="${CI_LANGUAGES:-${CODEX_CI_LANGUAGES:-}}"
  export CI_HAS_PYTHON
  export CI_HAS_NODE
  export CI_HAS_GO
  export CI_HAS_RUST
  export CI_HAS_TERRAFORM
  export CI_HAS_DOCKER

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

steps_file = pathlib.Path(os.environ["CI_STEPS_FILE"])
steps: list[dict] = []
if steps_file.exists():
    for line in steps_file.read_text(encoding="utf-8").splitlines():
        parts = line.split("|", 4)
        if len(parts) < 4:
            continue
        if len(parts) == 4:
            name, status, rc, note = parts
            duration_ms = 0
        else:
            name, status, rc, note, duration = parts
            try:
                duration_ms = int(duration)
            except ValueError:
                duration_ms = 0
        step = {"name": name, "status": status, "rc": int(rc), "duration_ms": duration_ms, "duration_seconds": duration_ms / 1000}
        if note:
            step["note"] = note
        steps.append(step)

profile_path = pathlib.Path(os.environ.get("CI_PROFILE_PATH", ""))
profile = {}
if profile_path.is_file():
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except Exception:
        profile = {}
if not profile:
    profile = {
        "has_python": os.environ.get("CI_HAS_PYTHON", "0") == "1",
        "has_node": os.environ.get("CI_HAS_NODE", "0") == "1",
        "has_go": os.environ.get("CI_HAS_GO", "0") == "1",
        "has_rust": os.environ.get("CI_HAS_RUST", "0") == "1",
        "has_terraform": os.environ.get("CI_HAS_TERRAFORM", "0") == "1",
        "has_docker": os.environ.get("CI_HAS_DOCKER", "0") == "1",
    }

languages_env = os.environ.get("CI_LANGUAGES", "")
if languages_env:
    profile["languages"] = [lang for lang in languages_env.split(",") if lang]
else:
    profile["languages"] = [
        name.replace("has_", "")
        for name, flag in profile.items()
        if name.startswith("has_") and isinstance(flag, bool) and flag
    ]

overall = "success"
for step in steps:
    if step["status"] not in ("success", "skipped"):
        overall = "failed"
        break

report = {
    "timestamp": os.environ["CI_TIMESTAMP"],
    "exit_status": int(os.environ["CI_EXIT_STATUS"]),
    "overall_status": overall,
    "steps": steps,
    "profile": profile,
    "duration_ms": int(os.environ.get("CI_DURATION_MS", "0")),
    "force_ci": os.environ.get("CI_FORCE_CI", "false") == "true",
    "skip_reason": os.environ.get("CI_SKIP_REASON", ""),
    "pruned_languages": json.loads(os.environ.get("CI_PRUNED_LANGUAGES", "[]")),
    "changed_files": json.loads(os.environ.get("CI_CHANGED_FILES_JSON", "[]")),
}
report["matrix"] = {
    "label": os.environ.get("CODEX_CI_MATRIX_LABEL", ""),
    "python": os.environ.get("CODEX_CI_PYTHON_VERSION", ""),
    "node": os.environ.get("CODEX_CI_NODE_VERSION", ""),
}
report_path = pathlib.Path(os.environ["CI_REPORT_JSON"])
report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

md_lines = [
    "# Codex CI Summary",
    "",
    f"*Status:* **{overall.upper()}** (exit {report['exit_status']})",
]
if profile.get("languages"):
    md_lines.append("")
    md_lines.append(f"*Languages:* {', '.join(profile['languages'])}")
md_lines.extend([
    "",
    "| Step | Status | RC | Duration (s) | Note |",
    "| --- | --- | --- | --- | --- |",
])
for step in steps:
    note = step.get("note", "")
    note = note.replace("|", "\\|")
    md_lines.append(f"| {step['name']} | {step['status']} | {step['rc']} | {step['duration_seconds']:.3f} | {note} |")
md_lines.append("")
md_path = pathlib.Path(os.environ["CI_REPORT_MD"])
md_path.write_text("\n".join(md_lines), encoding="utf-8")
PY
    local py_status=$?
    if [[ $py_status -ne 0 ]]; then
      log "report: failed to build structured summary"
    fi
  else
    log "report: python interpreter not available; skipping structured report"
  fi

  rm -f "$steps_file"

  if [[ $exit_status -eq 0 ]]; then
    log "ci harness complete (${script_duration_ms}ms)"
  else
    log "ci harness failed (${script_duration_ms}ms, rc=$exit_status)"
  fi

  exit "$exit_status"
}

detect_profile_bool() {
  local key=$1
  if [[ -n $CI_PROFILE_PATH && -f $CI_PROFILE_PATH ]]; then
    if command -v jq >/dev/null 2>&1; then
      if jq -e --arg key "$key" '.[$key] == true' "$CI_PROFILE_PATH" >/dev/null 2>&1; then
        return 0
      fi
      if jq -e --arg key "$key" '.[$key] == false' "$CI_PROFILE_PATH" >/dev/null 2>&1; then
        return 1
      fi
    fi
  fi
  return 2
}

resolve_lang_flag() {
  local env_value=$1 profile_key=$2 default_detect=$3
  if [[ -n ${env_value:-} ]]; then
    if truthy "$env_value"; then
      printf '%s' "1"
    else
      printf '%s' "0"
    fi
    return 0
  fi
  detect_profile_bool "$profile_key"
  case $? in
    0) printf '%s' "1"; return 0 ;;
    1) printf '%s' "0"; return 0 ;;
  esac
  if eval "$default_detect"; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

has_package_script() {
  local script=$1
  [[ -f package.json ]] || return 1
  if command -v jq >/dev/null 2>&1; then
    jq -e --arg name "$script" '.scripts[$name]' package.json >/dev/null 2>&1
  elif command -v node >/dev/null 2>&1; then
    node -e "const fs=require('fs');const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));process.exit(pkg.scripts && pkg.scripts['$script'] ? 0 : 1);" >/dev/null 2>&1
  else
    return 1
  fi
}

mkdir -p "$CI_ROOT"

CI_HAS_PYTHON="0"
CI_HAS_NODE="0"
CI_HAS_GO="0"
CI_HAS_RUST="0"
CI_HAS_TERRAFORM="0"
CI_HAS_DOCKER="0"

trap 'emit_report' EXIT

has_python=$(resolve_lang_flag "${CODEX_CI_HAS_PYTHON-}" "has_python" '[[ -f pyproject.toml || -f requirements.txt || -f Pipfile || -f setup.cfg ]]')
has_node=$(resolve_lang_flag "${CODEX_CI_HAS_NODE-}" "has_node" '[[ -f package.json ]]')
has_go=$(resolve_lang_flag "${CODEX_CI_HAS_GO-}" "has_go" '[[ -f go.mod ]]')
has_rust=$(resolve_lang_flag "${CODEX_CI_HAS_RUST-}" "has_rust" '[[ -f Cargo.toml ]]')
has_terraform=$(resolve_lang_flag "${CODEX_CI_HAS_TERRAFORM-}" "has_terraform" 'find . -name "*.tf" -print -quit | grep -q .')
has_docker=$(resolve_lang_flag "${CODEX_CI_HAS_DOCKER-}" "has_docker" '[[ -f Dockerfile || -f docker-compose.yml || -f compose.yml ]]')

python_skip_reason=""
node_skip_reason=""
go_skip_reason=""
rust_skip_reason=""
terraform_skip_reason=""
docker_skip_reason=""

if [[ $has_python == "1" && ${CI_CFG_PYTHON_ENABLE:-1} != "1" ]]; then
  python_skip_reason="disabled via config"
  has_python="0"
fi
if [[ $has_node == "1" && ${CI_CFG_NODE_ENABLE:-1} != "1" ]]; then
  node_skip_reason="disabled via config"
  has_node="0"
fi
if [[ $has_go == "1" && ${CI_CFG_GO_ENABLE:-1} != "1" ]]; then
  go_skip_reason="disabled via config"
  has_go="0"
fi
if [[ $has_rust == "1" && ${CI_CFG_RUST_ENABLE:-1} != "1" ]]; then
  rust_skip_reason="disabled via config"
  has_rust="0"
fi
if [[ $has_terraform == "1" && ${CI_CFG_TERRAFORM_ENABLE:-1} != "1" ]]; then
  terraform_skip_reason="disabled via config"
  has_terraform="0"
fi
if [[ $has_docker == "1" && ${CI_CFG_DOCKER_LINT:-1} != "1" ]]; then
  docker_skip_reason="disabled via config"
  has_docker="0"
fi

CI_HAS_PYTHON="$has_python"
CI_HAS_NODE="$has_node"
CI_HAS_GO="$has_go"
CI_HAS_RUST="$has_rust"
CI_HAS_TERRAFORM="$has_terraform"
CI_HAS_DOCKER="$has_docker"
export CI_HAS_PYTHON CI_HAS_NODE CI_HAS_GO CI_HAS_RUST CI_HAS_TERRAFORM CI_HAS_DOCKER

languages=()
[[ $has_python == "1" ]] && languages+=("python")
[[ $has_node == "1" ]] && languages+=("node")
[[ $has_go == "1" ]] && languages+=("go")
[[ $has_rust == "1" ]] && languages+=("rust")
CI_LANGUAGES=${CI_LANGUAGES:-${CODEX_CI_LANGUAGES:-$(IFS=,; echo "${languages[*]}")}}
export CI_LANGUAGES

if [[ -n ${CODEX_CI_MATRIX_LABEL:-} ]]; then
  log "matrix: ${CODEX_CI_MATRIX_LABEL}"
fi
if [[ -n ${CODEX_CI_PYTHON_VERSION:-} ]]; then
  log "python version hint: ${CODEX_CI_PYTHON_VERSION}"
fi
if [[ -n ${CODEX_CI_NODE_VERSION:-} ]]; then
  log "node version hint: ${CODEX_CI_NODE_VERSION}"
fi

if [[ -n ${CI_CFG_REQUIRED_SECRETS:-} ]]; then
  missing=()
  for raw in ${CI_CFG_REQUIRED_SECRETS//,/ }; do
    name=${raw//[[:space:]]/}
    [[ -z $name ]] && continue
    if [[ -z ${!name:-} ]]; then
      missing+=("$name")
    fi
  done
  if ((${#missing[@]})); then
    record_step "gate:secrets" "failure" 1 "missing: ${missing[*]}"
    log "secrets: missing ${missing[*]}"
    exit 1
  else
    record_step "gate:secrets" "success" 0 "all required secrets present"
  fi
else
  record_step "gate:secrets" "skipped" 0 "no required secrets configured"
fi

python_manager="${CODEX_CI_PYTHON_MANAGER:-}"
node_pm="${CODEX_CI_NODE_PM:-}"

if [[ $has_python == "1" && -z $python_manager ]]; then
  if [[ -f uv.lock || -f uv.toml ]]; then
    python_manager=uv
  elif [[ -f poetry.lock ]]; then
    python_manager=poetry
  elif [[ -f Pipfile ]]; then
    python_manager=pipenv
  else
    python_manager=pip
  fi
fi

if [[ $has_node == "1" && -z $node_pm ]]; then
  if [[ -f pnpm-lock.yaml ]]; then
    node_pm=pnpm
  elif [[ -f yarn.lock ]]; then
    node_pm=yarn
  elif [[ -f package-lock.json || -f npm-shrinkwrap.json ]]; then
    node_pm=npm
  else
    node_pm=npm
  fi
fi

python_tests_present=0
python_tests_skip_reason="no tests detected"
if [[ $has_python == "1" ]]; then
  if ls tests/*.py >/dev/null 2>&1 || ls test/*.py >/dev/null 2>&1 || [[ -f pytest.ini ]]; then
    python_tests_present=1
    python_tests_skip_reason=""
  fi
  if [[ ${CI_CFG_PYTHON_TESTS:-1} != "1" ]]; then
    python_tests_skip_reason="disabled via config"
    python_tests_present=0
  elif (( python_tests_present == 0 )); then
    python_tests_skip_reason="no tests detected"
  fi
else
  python_tests_skip_reason=${python_skip_reason:-"python disabled"}
fi

if [[ $has_python == "1" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    log "python: python3 not available; skipping Python automation"
    record_step "python:environment" "skipped" 0 "python3 binary missing"
    record_step "python:tests" "skipped" 0 "python3 binary missing"
  else
    case "${python_manager:-}" in
      uv)
        if command -v uv >/dev/null 2>&1; then
          run_step "python:uv sync (frozen)" uv sync --frozen || run_step "python:uv sync" uv sync
          if (( python_tests_present )); then
            run_step "python:uv pytest" uv run pytest || annotate_last_step "pytest failed via uv"
          else
            reason=${python_tests_skip_reason:-"no tests detected"}
            log "python: pytest skipped (${reason})"
            record_step "python:pytest" "skipped" 0 "$reason"
          fi
        else
          log "python: uv requested but not available; falling back to pip"
          python_manager="pip"
        fi
        ;;
      poetry)
        if command -v poetry >/dev/null 2>&1; then
          run_step "python:poetry install" poetry install --no-interaction || run_step "python:poetry install (fallback)" poetry install
          if (( python_tests_present )); then
            run_step "python:poetry pytest" poetry run pytest || annotate_last_step "pytest failed via poetry"
          else
            reason=${python_tests_skip_reason:-"no tests detected"}
            log "python: pytest skipped (${reason})"
            record_step "python:pytest" "skipped" 0 "$reason"
          fi
        else
          log "python: poetry not available; falling back to pip"
          python_manager="pip"
        fi
        ;;
      pipenv)
        if command -v pipenv >/dev/null 2>&1; then
          run_step "python:pipenv install" pipenv install --dev || run_step "python:pipenv install (fallback)" pipenv install
          if (( python_tests_present )); then
            run_step "python:pipenv pytest" pipenv run pytest || annotate_last_step "pytest failed via pipenv"
          else
            reason=${python_tests_skip_reason:-"no tests detected"}
            log "python: pytest skipped (${reason})"
            record_step "python:pytest" "skipped" 0 "$reason"
          fi
        else
          log "python: pipenv not available; falling back to pip"
          python_manager="pip"
        fi
        ;;
    esac

    if [[ ${python_manager:-pip} == "pip" ]]; then
      if run_step "python:venv" python3 -m venv .codex-ci-venv; then
        # shellcheck disable=SC1091
        . .codex-ci-venv/bin/activate
        run_step "python:pip upgrade" pip install --upgrade pip setuptools wheel >/dev/null 2>&1 || annotate_last_step "pip upgrade failed"
        if [[ -f requirements.txt ]]; then
          run_step "python:pip requirements" pip install -r requirements.txt >/dev/null
        elif [[ -f pyproject.toml ]]; then
          run_step "python:pip pyproject" pip install -e . >/dev/null 2>&1 || annotate_last_step "pip editable install failed"
        else
          record_step "python:dependencies" "skipped" 0 "no dependency file found"
        fi
        if (( python_tests_present )); then
          run_step "python:pytest" pytest || annotate_last_step "pytest failed"
        else
          reason=${python_tests_skip_reason:-"no tests detected"}
          record_step "python:pytest" "skipped" 0 "$reason"
        fi
        deactivate 2>/dev/null || true
      else
        log "python: failed to create virtualenv; skipping pip workflow"
        annotate_last_step "virtualenv creation failed"
      fi
    fi
  fi
else
  reason=${python_skip_reason:-"no Python project files"}
  log "python: skipping (${reason})"
  record_step "python:environment" "skipped" 0 "$reason"
  record_step "python:tests" "skipped" 0 "$reason"
fi

if [[ $has_node == "1" ]]; then
  if ! command -v node >/dev/null 2>&1; then
    log "node: node binary not available; skipping"
    record_step "node:install" "skipped" 0 "node binary missing"
    record_step "node:lint" "skipped" 0 "node binary missing"
    record_step "node:test" "skipped" 0 "node binary missing"
  else
    pm=${node_pm:-npm}
    log "node: using package manager '$pm'"
    case $pm in
      pnpm)
        if command -v corepack >/dev/null 2>&1; then
          corepack enable pnpm >/dev/null 2>&1 || true
        fi
        if ! command -v pnpm >/dev/null 2>&1; then
          log "node: pnpm unavailable; falling back to npm"
          pm=npm
        fi
        ;;
      yarn)
        if command -v corepack >/dev/null 2>&1; then
          corepack enable yarn >/dev/null 2>&1 || true
        fi
        if ! command -v yarn >/dev/null 2>&1; then
          log "node: yarn unavailable; falling back to npm"
          pm=npm
        fi
        ;;
    esac

    case $pm in
      pnpm)
        if ! run_step "node:pnpm install (frozen)" pnpm install --frozen-lockfile; then
          run_step "node:pnpm install" pnpm install
        fi
        if [[ ${CI_CFG_NODE_LINT:-1} != "1" ]]; then
          record_step "node:pnpm lint" "skipped" 0 "disabled via config"
        else
          if has_package_script lint; then
            run_step "node:pnpm lint" pnpm run --if-present lint || annotate_last_step "lint script failed"
          else
            log "node: pnpm lint skipped (script missing)"
            record_step "node:pnpm lint" "skipped" 0 "script missing"
          fi
        fi
        if [[ ${CI_CFG_NODE_TESTS:-1} != "1" ]]; then
          record_step "node:pnpm test" "skipped" 0 "disabled via config"
        else
          if has_package_script test; then
            run_step "node:pnpm test" pnpm run --if-present test || annotate_last_step "test script failed"
          else
            log "node: pnpm test skipped (script missing)"
            record_step "node:pnpm test" "skipped" 0 "script missing"
          fi
        fi
        ;;
      yarn)
        if ! run_step "node:yarn install (frozen)" yarn install --frozen-lockfile; then
          if ! run_step "node:yarn install (immutable)" yarn install --immutable --immutable-cache; then
            run_step "node:yarn install" yarn install
          fi
        fi
        if [[ ${CI_CFG_NODE_LINT:-1} != "1" ]]; then
          record_step "node:yarn lint" "skipped" 0 "disabled via config"
        else
          if has_package_script lint; then
            run_step "node:yarn lint" yarn run lint || annotate_last_step "lint script failed"
          else
            log "node: yarn lint skipped (script missing)"
            record_step "node:yarn lint" "skipped" 0 "script missing"
          fi
        fi
        if [[ ${CI_CFG_NODE_TESTS:-1} != "1" ]]; then
          record_step "node:yarn test" "skipped" 0 "disabled via config"
        else
          if has_package_script test; then
            run_step "node:yarn test" yarn test || annotate_last_step "test script failed"
          else
            log "node: yarn test skipped (script missing)"
            record_step "node:yarn test" "skipped" 0 "script missing"
          fi
        fi
        ;;
      npm|*)
        if ! run_step "node:npm ci" npm ci; then
          run_step "node:npm install" npm install
        fi
        if [[ ${CI_CFG_NODE_LINT:-1} != "1" ]]; then
          record_step "node:npm lint" "skipped" 0 "disabled via config"
        else
          if has_package_script lint; then
            run_step "node:npm lint" npm run lint --if-present || annotate_last_step "lint script failed"
          else
            log "node: npm lint skipped (script missing)"
            record_step "node:npm lint" "skipped" 0 "script missing"
          fi
        fi
        if [[ ${CI_CFG_NODE_TESTS:-1} != "1" ]]; then
          record_step "node:npm test" "skipped" 0 "disabled via config"
        else
          if has_package_script test; then
            run_step "node:npm test" npm test || annotate_last_step "test script failed"
          else
            log "node: npm test skipped (script missing)"
            record_step "node:npm test" "skipped" 0 "script missing"
          fi
        fi
        ;;
    esac
  fi
else
  reason=${node_skip_reason:-"package.json missing"}
  log "node: skipping (${reason})"
  record_step "node:install" "skipped" 0 "$reason"
  record_step "node:lint" "skipped" 0 "$reason"
  record_step "node:test" "skipped" 0 "$reason"
fi

if [[ $has_go == "1" ]]; then
  if command -v go >/dev/null 2>&1; then
    run_step "go:vet" go vet ./... || annotate_last_step "go vet failed"
    run_step "go:test" go test ./... || annotate_last_step "go test failed"
  else
    log "go: go binary not available; skipping"
    record_step "go:vet" "skipped" 0 "go binary missing"
    record_step "go:test" "skipped" 0 "go binary missing"
  fi
else
  reason=${go_skip_reason:-"go.mod missing"}
  record_step "go:vet" "skipped" 0 "$reason"
  record_step "go:test" "skipped" 0 "$reason"
fi

if [[ $has_rust == "1" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    run_step "rust:fmt" cargo fmt -- --check || annotate_last_step "cargo fmt failed"
    run_step "rust:clippy" cargo clippy --all-targets --all-features -- -D warnings || annotate_last_step "cargo clippy failed"
    run_step "rust:test" cargo test || annotate_last_step "cargo test failed"
  else
    log "rust: cargo binary not available; skipping"
    record_step "rust:fmt" "skipped" 0 "cargo binary missing"
    record_step "rust:clippy" "skipped" 0 "cargo binary missing"
    record_step "rust:test" "skipped" 0 "cargo binary missing"
  fi
else
  reason=${rust_skip_reason:-"Cargo.toml missing"}
  record_step "rust:fmt" "skipped" 0 "$reason"
  record_step "rust:clippy" "skipped" 0 "$reason"
  record_step "rust:test" "skipped" 0 "$reason"
fi

if [[ $has_terraform == "1" ]]; then
  if command -v terraform >/dev/null 2>&1; then
    run_step "terraform:fmt" terraform fmt -check -recursive || annotate_last_step "terraform fmt failed"
    if run_step "terraform:init" terraform init -backend=false -input=false -no-color; then
      run_step "terraform:validate" terraform validate -no-color || annotate_last_step "terraform validate failed"
    else
      record_step "terraform:validate" "skipped" 0 "terraform init failed"
      log "terraform: init failed; skipping validate"
    fi
  else
    log "terraform: terraform binary not available; skipping"
    record_step "terraform:fmt" "skipped" 0 "terraform binary missing"
    record_step "terraform:validate" "skipped" 0 "terraform binary missing"
  fi
else
  reason=${terraform_skip_reason:-"no Terraform configuration detected"}
  record_step "terraform:fmt" "skipped" 0 "$reason"
  record_step "terraform:validate" "skipped" 0 "$reason"
fi

if [[ $has_docker == "1" ]]; then
  if command -v hadolint >/dev/null 2>&1 && [[ -f Dockerfile ]]; then
    run_step "docker:hadolint" hadolint Dockerfile || annotate_last_step "hadolint failed"
  else
    record_step "docker:hadolint" "skipped" 0 "hadolint missing or Dockerfile absent"
  fi
else
  reason=${docker_skip_reason:-"Dockerfile not detected"}
  record_step "docker:hadolint" "skipped" 0 "$reason"
fi

generate_step_telemetry

if [[ ${CI_CFG_HOOKS_CI:-1} != "1" ]]; then
  record_step "hooks:ci" "skipped" 0 "disabled via config"
elif ! compgen -G "$CI_ROOT/ci.d/*.sh" >/dev/null 2>&1; then
  record_step "hooks:ci" "skipped" 0 "no CI hooks present"
else
  hook_count=0
  for hook in "$CI_ROOT"/ci.d/*.sh; do
    [[ -f $hook ]] || continue
    hook_count=$((hook_count + 1))
    base=$(basename "$hook")
    if [[ -x $hook ]]; then
      run_step "hook:${base}" "$hook"
    else
      run_step "hook:${base}" bash "$hook"
    fi
  done
  record_step "hooks:ci" "success" 0 "${hook_count} hook(s) executed"
  log "hooks: executed ${hook_count} CI hook(s)"
fi

generate_step_telemetry
