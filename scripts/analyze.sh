#!/usr/bin/env bash
# reaper — malware static + dynamic analysis pipeline
# Usage: ./scripts/analyze.sh <target.js> [options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$PROJECT_DIR/docker"
IMAGE_NAME="reaper-sandbox"
IMAGE_TAG="latest"

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
STATIC=true
DYNAMIC=true
TIMEOUT=20
OUTPUT_DIR=""
OBSERVE_NETWORK=false
BLOCK_EVAL=false
BLOCK_FS=false

usage() {
  cat <<EOF
Usage: $0 <target.js> [options]

Options:
  --static-only        Only run static analysis (no Docker)
  --dynamic-only       Only run dynamic sandbox execution
  --timeout <sec>      Container wall-clock timeout (default: 20)
  --output-dir <dir>   Write static JSON report to this directory

Sandbox runtime modes (dynamic only):
  --observe-network    Real egress stays blocked (docker --network none),
                       but a stub fetch/http/https responder is installed
                       inside the container so the target script proceeds
                       past network calls. Lets you see what URLs / methods /
                       bodies it would have used to fetch second-stage code.
  --block-eval         eval() and Function() throw after logging — observe
                       what code the script tries to execute without
                       actually running it.
  --block-fs           File-system writes throw after logging.

  -h, --help           Show this help

Examples:
  $0 suspicious.js
  $0 malware.js --timeout 30 --output-dir ./reports
  $0 packed.js --static-only
  $0 etherhiding.js --observe-network --block-eval --timeout 30
EOF
  exit 1
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --static-only)      DYNAMIC=false;        shift ;;
    --dynamic-only)     STATIC=false;         shift ;;
    --timeout)          TIMEOUT="$2";         shift 2 ;;
    --output-dir)       OUTPUT_DIR="$2";      shift 2 ;;
    --observe-network)  OBSERVE_NETWORK=true; shift ;;
    --block-eval)       BLOCK_EVAL=true;      shift ;;
    --block-fs)         BLOCK_FS=true;        shift ;;
    -h|--help)          usage ;;
    -*)                 echo "Unknown option: $1"; usage ;;
    *)                  TARGET="$1";          shift ;;
  esac
done

[[ -z "$TARGET" ]] && { echo "Error: no target file specified."; usage; }
[[ ! -f "$TARGET" ]] && { echo "Error: file not found: $TARGET"; exit 1; }

TARGET_ABS="$(realpath "$TARGET")"
TARGET_EXT="${TARGET_ABS##*.}"
TARGET_BASENAME="$(basename "$TARGET_ABS")"

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo "  ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ "
echo "  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗"
echo "  ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝"
echo "  ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗"
echo "  ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║"
echo "  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝"
echo ""
echo "  target : $TARGET_ABS"
echo "  date   : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

# ── Static Analysis ───────────────────────────────────────────────────────────
if $STATIC; then
  echo "━━━ STATIC ANALYSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  STATIC_ARGS=("$TARGET_ABS")

  if [[ -n "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
    REPORT_FILE="$OUTPUT_DIR/${TARGET_BASENAME%.js}.reaper.json"
    STATIC_ARGS+=("--output" "$REPORT_FILE")
    echo "  report → $REPORT_FILE"
  fi

  cd "$PROJECT_DIR"
  npx tsx src/cli.ts "${STATIC_ARGS[@]}" || true
fi

# ── Dynamic Sandbox ───────────────────────────────────────────────────────────
if $DYNAMIC; then
  echo "━━━ DYNAMIC SANDBOX ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if [[ "$TARGET_EXT" == "ts" || "$TARGET_EXT" == "tsx" ]]; then
    echo ""
    echo "  [SKIP] TypeScript source cannot be executed directly."
    echo "         Compile first:  npx tsc --outDir /tmp/compiled $TARGET_ABS"
    echo "         Then re-run:    $0 /tmp/compiled/${TARGET_BASENAME%.ts}.js --dynamic-only"
    echo ""
  else
    # Verify Docker is available
    if ! command -v docker &>/dev/null; then
      echo "  [ERROR] Docker not found. Install Docker to run dynamic analysis."
      exit 1
    fi

    # Build sandbox image if missing or Dockerfile changed
    echo "  Building sandbox image ($IMAGE_NAME:$IMAGE_TAG)..."
    docker build -q -t "$IMAGE_NAME:$IMAGE_TAG" "$DOCKER_DIR"
    echo "  Sandbox ready."
    echo ""
    echo "  Constraints:"
    echo "    network : none (no egress)"
    echo "    memory  : 256 MB"
    echo "    cpus    : 0.5"
    echo "    timeout : ${TIMEOUT}s"
    echo "    user    : sandbox (uid 1001, non-root)"
    echo "    caps    : all dropped"
    echo ""
    echo "  Executing..."
    echo ""

    SANDBOX_TIMEOUT_MS=$(( (TIMEOUT - 2) * 1000 ))

    # Run with hardened flags:
    #   --network none          no network egress
    #   --memory / --cpus       resource caps
    #   --read-only             immutable container FS
    #   --tmpfs /tmp            writable scratch in RAM only (noexec)
    #   --cap-drop ALL          remove all Linux capabilities
    #   --security-opt          prevent privilege escalation
    #   -v target:ro            target file read-only bind mount
    # Build runtime mode env-var args
    RUNTIME_ENV=()
    if $OBSERVE_NETWORK; then RUNTIME_ENV+=(-e REAPER_OBSERVE_NETWORK=1); echo "    mode    : observe-network (stub responders, real egress still blocked)"; fi
    if $BLOCK_EVAL;      then RUNTIME_ENV+=(-e REAPER_BLOCK_EVAL=1);      echo "    mode    : block-eval (eval/Function throw after logging)"; fi
    if $BLOCK_FS;        then RUNTIME_ENV+=(-e REAPER_BLOCK_FS=1);        echo "    mode    : block-fs (writes throw after logging)"; fi
    echo ""

    timeout "$TIMEOUT" docker run \
      --rm \
      --network none \
      --memory 256m \
      --memory-swap 256m \
      --cpus 0.5 \
      --read-only \
      --tmpfs /tmp:rw,noexec,nosuid,size=16m \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --user 1001:1001 \
      -e "SANDBOX_TIMEOUT=${SANDBOX_TIMEOUT_MS}" \
      "${RUNTIME_ENV[@]}" \
      -v "${TARGET_ABS}:/sandbox/target.js:ro" \
      "$IMAGE_NAME:$IMAGE_TAG" \
      /sandbox/target.js 2>&1 || {
        EXIT=$?
        echo ""
        if [[ $EXIT -eq 124 ]]; then
          echo "  [TIMEOUT] Container killed after ${TIMEOUT}s."
        else
          echo "  [EXIT] Container exited with code $EXIT"
        fi
      }

    echo ""
    echo "  [DONE] Dynamic analysis complete."
  fi
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
