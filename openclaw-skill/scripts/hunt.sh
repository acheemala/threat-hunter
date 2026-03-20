#!/usr/bin/env bash
# ============================================================
# ThreatHunter OpenClaw skill — hunt.sh
#
# Wrapper script for the OpenClaw agent to invoke ThreatHunter.
# Auto-selects the best available AI provider based on env vars.
#
# Usage (called by OpenClaw agent):
#   ./hunt.sh [target] [provider] [depth] [save_path]
#
# Arguments (all optional, positional):
#   $1  target path   (default: /)
#   $2  provider      (default: auto-detect)
#   $3  depth         quick|normal|deep (default: normal)
#   $4  save path     (default: none)
# ============================================================

set -euo pipefail

TARGET="${1:-/}"
PROVIDER="${2:-auto}"
DEPTH="${3:-normal}"
SAVE_PATH="${4:-}"

# ── Provider auto-detection ───────────────────────────────────────────────────
if [ "$PROVIDER" = "auto" ]; then
    if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        PROVIDER="claude"
    elif [ -n "${OPENAI_API_KEY:-}" ]; then
        PROVIDER="openai"
    elif [ -n "${GROQ_API_KEY:-}" ]; then
        PROVIDER="groq"
    else
        PROVIDER="ollama"
        echo "[INFO] No cloud API key found — using Ollama (local). Run: ollama pull llama3.2"
    fi
fi

# ── Depth → max iterations ────────────────────────────────────────────────────
case "$DEPTH" in
    quick)  MAX_ITER=5  ;;
    deep)   MAX_ITER=20 ;;
    *)      MAX_ITER=10 ;;
esac

# ── Check threathunter is installed ──────────────────────────────────────────
if ! command -v threathunter &>/dev/null; then
    echo "ERROR: threathunter not found in PATH."
    echo "Build it with: cargo build --release"
    echo "Then: export PATH=\$PATH:/path/to/target/release"
    exit 1
fi

# ── Build command ─────────────────────────────────────────────────────────────
CMD=(threathunter agent
    --target "$TARGET"
    --provider "$PROVIDER"
    --max-iterations "$MAX_ITER"
    --quiet  # suppress banner for cleaner chat output
)

if [ -n "$SAVE_PATH" ]; then
    CMD+=(--save "$SAVE_PATH")
fi

# ── Run ───────────────────────────────────────────────────────────────────────
echo "▶ Starting ThreatHunter"
echo "  Target:   $TARGET"
echo "  Provider: $PROVIDER"
echo "  Depth:    $DEPTH ($MAX_ITER iterations)"
[ -n "$SAVE_PATH" ] && echo "  Save:     $SAVE_PATH"
echo ""

exec "${CMD[@]}"
