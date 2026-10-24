#!/usr/bin/env bash
# ==============================================================================
# AI-Driven Adaptive Deception Mesh — Operations Dashboard Launcher
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Support existing .venv-sklearn-test or standard .venv
VENV_DIR=""
if [ -d "$SCRIPT_DIR/.venv-sklearn-test" ]; then
    VENV_DIR="$SCRIPT_DIR/.venv-sklearn-test"
elif [ -d "$SCRIPT_DIR/.venv" ]; then
    VENV_DIR="$SCRIPT_DIR/.venv"
elif [ -d "$SCRIPT_DIR/venv" ]; then
    VENV_DIR="$SCRIPT_DIR/venv"
fi

if [ -n "$VENV_DIR" ]; then
    # Activate virtual environment
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
fi

# Export Python path to resolve all modules
export PYTHONPATH="$SCRIPT_DIR:$SCRIPT_DIR/module3_ai_xai_engine:${PYTHONPATH:-}"

TARGET_PORT=8000
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            TARGET_PORT="$2"
            shift 2
            ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                TARGET_PORT="$1"
            fi
            shift
            ;;
    esac
done

# Check if target port is already in use
if command -v ss >/dev/null 2>&1 && ss -tulpn 2>/dev/null | grep -q ":${TARGET_PORT} "; then
    # Check if our dashboard is already running on this port
    if command -v curl >/dev/null 2>&1 && curl -s -f "http://127.0.0.1:${TARGET_PORT}/api/status" >/dev/null 2>&1; then
        echo "=================================================================="
        echo " [i] The Deception Mesh Dashboard is ALREADY RUNNING at:"
        echo "     http://127.0.0.1:${TARGET_PORT}/"
        echo "=================================================================="
        echo " -> Open the URL in your browser to access the active dashboard."
        echo " -> To launch a separate instance, specify another port:"
        echo "      ./run_dashboard.sh --port $((TARGET_PORT + 1))"
        echo " -> To shut down the running server, locate its terminal or run:"
        echo "      fuser -k ${TARGET_PORT}/tcp"
        exit 0
    else
        echo "[!] Warning: Port ${TARGET_PORT} is currently occupied by another process."
        echo "    To avoid port conflicts, launch the dashboard on another port:"
        echo "      ./run_dashboard.sh --port $((TARGET_PORT + 1))"
        echo "    Or terminate the process using: fuser -k ${TARGET_PORT}/tcp"
        exit 1
    fi
fi

echo "=================================================================="
echo " Starting AI-Driven Adaptive Deception Mesh Operations Dashboard"
echo " Python: $(python3 --version 2>&1)"
echo " Host Binding: 127.0.0.1 (Strict Localhost Only)"
echo " Dashboard URL: http://127.0.0.1:${TARGET_PORT}/"
echo "=================================================================="

exec python3 dashboard/server.py --port "$TARGET_PORT"
