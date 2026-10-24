#!/usr/bin/env python3
"""
Python Launcher for the Adaptive Deception Mesh Operations Dashboard.
Ensures correct virtual environment, module search paths, and launches the server.
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE3_ROOT = PROJECT_ROOT / "module3_ai_xai_engine"

# Inject module roots into sys.path
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(MODULE3_ROOT))

from dashboard.server import run_server

if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_server(host="127.0.0.1", port=port)
