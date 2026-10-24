#!/usr/bin/env python3
"""
Lightweight Multithreaded Operations Backend Server for the Adaptive Deception Mesh.

Uses Python standard library http.server only (zero external pip packages required).
Binds strictly to localhost (127.0.0.1) to uphold VM and demonstration security.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import mimetypes
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
OUTPUT_PATH = PROJECT_ROOT / "output" / "cowrie_integration_demo.json"
DOCS_PATH = PROJECT_ROOT / "docs" / "PROJECT_TECHNICAL_GUIDE.md"
MODULE3_MODEL_DIR = PROJECT_ROOT / "module3_ai_xai_engine" / "experiments" / "two_output_model_v1"
DEFAULT_COWRIE_LOG_DIR = Path.home() / "cowrie" / "var" / "log" / "cowrie"
SAMPLE_COWRIE_LOG_DIR = PROJECT_ROOT / "data" / "sample_cowrie_logs"
DEMO_SCRIPT = PROJECT_ROOT / "scripts" / "cowrie_to_module4_demo.py"


def resolve_cowrie_log_dir() -> Path:
    """Resolve Cowrie log directory with portable fallback for teammate environments."""
    env_dir = os.environ.get("COWRIE_LOG_DIR")
    if env_dir:
        p = Path(env_dir).expanduser().resolve()
        if p.is_dir():
            return p
    if DEFAULT_COWRIE_LOG_DIR.is_dir() and any(DEFAULT_COWRIE_LOG_DIR.glob("cowrie.json*")):
        return DEFAULT_COWRIE_LOG_DIR
    if SAMPLE_COWRIE_LOG_DIR.is_dir() and any(SAMPLE_COWRIE_LOG_DIR.glob("cowrie.json*")):
        return SAMPLE_COWRIE_LOG_DIR
    return DEFAULT_COWRIE_LOG_DIR

EXPECTED_HASHES = {
    "binary_weaponization_model.joblib": "1cb17b111b25b837b6de36bf5a4cf1075c666c8336786da31f088142de18e057",
    "multilabel_intent_model.joblib": "f0f1d092820143e0985a08fd7316843748676cb9e73ae6f642ed5a13a1459c10",
    "cowrie_adapter_scaler.joblib": "bb9e8c6893452a915379a4d34d67c375620f17f85c1418649df243d261f64157",
    "model_metadata.json": "6d255d6e07836fd01d8d35d262411d9965a188a6ee92688c2a0643fb9769ddba",
}

RUN_LOCK = threading.Lock()
LAST_RUN_METADATA = {
    "last_run_timestamp": None,
    "last_status": "initialized",
    "stdout": "",
    "stderr": "",
}


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    if not file_path.is_file():
        return ""
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def check_system_health() -> dict:
    """Verify presence and integrity of all system artifacts and data sources."""
    artifacts = {}
    all_artifacts_valid = True

    for filename, expected_hash in EXPECTED_HASHES.items():
        artifact_path = MODULE3_MODEL_DIR / filename
        exists = artifact_path.is_file()
        current_hash = compute_sha256(artifact_path) if exists else None
        valid = (current_hash == expected_hash) if exists else False
        if not valid:
            all_artifacts_valid = False

        artifacts[filename] = {
            "exists": exists,
            "expected_sha256": expected_hash,
            "actual_sha256": current_hash,
            "valid": valid,
            "path": str(artifact_path),
        }

    # Check Cowrie log directory with portable fallback
    active_cowrie_dir = resolve_cowrie_log_dir()
    cowrie_exists = active_cowrie_dir.is_dir()
    cowrie_files = (
        sorted([p.name for p in active_cowrie_dir.glob("cowrie.json*")])
        if cowrie_exists
        else []
    )

    # Check output report
    report_exists = OUTPUT_PATH.is_file()
    last_modified = (
        datetime.fromtimestamp(OUTPUT_PATH.stat().st_mtime, tz=timezone.utc).isoformat()
        if report_exists
        else None
    )

    return {
        "status": "healthy" if all_artifacts_valid else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "artifacts_intact": all_artifacts_valid,
        "artifacts": artifacts,
        "cowrie_logs": {
            "directory_exists": cowrie_exists,
            "directory_path": str(active_cowrie_dir),
            "is_sample_fallback": active_cowrie_dir == SAMPLE_COWRIE_LOG_DIR,
            "log_files_count": len(cowrie_files),
            "log_files": cowrie_files,
        },
        "latest_report": {
            "exists": report_exists,
            "path": str(OUTPUT_PATH),
            "last_modified": last_modified,
        },
        "safety_guarantees": {
            "simulation_only": True,
            "no_live_commands_executed": True,
            "no_cowrie_config_changes": True,
            "localhost_binding_only": True,
            "frozen_model_and_scaler": True,
        },
        "disclosures": [
            "Provisional target labels: Models trained on heuristic rule-derived targets.",
            "Botnet repetition overlap: High accuracy reflects learned script archetypes.",
            "Simulation only: Module 4 executes in simulation mode without mutating Cowrie.",
            "Kernel telemetry: Module 1 eBPF is standalone and not session-correlated in this demo.",
        ],
        "pipeline_state": LAST_RUN_METADATA,
    }


def execute_offline_pipeline() -> tuple[bool, str, str]:
    """Execute the offline demonstration pipeline in a thread-safe manner."""
    if not RUN_LOCK.acquire(blocking=False):
        return False, "", "Another demonstration run is already in progress."

    try:
        env = os.environ.copy()
        python_path = f"{PROJECT_ROOT}:{PROJECT_ROOT / 'module3_ai_xai_engine'}"
        if "PYTHONPATH" in env:
            env["PYTHONPATH"] = f"{python_path}:{env['PYTHONPATH']}"
        else:
            env["PYTHONPATH"] = python_path

        cmd = [sys.executable, str(DEMO_SCRIPT)]
        process = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

        success = process.returncode == 0
        LAST_RUN_METADATA["last_run_timestamp"] = datetime.now(timezone.utc).isoformat()
        LAST_RUN_METADATA["last_status"] = "success" if success else "failed"
        LAST_RUN_METADATA["stdout"] = process.stdout
        LAST_RUN_METADATA["stderr"] = process.stderr

        return success, process.stdout, process.stderr
    except Exception as exc:
        LAST_RUN_METADATA["last_run_timestamp"] = datetime.now(timezone.utc).isoformat()
        LAST_RUN_METADATA["last_status"] = "error"
        LAST_RUN_METADATA["stderr"] = str(exc)
        return False, "", str(exc)
    finally:
        RUN_LOCK.release()


def generate_csv_report(data: dict) -> str:
    """Convert session-level report data to CSV format."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "session_id",
        "source_ip",
        "command_count",
        "duration_seconds",
        "predicted_label",
        "confidence",
        "detected_intents",
        "selected_strategy",
        "threat_level",
        "simulation_status",
        "simulated_profile",
        "top_shap_features",
        "commands_summary",
    ])

    for sess in data.get("sessions", []):
        sid = sess.get("session_id", "")
        src_ips = ", ".join(sess.get("source_ips", []))
        cmd_count = sess.get("event_count", 0)
        raw_feat = sess.get("raw_features", {})
        duration = raw_feat.get("session_duration_seconds", 0.0)

        pred = sess.get("module3_prediction", {})
        classification = pred.get("classification", {})
        label = classification.get("predicted_label", "unknown")
        confidence = classification.get("confidence", 0.0)

        intent = pred.get("intent", {})
        intents = ", ".join(intent.get("detected_intents", []))

        decision = sess.get("module4_decision", {})
        strategy = decision.get("selected_strategy", "unknown")
        threat = decision.get("threat_level", "unknown")

        sim = sess.get("module4_simulation", {})
        sim_status = sim.get("status", "unknown")
        sim_profile = sim.get("simulated_profile", "unknown")

        shap_obj = pred.get("shap_explanation", {})
        top_shap = ", ".join([
            f"{item.get('feature_name', '')} ({item.get('shap_value', 0):+.2f})"
            for item in shap_obj.get("top_features", [])
        ])

        cmds = " | ".join(sess.get("commands_observed", []))

        writer.writerow([
            sid,
            src_ips,
            cmd_count,
            f"{duration:.2f}",
            label,
            f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "N/A",
            intents,
            strategy,
            threat,
            sim_status,
            sim_profile,
            top_shap,
            cmds,
        ])

    return output.getvalue()


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler for the demonstration dashboard."""

    def log_message(self, format: str, *args) -> None:
        """Override to provide clean, timestamped stdout logging."""
        sys.stdout.write(f"[{datetime.now().strftime('%H:%M:%S')}] {self.address_string()} - {format % args}\n")

    def send_json_response(self, data: dict | list, status_code: int = 200) -> None:
        """Send a JSON HTTP response."""
        payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_HEAD(self) -> None:
        """Handle HEAD requests for health and connectivity checks."""
        self.do_GET()

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle GET requests for static assets and API queries."""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # API: System health & audit status
        if path == "/api/status" or path == "/api/health":
            health_data = check_system_health()
            self.send_json_response(health_data)
            return

        # API: Demonstration session dataset
        if path == "/api/data" or path == "/api/sessions":
            if not OUTPUT_PATH.is_file():
                # Auto-run if missing
                success, _, err = execute_offline_pipeline()
                if not success:
                    self.send_json_response(
                        {"error": f"Failed to generate initial dataset: {err}"},
                        status_code=500,
                    )
                    return

            try:
                with OUTPUT_PATH.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                self.send_json_response(data)
            except Exception as exc:
                self.send_json_response(
                    {"error": f"Error reading dataset: {exc}"},
                    status_code=500,
                )
            return

        # API: Technical Documentation
        if path == "/api/documentation":
            if not DOCS_PATH.is_file():
                self.send_json_response(
                    {"error": "Documentation file not found."},
                    status_code=404,
                )
                return

            try:
                content = DOCS_PATH.read_text(encoding="utf-8")
                # Extract headers for table of contents
                headings = []
                for line in content.splitlines():
                    if line.startswith("## "):
                        headings.append(line.replace("## ", "").strip())
                self.send_json_response({
                    "title": "AI-Driven Adaptive Deception Mesh - Technical Reference Guide",
                    "file_path": str(DOCS_PATH),
                    "headings": headings,
                    "content_markdown": content,
                })
            except Exception as exc:
                self.send_json_response(
                    {"error": f"Error loading documentation: {exc}"},
                    status_code=500,
                )
            return

        # API: Export data (JSON or CSV)
        if path == "/api/export":
            export_format = query.get("format", ["json"])[0].lower()
            if not OUTPUT_PATH.is_file():
                self.send_json_response({"error": "No demo data available to export."}, status_code=404)
                return

            try:
                with OUTPUT_PATH.open("r", encoding="utf-8") as f:
                    data = json.load(f)

                if export_format == "csv":
                    csv_content = generate_csv_report(data).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/csv; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="adaptive_deception_report.csv"')
                    self.send_header("Content-Length", str(len(csv_content)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(csv_content)
                    return
                else:
                    json_bytes = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Disposition", 'attachment; filename="adaptive_deception_report.json"')
                    self.send_header("Content-Length", str(len(json_bytes)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(json_bytes)
                    return
            except Exception as exc:
                self.send_json_response({"error": f"Export failed: {exc}"}, status_code=500)
                return

        # Static file serving: fallback to index.html for root or routes
        if path == "/" or path == "/index.html":
            target_file = DASHBOARD_DIR / "index.html"
        else:
            # Strip leading slash and sanitize path
            rel_path = path.lstrip("/")
            target_file = (DASHBOARD_DIR / rel_path).resolve()
            # Security: ensure file resides inside DASHBOARD_DIR
            if not str(target_file).startswith(str(DASHBOARD_DIR.resolve())):
                self.send_json_response({"error": "Forbidden path traversal."}, status_code=403)
                return

        if target_file.is_file():
            mime_type, _ = mimetypes.guess_type(str(target_file))
            if str(target_file).endswith(".ts") or str(target_file).endswith(".tsx"):
                mime_type = "text/typescript"
            elif not mime_type:
                mime_type = "text/plain"

            try:
                content = target_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(content)
            except Exception as exc:
                self.send_json_response({"error": f"Failed to serve file: {exc}"}, status_code=500)
            return

        # If not found, serve index.html for single-page routing
        fallback_index = DASHBOARD_DIR / "index.html"
        if fallback_index.is_file():
            content = fallback_index.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(content)
        else:
            self.send_json_response({"error": "Resource not found."}, status_code=404)

    def do_POST(self) -> None:
        """Handle POST actions, particularly running the offline demo pipeline."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/run-demo":
            success, stdout, stderr = execute_offline_pipeline()
            if not success:
                self.send_json_response(
                    {
                        "success": False,
                        "error": stderr or "Pipeline execution failed.",
                        "stdout": stdout,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    status_code=500,
                )
                return

            # Return latest updated data
            try:
                with OUTPUT_PATH.open("r", encoding="utf-8") as f:
                    updated_data = json.load(f)
                self.send_json_response({
                    "success": True,
                    "message": "Demonstration pipeline executed successfully.",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "command_events_processed": updated_data.get("command_events_processed", 0),
                    "sessions_processed": updated_data.get("sessions_processed", 0),
                    "stdout": stdout,
                    "data": updated_data,
                })
            except Exception as exc:
                self.send_json_response(
                    {
                        "success": True,
                        "warning": f"Pipeline succeeded but reading output encountered error: {exc}",
                        "stdout": stdout,
                    },
                    status_code=200,
                )
            return

        self.send_json_response({"error": "Invalid POST endpoint."}, status_code=404)


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the demonstration dashboard HTTP server."""
    server_address = (host, port)
    ThreadingHTTPServer.allow_reuse_address = True
    try:
        server = ThreadingHTTPServer(server_address, DashboardRequestHandler)
    except OSError as err:
        if err.errno == 98:
            print(f"\n[!] Port {port} is already in use by another process.")
            print(f"    To terminate the occupying process, run: fuser -k {port}/tcp")
            print(f"    Or specify a different port: python dashboard/server.py --port 8001\n")
            sys.exit(1)
        raise
    print(f"\n=======================================================")
    print(f" AI-DRIVEN ADAPTIVE DECEPTION MESH — OPERATIONS DASHBOARD")
    print(f"=======================================================")
    print(f" Server active at: http://{host}:{port}/")
    print(f" Bound strictly to localhost ({host}) for security.")
    print(f" Pre-loaded pipeline status: {'Available' if OUTPUT_PATH.is_file() else 'Pending demo run'}")
    print(f" Press Ctrl+C to terminate.")
    print(f"=======================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server gracefully...")
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adaptive Honeypot Operations Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Listening port (default: 8000)")
    args = parser.parse_args()

    # Enforce localhost restriction unless user explicitly provided 127.0.0.1
    if args.host not in ("127.0.0.1", "localhost"):
        print(f"[SECURITY WARNING] Binding to non-localhost address ({args.host}) is blocked by security policy.")
        sys.exit(1)

    run_server(host=args.host, port=args.port)
