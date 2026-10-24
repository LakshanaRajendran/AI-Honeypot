# AI-Driven Adaptive Deception Mesh / Adaptive Honeypot System

[![Python 3.10-3.14](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Ubuntu Linux | Windows | WSL2](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20WSL2-teal.svg)]()
[![Deception Mode: Simulation Only](https://img.shields.io/badge/execution-simulation--only-emerald.svg)]()
[![Model Status: Frozen Artifacts](https://img.shields.io/badge/models-frozen%20(SHA--256%20verified)-purple.svg)]()

> **Autonomous cyber deception and explainable AI framework that ingests interaction telemetry, extracts canonical behavioral features, predicts weaponization and multi-label intent with SHAP local attribution, and evaluates policy-governed deception strategies in a safe, simulation-only environment.**

---

## 1. Project Title & Purpose

The **AI-Driven Adaptive Deception Mesh** is an end-to-end cybersecurity research and operations platform designed to shift the asymmetry of cyber defense. Traditional honeypots present static, predictable environments that adversaries quickly fingerprint and evade. This system replaces static traps with an **adaptive deception lifecycle**: capturing adversary keystrokes and session dynamics, transforming telemetry into a 26-dimensional canonical behavioral vector, classifying threat level and attacker intent using supervised machine learning, providing explainability via SHAP (Shapley Additive exPlanations), and evaluating rule-governed deception strategies without host system risks.

---

## 2. Problem Statement & Motivation

### The Operational Challenge
1. **Static Fingerprinting:** Conventional honeypots exhibit invariant shell outputs and static filesystem trees. Attackers employ automated discovery commands (`uname -a`, `cat /proc/cpuinfo`, `cat /etc/issue`) and quickly abort upon detecting emulation artifacts.
2. **Immediate Connection Severing:** Traditional firewalls and intrusion prevention systems terminate anomalous sessions immediately. While this halts an isolated intrusion, it destroys valuable threat intelligence regarding zero-day tools, C2 ingress URLs, and persistence scripts.
3. **Black-Box AI Risks:** Automated defense systems that rely on uninterpretable neural networks or black-box classifiers introduce critical operational risks in production networks, potentially triggering destructive counter-measures on false positives.

### The Defensive Solution
* **Prolonged Adversary Containment:** Keeps attackers safely engaged inside monitored sandboxes while studying their tooling.
* **Dual-Output Threat Intelligence:** Simultaneously classifies binary intrusion risk (`weaponized_intrusion` vs. `low_interaction_probe`) and multi-label attack intent (`reconnaissance`, `execution`, `persistence`, `defense_evasion`).
* **Transparent Local XAI:** Generates local SHAP attribution scores for every classification, empowering security analysts to verify model rationale before taking action.
* **Deterministic Policy Engine:** Enforces confidence floors (0.65 threshold) and safe observation fallbacks, ensuring machine learning predictions cannot trigger unvetted deception profiles.

---

## 3. System Architecture & Data Flow

```text
+----------------------------------------------------------------------------------------------------+
|                                    ATTACKER INTERACTION STREAM                                     |
+----------------------------------------------------------------------------------------------------+
                                                   |
                                                   v
+----------------------------------------------------------------------------------------------------+
|                              COWRIE INTERACTION SENSOR (Honeypot)                                  |
|   - Bound strictly to 127.0.0.1:2222 (Loopback Only)                                               |
|   - Logs: cowrie.command.input, cowrie.session.connect, timestamps, raw commands                    |
+----------------------------------------------------------------------------------------------------+
            |                                                     |
            | (Kernel Telemetry - Planned Future Work)            v (JSON Telemetry Stream)
            v                                         +--------------------------------------+
+--------------------------------------+              | CowrieSessionAdapter                 |
| Module 1: Kernel Collector (eBPF)    |              | - Aggregates events by Session ID    |
| - Standalone daemon in Linux VM      |              | - Parses ISO-8601 timestamps         |
| - Trace execve, sys_enter sys-calls  |              | - Reconstructs command sequences     |
+--------------------------------------+              +--------------------------------------+
                                                                  |
                                                                  v
+----------------------------------------------------------------------------------------------------+
| MODULE 2: Canonical Feature Extraction Pipeline                                                    |
|   - Ingests raw session event dictionaries                                                         |
|   - Computes 20 temporal, diversity, pattern, and syntax features                                  |
|   - Enriches 6 transparent heuristic features (MITRE tactics/techniques, risk scores)              |
|   - Output: Immutable canonical 26-feature float vector conforming to frozen scaler contract       |
+----------------------------------------------------------------------------------------------------+
                                                   |
                                                   v (26-dimensional float vector)
+----------------------------------------------------------------------------------------------------+
| MODULE 3: AI Inference & Explainability Engine (TwoOutputPredictor)                                 |
|   - Normalizes vector using frozen StandardScaler (cowrie_adapter_scaler.joblib)                   |
|   - Output A: RandomForestClassifier -> Binary threat label & confidence [0.0 - 1.0]              |
|   - Output B: MultiOutputClassifier -> Intent scores (Recon, Execution, Persistence, Evasion)      |
|   - Local XAI: TreeExplainer computes signed SHAP contribution values for each feature             |
+----------------------------------------------------------------------------------------------------+
                                                   |
                                                   v (JSON Prediction & SHAP Object)
+----------------------------------------------------------------------------------------------------+
| MODULE 4: Policy Decision Engine & Simulation Adapter                                              |
|   - Rule-based policy mapping: evaluates confidence floor (>= 0.65) and detected intents           |
|   - Safe Fallback: routes low-confidence sessions to safe_observation_fallback                     |
|   - Simulation Adapter: validates deception profiles in simulation-only mode                       |
|   - Safety Guarantee: Zero shell commands executed; zero honeypot configurations modified          |
+----------------------------------------------------------------------------------------------------+
                                                   |
                                                   v (Full Demonstration JSON Payload)
+----------------------------------------------------------------------------------------------------+
| WEB OPERATIONS DASHBOARD (React + TypeScript + Tailwind CSS + Python http.server)                  |
|   - Real-time localhost operations console on http://127.0.0.1:8000/                               |
|   - Multi-tab visualization: Overview, Live Runner, Session Explorer, XAI Attributions, Docs       |
|   - One-click pipeline execution, scenario exploration, JSON/CSV export, System Health Audit       |
+----------------------------------------------------------------------------------------------------+
```

---

## 4. Module Responsibilities & Core Files

| Component | Responsibility | Primary Implementation Files |
| :--- | :--- | :--- |
| **Module 1** | eBPF host kernel telemetry collection (Linux syscall tracing) | `~/adaptive-honeypot-integration/module1/` ([Standalone Repo](https://github.com/mohanalakshmis06/adaptive-honeypot-kernel-telemetry)) |
| **Module 2** | Raw event ingestion, session grouping, 26 canonical feature computation | `src/feature_extractor.py`, `module3_ai_xai_engine/training/cowrie_adapter.py` |
| **Module 3** | Dual-output classification (Binary threat + Multi-label intent) & SHAP attributions | `module3_ai_xai_engine/models/two_output_predictor.py`, `module3_ai_xai_engine/training/shap_explainer.py` |
| **Module 4** | Rule-based policy evaluation, confidence floor gating, simulation adapter | `module4_decision_engine/decision_engine.py`, `module4_decision_engine/execution_adapter.py` |
| **Integration** | Pipeline glue script connecting Cowrie/sample logs to Modules 2, 3, and 4 | `scripts/cowrie_to_module4_demo.py` |
| **Dashboard** | Web operations SOC interface, local REST API, report export | `dashboard/server.py`, `dashboard/index.html`, `dashboard/app.tsx` |

---

## 5. Dashboard Capabilities

The operations dashboard runs locally at `http://127.0.0.1:8000/` and provides:
1. **Executive Overview**: High-level SOC metrics, Cowrie telemetry volume, classification distributions, intent breakdown, and quick scenario selectors.
2. **One-Click Live Demo Runner**: Executes the complete end-to-end pipeline in real time with visual step indicators and streaming status logs.
3. **Session Explorer**: Drill-down inspector for all analyzed sessions, displaying raw keystroke command sequences, attacker IP, and canonical 26-feature tables with heuristic provenance tags.
4. **AI & XAI Attribution Inspector**: Local SHAP explanation waterfall/bar displays showing positive (threat-increasing) and negative (threat-decreasing) feature weights alongside confidence ratings.
5. **Adaptive Decisions**: Detailed policy rule evaluation display showing confidence threshold gating, assigned deception profiles, and fallback reasons.
6. **Data Flow & Mesh**: Interactive architectural diagram tracing data flow across all modules.
7. **Technical Docs Viewer**: Embedded full-text reader of `docs/PROJECT_TECHNICAL_GUIDE.md` with table-of-contents navigation.
8. **Real-Time Roadmap**: Engineering milestones for transitioning from offline prototype to production live deception.
9. **System Health & Audit**: Automated verification of SHA-256 cryptographic signatures for all frozen model and scaler artifacts.
10. **Telemetry Export**: One-click downloads of analyzed session reports in standard JSON and CSV formats.

---

## 6. Required Software & Dependencies

* **Python:** Python 3.10 through 3.14 (fully verified in Python 3.14.4 on Ubuntu Linux 24.04).
* **Core Libraries:** `numpy`, `pandas`, `scikit-learn`, `joblib`, `pydantic`, `shap`, `scipy`, `pytest`.
* **Frontend:** Offline-first vendor bundle included in repository (`React 18`, `ReactDOM 18`, `Babel Standalone 8.0.7`, `Tailwind CSS`). No Node.js or npm installation required!

---

## 7. Ubuntu / Linux Setup Instructions

### Prerequisites
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip curl
```

### Installation & Environment Setup
```bash
# Clone the repository
git clone https://github.com/mohanalakshmis06/adaptive-honeypot-mesh.git
cd adaptive-honeypot-mesh

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 8. Windows Native Compatibility Status

| Feature | Windows Native | Notes |
| :--- | :---: | :--- |
| **Dashboard Web UI & Backend** | **VERIFIED** | Python standard library `http.server` runs natively on Windows |
| **Cowrie JSON Parsing** | **VERIFIED** | Standard JSON streaming; cross-platform |
| **Module 2 Feature Extraction** | **VERIFIED** | Pure Python & standard libraries; cross-platform |
| **Module 3 AI Inference & SHAP** | **VERIFIED** | Wheels available on PyPI for scikit-learn, joblib, pydantic, shap |
| **Module 4 Decision Engine** | **VERIFIED** | Pure Python rules and dictionaries |
| **Offline Pipeline Demo** | **VERIFIED** | Runs natively via `python scripts/cowrie_to_module4_demo.py` |
| **Unit & Parity Test Suite** | **VERIFIED** | `pytest tests/` runs identically on Windows |
| **Module 1 (eBPF Kernel Tracing)** | **UNSUPPORTED** | eBPF syscall tracing requires Linux kernel headers & `bpf()` syscall |
| **Live Cowrie Daemon** | **UNSUPPORTED** | Honeypot daemon requires Linux PAM and POSIX networking |

### Windows Quick-Start
On Windows (Command Prompt or PowerShell):
```cmd
cd adaptive-honeypot-mesh
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
run_dashboard.bat
```
Then open `http://127.0.0.1:8000/` in your browser.

---

## 9. Windows with WSL2 Setup Instructions

For teammates on Windows who wish to explore Linux-specific capabilities (such as running the live Cowrie honeypot or exploring Module 1 eBPF code):

1. **Install WSL2 (Ubuntu 24.04 recommended):**
   ```powershell
   wsl --install -d Ubuntu-24.04
   ```
2. **Open WSL2 terminal and follow Ubuntu setup:**
   ```bash
   sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
   git clone https://github.com/mohanalakshmis06/adaptive-honeypot-mesh.git
   cd adaptive-honeypot-mesh
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ./run_dashboard.sh
   ```
3. **Access Dashboard from Windows Host:**
   Open your browser in Windows and navigate to `http://localhost:8000/` (WSL2 automatically bridges localhost to the host OS).

> [!NOTE]
> eBPF kernel tracing inside WSL2 requires a custom WSL2 kernel built with `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, and `CONFIG_KPROBES=y`. For evaluating offline telemetry, feature extraction, and dashboard operations, WSL2 or native Windows works out of the box with zero custom kernel requirements!

---

## 10. Quick-Start Commands (TL;DR)

```bash
# 1. Start the operations dashboard
./run_dashboard.sh

# 2. In your browser, open:
# http://127.0.0.1:8000/

# 3. Run the offline pipeline directly from CLI
python scripts/cowrie_to_module4_demo.py

# 4. Run all unit and integration tests
pytest tests/
```

---

## 11. How to Run the Offline Demonstration Pipeline

The pipeline ingests Cowrie honeypot JSON logs, groups commands by session, extracts the 26-feature behavioral schema, executes Module 3 predictions and SHAP attributions, applies Module 4 decision policies, and produces an integration report:

```bash
# Activate environment
source .venv/bin/activate
export PYTHONPATH=".:module3_ai_xai_engine:$PYTHONPATH"

# Run with automated source resolution (detects ~/cowrie or in-repo sample data):
python scripts/cowrie_to_module4_demo.py

# Or explicitly specify a custom log directory:
python scripts/cowrie_to_module4_demo.py --log-dir data/sample_cowrie_logs
```

---

## 12. How to Run the Test Suites

All tests must be run with the virtual environment activated:

```bash
# 1. Full repository test suite (36 tests)
python -m pytest tests/

# 2. Integration parity tests (Module 2 -> Module 3 -> Module 4)
python -m unittest tests/test_integration_parity.py

# 3. Dashboard backend and API tests
python -m unittest tests/test_dashboard_backend.py

# 4. Module 4 decision engine and simulation adapter tests
python -m unittest discover -s module4_decision_engine/tests -p "test_*.py"

# 5. Module 3 AI/XAI engine tests
PYTHONPATH=module3_ai_xai_engine:.:$PYTHONPATH python -m unittest discover -s module3_ai_xai_engine/tests -p "test_*.py"
```

---

## 13. How to Supply Sanitized Telemetry

The repository includes a sanitized Cowrie log at `data/sample_cowrie_logs/cowrie.json`.

To analyze your own honeypot logs without exposing sensitive network information:
1. Ensure events contain standard Cowrie format with `eventid: "cowrie.command.input"`.
2. Sanitize IP addresses to RFC1918 private ranges (`192.168.1.x`, `10.0.2.x`, or `127.0.0.1`).
3. Strip any captured plain-text credentials or passwords (the pipeline only parses `input` shell command strings).
4. Place the file into `data/sample_cowrie_logs/cowrie.json` or pass via `--log-dir`:
   ```bash
   python scripts/cowrie_to_module4_demo.py --log-dir /path/to/your/logs
   ```

---

## 14. Expected Outputs & Report Locations

| Output File | Format | Description |
| :--- | :--- | :--- |
| `output/cowrie_integration_demo.json` | JSON | Master integration report containing all analyzed sessions, extracted features, predictions, SHAP attributions, decisions, and safety guarantees |
| `output/module3_prediction.json` | JSON | Direct Module 3 prediction payload for the latest evaluated session |
| `output/module4_decision.json` | JSON | Module 4 rule-based decision object with selected deception strategy |
| `output/module4_simulation_report.json` | JSON | Simulation adapter execution validation report |
| `GET /api/export?format=csv` | CSV | Exportable spreadsheet table summarizing all session metrics, classifications, and decisions |

---

## 15. Troubleshooting Common Errors

### Error: `Address already in use (port 8000)`
* **Cause:** A previous dashboard instance is still running in the background.
* **Remediation:** `./run_dashboard.sh` automatically detects if the dashboard is running and provides safe instructions. To stop it:
  ```bash
  fuser -k 8000/tcp
  ```
  Or launch on another port:
  ```bash
  ./run_dashboard.sh --port 8001
  ```

### Error: `ModuleNotFoundError: No module named 'pydantic'`
* **Cause:** The virtual environment does not have all integrated dependencies installed.
* **Remediation:** Reinstall from the updated root manifest:
  ```bash
  pip install -r requirements.txt
  ```

### Warning: `DeprecationWarning: Setting the shape on a NumPy array...`
* **Cause:** NumPy 2.x unpickling frozen models saved in earlier versions.
* **Remediation:** Safe to ignore; mathematical prediction outputs match bit-for-bit parity. Do not retrain or overwrite the frozen model artifacts!

---

## 16. Security Precautions & Safety Guarantees

* **Strict Localhost Binding:** The dashboard server binds solely to `127.0.0.1`. It refuses to bind to public or 0.0.0.0 interfaces.
* **Simulation-Only Execution:** The Module 4 execution adapter operates in `simulated_only` mode. No commands are sent to the operating system, firewall, or network interfaces.
* **Honeypot Isolation:** Cowrie is configured strictly to loopback `127.0.0.1:2222`. It is never exposed to external internet traffic.
* **Zero Secret Leakage:** The repository contains no API keys, SSH private keys, certificates, or real victim IP addresses.

---

## 17. Known Limitations

1. **Batch vs. Real-Time Streaming:** The current pipeline operates in batch mode over Cowrie JSON logs. Real-time streaming requires a message queue (e.g., Redis Streams, Kafka).
2. **eBPF Session Correlation:** Module 1 host telemetry operates independently from Cowrie application sessions. Associating container/shell PID lineage with eBPF events requires socket inode mapping.
3. **Simulated Deception Execution:** Deception profile responses (mock files, delayed terminal prompts, synthetic tokens) are calculated in software structures but not yet hooked to Cowrie's live terminal handler.

---

## 18. Project Maturity & Roadmap

### Maturity Estimates
1. **Academic Prototype & Offline Demonstration:** **95% Complete** (Fully functional, verified parity, local XAI, interactive operations dashboard).
2. **Team-Ready Reproducible Repository:** **92% Complete** (Clean manifests, Windows/WSL2 portability, in-repo sanitized sample dataset, comprehensive documentation).
3. **Production Real-Time Adaptive System:** **35% Complete** (Requires live event bus, eBPF session correlation, and active proxy deception interception).

### Future Milestones
* [ ] Integrate Redis Pub/Sub for sub-second Cowrie event streaming.
* [ ] Implement eBPF socket cookie correlation to tie kernel syscalls directly to Cowrie SSH session IDs.
* [ ] Connect Module 4 deception profiles to Cowrie dynamic filesystem backend plugins.

---

## 19. Team Contribution Instructions

1. **Branching Strategy:** Work on feature branches branched from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Commit Policy:** Do not commit virtual environments (`.venv`), large raw binary datasets (>10MB), or secrets.
3. **Model Artifact Preservation:** The model artifacts in `module3_ai_xai_engine/experiments/two_output_model_v1/` are **frozen**. Do not retrain, replace, or overwrite these files.
4. **Pre-Push Testing:** Run the full test suite before committing:
   ```bash
   pytest tests/
   ```

---

## 20. Citation & Licensing

### Academic Citation
If using this framework or its canonical feature schema in academic research:
```bibtex
@misc{adaptive_honeypot_mesh_2026,
  author = {Sundareswaran, Mohanalakshmi and Contributors},
  title = {AI-Driven Adaptive Deception Mesh: Autonomous Cyber Deception and Explainable AI Architecture},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/mohanalakshmis06/adaptive-honeypot-mesh}}
}
```

### License
This project is distributed under the terms of the **MIT License**. See [LICENSE](LICENSE) for details.
