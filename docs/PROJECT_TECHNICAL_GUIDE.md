# AI-Driven Adaptive Deception Mesh / Adaptive Honeypot System
## Technical Reference Manual and Architecture Specification

**Document Version:** 1.0.0-PROD-SPEC
**Classification:** Academic & Defensive Engineering Demonstration
**Target Environment:** Offline Evaluation & Verification Harness
**Applicable Components:** Module 1 (Telemetry), Module 2 (Feature Engine), Module 3 (ML & XAI), Module 4 (Decision Engine), Execution Adapter (Simulation), and Operations Dashboard.

---

## 1. Project Overview and Problem Statement

Modern cyber attackers leverage automated reconnaissance, vulnerability scanning, and multi-stage lateral movement to breach organizational boundaries. Traditional defensive mechanisms—such as static honeypots, signature-based Intrusion Detection Systems (IDS), and conventional firewalls—suffer from distinct operational shortcomings:
1. **Predictability:** Static honeypots display invariable responses (e.g., standard Linux command outputs, fixed file trees, or canned service banners). Savvy adversaries and automated malware scan for telltale artifacts and quickly fingerprint the honeypot, aborting the attack or evading observation.
2. **Binary Defense:** Traditional network defenses terminate connections immediately upon detecting suspicious activity. While this stops isolated threats, it deprives security analysts of threat intelligence concerning attacker objectives, command-and-control (C2) domains, persistence mechanisms, and zero-day toolkits.
3. **Alert Fatigue:** SOC teams receive thousands of disconnected alerts without unified intent or behavioral attribution, leaving analysts unable to prioritize responses.

The **AI-Driven Adaptive Deception Mesh** addresses these challenges by transforming static honeypot deception into an intelligent, dynamic, and policy-governed cyber deception system. By coupling continuous session telemetry with Machine Learning (ML), Explainable AI (SHAP), and a deterministic rule-based decision engine, the system assesses attacker behavior in real time and proposes calibrated deception profiles.

---

## 2. Motivation for Adaptive Deception

The central thesis of adaptive deception is **asymmetric engagement**:
* **Prolong Attacker Engagement:** Rather than abruptly severing the session, the system selectively presents tailored decoys, simulated file paths, synthetic delay profiles, or synthetic service responses that keep the attacker engaged in a monitored, harmless sandbox.
* **Observe Full Cyber Kill Chain Progression:** Security teams observe initial access, discovery commands, tool downloads (`wget`, `curl`), privilege escalation attempts, and persistence scripts in controlled containment.
* **Drain Adversary Resources:** Forcing attackers to expend compute, time, and manual effort analyzing simulated system artifacts shifts the cost asymmetry back to the defender.
* **High-Fidelity Threat Intelligence:** The telemetry generated within an adaptive deception environment produces high-signal, zero-false-positive indicators of compromise (IoCs).

---

## 3. Innovation and Distinguishing Features

1. **Canonical 26-Feature Behavioral Contract:** Unifies disparate telemetry sources (network ingress, shell command streams, process trees, inter-arrival time distributions, and command syntax complexity) into an immutable 26-dimensional mathematical representation.
2. **Two-Output Supervised ML Architecture:** Concurrently evaluates binary weaponization likelihood (`weaponized_intrusion` vs. `low_interaction_probe`) alongside multi-label attacker intent classification (`reconnaissance`, `execution`, `persistence`, `defense_evasion`).
3. **Local Attribution with SHAP (Shapley Additive exPlanations):** Every single classification is accompanied by signed feature attribution vectors derived via tree-explainer algorithms, revealing which exact features elevated or lowered the model's confidence.
4. **Decoupled, Policy-Governed Decision Engine (Module 4):** Eliminates "black-box automated response" hazards. Machine learning predictions never directly execute system modifications; instead, Module 4 evaluates confidence bounds, filters unsupported classes, applies deterministic safety rules, and routes to approved deception profiles.
5. **Fail-Safe Conservative Fallbacks:** If prediction confidence drops below configured safety thresholds (e.g., `< 0.65`), the decision engine automatically engages `safe_observation_fallback`, preventing erroneous escalation.
6. **Isolated Simulation-Only Execution Layer:** The current architecture strictly implements and validates the decision-to-profile transformation in simulation mode, guaranteeing that no host system, firewall, or honeypot configuration is mutated during demonstration.

---

## 4. Complete Architecture and Data Flow

```
+----------------------------------------------------------------------------------------------------+
|                                      ATTACKER (SSH / Network)                                      |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                              COWRIE INTERACTION SENSOR (Honeypot)                                  |
|   - Session Logging (`cowrie.session.connect`, `cowrie.command.input`, `cowrie.session.closed`)     |
|   - Captures raw keystrokes, source IP, RFC-3339 timestamps, credentials                           |
+----------------------------------------------------------------------------------------------------+
            |                                                     |
            | (Kernel Telemetry Stream - Planned)                 v (JSONL Logs)
            v                                         +--------------------------------------+
+--------------------------------------+              | CowrieSessionAdapter                 |
| Module 1: Kernel Collector (eBPF)    |              | - Groups events by Session ID        |
| - Syscall tracing (`execve`, `open`) |              | - Parses ISO-8601 timestamps         |
| - Uncorrelated in current demo       |              | - Tokenizes commands & pipelines     |
+--------------------------------------+              +--------------------------------------+
                                                                  |
                                                                  v
+----------------------------------------------------------------------------------------------------+
| MODULE 2: Canonical Feature Extraction Pipeline                                                    |
|   - Computes 20 directly observed temporal, behavioral, pattern, and lexical features              |
|   - Enriches 6 transparent heuristic features (MITRE tactics/techniques, risk scores)              |
|   - Validates vector integrity: exactly 26 finite floating-point values                            |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v (Pre-normalized 26-feature vector)
+----------------------------------------------------------------------------------------------------+
| MODULE 3: AI Decision & XAI Engine (TwoOutputPredictor)                                            |
|   - Loads frozen StandardScaler (`cowrie_adapter_scaler.joblib`)                                   |
|   - Output A: RandomForestClassifier (100 trees, max_depth=6) -> Class & Confidence                |
|   - Output B: MultiOutputClassifier -> Intent scores (Recon, Exec, Persist, Evasion)               |
|   - XAI: TreeExplainer -> Top signed SHAP contributions (supports vs. opposes)                     |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v (Unified prediction payload)
+----------------------------------------------------------------------------------------------------+
| MODULE 4: Rule-Based Decision Engine (`decide()`)                                                  |
|   - Validates session format and confidence threshold (`MIN_CONFIDENCE = 0.65`)                    |
|   - Priority rule evaluation: persistence > defense_evasion > execution > reconnaissance            |
|   - Low confidence or unsupported intent -> `safe_observation_fallback`                            |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v (Strategy assignment)
+----------------------------------------------------------------------------------------------------+
| EXECUTION ADAPTER: Simulation Layer (`simulate_decision()`)                                         |
|   - Validates strategy against allowlist of 6 safe deception profiles                             |
|   - Verifies `execution_status == 'pending'` and numeric confidence                                |
|   - Asserts safety invariants: `applied_to_cowrie: False`, `commands_executed: False`              |
|   - Produces simulated profile execution report                                                    |
+----------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
| JURY DEMONSTRATION & SOC OPERATIONS DASHBOARD (React + TypeScript + Tailwind CSS)                  |
|   - Single-click offline pipeline execution                                                        |
|   - Executive overview & scenario explorer (Reconnaissance, Suspicious Activity, Safe Fallback)    |
|   - Live SHAP attribution bar charts and decision flow visualizer                                  |
|   - JSON/CSV export, system health verification, and full documentation viewer                     |
+----------------------------------------------------------------------------------------------------+
```

---

## 5. Project Directory Structure and Source File Index

```
~/adaptive-honeypot-integration/ai-honeypot/
├── config.py (symlink or root config)
├── requirements.txt                   # Baseline virtualenv dependencies
├── run_dashboard.sh                   # One-click dashboard execution wrapper
│
├── dashboard/                         # Jury Demonstration GUI Application
│   ├── server.py                      # Pure-Python multithreaded REST API & static server
│   ├── index.html                     # HTML5 shell loading React, TypeScript & Tailwind CSS
│   └── src/                           # TypeScript & React component source tree
│       ├── types.ts                   # Complete TypeScript data model and API interfaces
│       ├── App.tsx                    # Main stateful dashboard orchestration component
│       └── components/                # Specialized modular views
│           ├── OverviewTab.tsx        # Page A: Executive briefing & key metrics
│           ├── InteractiveDemoTab.tsx # Page B: One-click pipeline runner & logs
│           ├── SessionExplorerTab.tsx # Page C: Interactive session & scenario inspector
│           ├── XaiExplainerTab.tsx    # Page D: AI classification & SHAP visualizer
│           ├── DecisionEngineTab.tsx  # Page E: Module 4 rules & strategy mapping
│           ├── TelemetryFlowTab.tsx   # Page F: Telemetry architecture & status
│           ├── TechnicalDocsTab.tsx   # Page G: In-dashboard technical guide viewer
│           ├── RoadmapTab.tsx         # Page H: Real-time deployment roadmap
│           └── SystemHealthTab.tsx    # Page I: Artifact hashes & health checks
│
├── docs/                              # Project Documentation
│   └── PROJECT_TECHNICAL_GUIDE.md     # This comprehensive technical guide
│
├── module3_ai_xai_engine/             # Module 3 Source Tree
│   ├── config.py                      # Canonical 26-feature names, indices, engine settings
│   ├── main.py                        # Standalone Module 3 runner
│   ├── explainability/
│   │   ├── shap_explainer.py          # TreeExplainer wrapper extracting signed feature attributions
│   │   ├── explanation_formatter.py   # Baseline deviation calculator (z-scores)
│   │   └── visualization.py           # Plotting utilities
│   ├── models/
│   │   ├── two_output_predictor.py    # Core inference class unifying Output A, B, and SHAP
│   │   ├── classifier.py              # Legacy single-output classifier
│   │   ├── predictor.py               # Isolation Forest anomaly inference
│   │   └── model_loader.py            # Artifact deserialization helper
│   ├── training/
│   │   ├── cowrie_adapter.py          # Cowrie JSON parser & 26-feature extractor
│   │   ├── provisional_labeler.py     # Rule-based heuristic label generator for training
│   │   └── train_two_output_models.py # Model fitting script for Random Forest models
│   ├── schemas/
│   │   ├── feature_object.py          # Pydantic schema for Module 2 session payload
│   │   ├── prediction_schema.py       # Pydantic schemas for classification, intent, and SHAP
│   │   └── input_schema.py            # Input validation schemas
│   ├── experiments/
│   │   └── two_output_model_v1/       # Frozen Model Artifacts
│   │       ├── binary_weaponization_model.joblib # 100-tree binary Random Forest
│   │       ├── multilabel_intent_model.joblib    # Multi-output intent Random Forest
│   │       ├── cowrie_adapter_scaler.joblib      # Frozen StandardScaler for 26 features
│   │       ├── model_metadata.json               # Full evaluation metrics and hyperparameters
│   │       └── evaluation_report.json            # Classification report & cross-validation
│   └── tests/
│       ├── test_anomaly_detector.py   # Tests for Isolation Forest
│       ├── test_cowrie_adapter.py     # Tests for CowrieSessionAdapter
│       ├── test_module2_input.py      # Tests for canonical 26-feature contract
│       └── test_two_output_engine.py  # Tests for TwoOutputPredictor inference
│
├── module4_decision_engine/           # Module 4 Source Tree
│   ├── decision_engine.py             # Rule-based strategy selection engine (`decide()`)
│   ├── execution_adapter.py           # Simulation-only execution validator (`simulate_decision()`)
│   └── tests/
│       ├── test_decision_engine.py    # Unit tests for Module 4 strategy selection
│       └── test_execution_adapter.py  # Unit tests for simulation execution adapter
│
├── scripts/
│   ├── cowrie_to_module4_demo.py      # Standalone CLI integration pipeline
│   └── launch_dashboard.py            # Python dashboard runner script
│
├── src/                               # Module 2 Feature Extraction Engine
│   ├── feature_extractor.py           # Master 26-feature extraction coordinator
│   ├── feature_pipeline.py            # End-to-end dataset feature processor
│   ├── behavioral_features.py         # Behavioral ratio computations
│   ├── command_features.py            # Command syntax & length analysis
│   ├── temporal_features.py           # Inter-arrival time statistics
│   ├── process_features.py            # Process tracking
│   ├── network_features.py            # Network utility detection
│   ├── cleaner.py                     # Raw telemetry cleaning & null handling
│   ├── reader.py                      # Safe JSON/JSONL streaming ingestion
│   ├── validator.py                   # Input record validation
│   └── scaler.py                      # Feature scaling utilities
│
├── tests/                             # Integration & Regression Tests
│   ├── test_integration_parity.py    # Parity tests verifying exact hashes, formulas & schemas
│   ├── test_dashboard_backend.py     # Automated test suite for the dashboard server and APIs
│   ├── test_cleaner.py                # Tests for Module 2 telemetry cleaning
│   ├── test_features.py               # Tests for Module 2 feature extraction
│   ├── test_reader.py                 # Tests for malformed log handling
│   ├── test_scaler.py                 # Tests for scaler persistence
│   └── test_validator.py              # Tests for input schema compliance
│
└── output/                            # Integration and Demonstration Artifacts
    ├── cowrie_integration_demo.json   # Full session-by-session pipeline execution report
    ├── module3_prediction.json        # Sample Module 3 prediction payload
    ├── module4_decision.json          # Sample Module 4 decision payload
    └── module4_simulation_report.json # Sample simulation report
```

---

## 6. Detailed File Responsibilities

| File Path | Component | Responsibility |
|---|---|---|
| `scripts/cowrie_to_module4_demo.py` | Pipeline | End-to-end offline integration harness. Ingests Cowrie logs, aggregates sessions, runs `CowrieSessionAdapter`, invokes `TwoOutputPredictor`, runs `decide()`, executes `simulate_decision()`, and outputs `cowrie_integration_demo.json`. |
| `module3_ai_xai_engine/models/two_output_predictor.py` | Module 3 | Main inference coordinator. Loads frozen models and scaler, validates incoming 26-feature payloads, runs binary classification and multi-label intent prediction, and calculates SHAP values. |
| `module3_ai_xai_engine/explainability/shap_explainer.py` | Module 3 | Computes SHAP values using `shap.TreeExplainer` on the binary Random Forest, sorting the top positive (supporting) and negative (opposing) feature contributions. |
| `module3_ai_xai_engine/training/cowrie_adapter.py` | Module 3 / 2 | Ingests raw Cowrie commands, extracts executable tokens, computes inter-arrival timing statistics, applies deterministic MITRE heuristics, and constructs canonical 26-feature vectors. |
| `module4_decision_engine/decision_engine.py` | Module 4 | Evaluates Module 3 predictions against deterministic cybersecurity policies. Applies confidence floor (`0.65`), priority ordering of intents, and fallback mechanisms. |
| `module4_decision_engine/execution_adapter.py` | Execution | Validates Module 4 decisions, verifies the profile allowlist, and records simulated execution state without touching host processes or Cowrie configs. |
| `dashboard/server.py` | Dashboard | Lightweight, zero-dependency multithreaded HTTP server implementing REST API endpoints (`/api/status`, `/api/run-demo`, `/api/data`, `/api/export`, `/api/documentation`) bound strictly to `127.0.0.1:8000`. |
| `dashboard/src/App.tsx` | Dashboard | Main React interface coordinator. Manages active tab state, preset demonstration scenario switching, pipeline triggering, and asynchronous data fetching. |
| `src/cleaner.py` | Module 2 | Normalizes raw log fields, removes corrupt JSON lines, handles null fields, and formats timestamps into UTC datetimes. |
| `src/feature_extractor.py` | Module 2 | Orchestrates feature extractors across command, behavioral, network, and temporal domains to generate canonical records. |

---

## 7. Key Classes and Functions

* **`TwoOutputPredictor`** (`module3_ai_xai_engine/models/two_output_predictor.py`):
  * `__init__(model_dir)`: Loads `binary_weaponization_model.joblib`, `multilabel_intent_model.joblib`, `cowrie_adapter_scaler.joblib`, and `model_metadata.json`. Initializes `ShapExplainer`.
  * `predict_session(payload)`: Validates payload against `Module2SessionPayload`, normalizes features with the frozen scaler, generates binary class probability, computes multi-label intent scores, and attaches SHAP attributions.
* **`ShapExplainer`** (`module3_ai_xai_engine/explainability/shap_explainer.py`):
  * `explain(feature_vector, feature_names, top_k=5)`: Calls `_explainer(row)`, extracts positive-class contributions, ranks features by absolute magnitude, and labels direction (`supports_weaponized_intrusion` or `opposes_weaponized_intrusion`).
* **`CowrieSessionAdapter`** (`module3_ai_xai_engine/training/cowrie_adapter.py`):
  * `compute_session_features(session_dict)`: Accepts command list and timestamps, computes all 26 metrics, and outputs a feature dictionary and a provenance map.
  * `extract_executable_tokens(command)`: Deconstructs shell command strings, strips arguments, handles pipe (`|`) and redirect (`>`) chains, and extracts the primary binary.
  * `parse_iso_timestamp(ts)`: Safely parses ISO-8601 strings into timezone-aware `datetime` objects.
* **`decide(module3)`** (`module4_decision_engine/decision_engine.py`):
  * Validates incoming schema and verifies `confidence >= MIN_CONFIDENCE (0.65)`. Evaluates label and intent priority: `persistence > defense_evasion > execution > reconnaissance`. Returns proposed strategy and audit rationale.
* **`simulate_decision(decision)`** (`module4_decision_engine/execution_adapter.py`):
  * Validates `session_id`, `requires_execution_layer is True`, `execution_status == 'pending'`, and ensures the strategy exists in `ALLOWED_PROFILES`. Returns simulation result with `applied_to_cowrie: False`.

---

## 8. Cowrie Record Parsing and Session Aggregation

Cowrie honeypot instances log interaction events in newline-delimited JSON (`cowrie.json`).
1. **Filtering:** The pipeline filters for `eventid == "cowrie.command.input"`.
2. **Session Grouping:** Events are grouped by the unique honeypot session identifier (`session` string).
3. **Temporal Sorting:** Timestamps (`timestamp` field) are parsed into UTC `datetime` objects and sorted chronologically.
4. **Command Extraction:** Keystroke entries (`input` field) are collected in chronological order, with leading/trailing whitespace trimmed.
5. **Session Inclusion Threshold:** Only sessions containing at least one valid command entry are forwarded to feature extraction. In the historical sample, 42 command events across 11 sessions were extracted.

---

## 9. Module 2 Input Validation and Transformation

Module 2 guarantees data hygiene before mathematical feature extraction:
* **JSON Line Integrity:** Skipped records during parsing do not crash the pipeline; malformed records increment a skipped-line counter.
* **Null Imputation:** Missing numerical values default to `0.0`. Empty command lists are rejected.
* **Finite Value Assertion:** Every feature is checked with `math.isfinite()`. `NaN`, `+inf`, and `-inf` are coerced to `0.0`.
* **Ordering Guarantee:** Feature vectors are assembled in the exact 26-feature sequence defined by `MODULE2_CANONICAL_FEATURE_NAMES`.

---

## 10. The 26 Canonical Features Specification

| Index | Feature Name | Domain | Formula / Definition |
|---|---|---|---|
| 0 | `total_events` | Volume | Total logged interaction events within the session window. |
| 1 | `command_count` | Volume | Total number of executed shell commands ($N$). |
| 2 | `unique_commands` | Diversity | Count of distinct full command strings executed. |
| 3 | `unique_processes` | Diversity | Count of unique primary executable binaries extracted. |
| 4 | `unique_mitre_tactics` | Heuristic | Number of distinct MITRE ATT&CK tactics identified via keyword mapping. |
| 5 | `unique_mitre_techniques` | Heuristic | Number of distinct MITRE ATT&CK technique IDs identified. |
| 6 | `session_duration_seconds` | Temporal | Elapsed time: $t_{\text{last}} - t_{\text{first}}$ in seconds. Single commands yield $0.0$. |
| 7 | `mean_inter_event_seconds` | Temporal | Mean of delta times between consecutive commands: $\frac{1}{N-1} \sum \Delta t_i$. |
| 8 | `std_inter_event_seconds` | Temporal | Standard deviation of inter-command intervals: $\sqrt{\frac{1}{N-1} \sum (\Delta t_i - \bar{\Delta t})^2}$. |
| 9 | `min_inter_event_seconds` | Temporal | Minimum inter-arrival interval $\min(\Delta t_i)$ (automated bot detection indicator). |
| 10 | `max_inter_event_seconds` | Temporal | Maximum inter-arrival interval $\max(\Delta t_i)$ (operator idle detection). |
| 11 | `commands_per_minute` | Temporal | Execution frequency: $\frac{N}{\max(\text{duration}, 1.0) / 60.0}$. |
| 12 | `network_utility_ratio` | Pattern | Ratio of commands invoking network utilities (`curl`, `wget`, `nc`, `ssh`, etc.) to $N$. |
| 13 | `file_inspection_ratio` | Pattern | Ratio of commands inspecting files (`cat`, `head`, `tail`, `grep`, `find`, etc.) to $N$. |
| 14 | `identity_command_ratio` | Pattern | Ratio of discovery commands (`whoami`, `id`, `uname`, `hostname`) to $N$. |
| 15 | `credential_keyword_ratio` | Pattern | Ratio of commands referencing credentials (`shadow`, `passwd`, `id_rsa`) to $N$. |
| 16 | `download_utility_ratio` | Pattern | Ratio of ingress tool transfer utilities (`curl`, `wget`, `scp`, `tftp`) to $N$. |
| 17 | `mean_risk_score` | Heuristic | Average assigned risk score across commands in session ($\bar{R}$). |
| 18 | `max_risk_score` | Heuristic | Maximum individual command risk score observed ($\max(R_i)$). |
| 19 | `risk_score_std` | Heuristic | Standard deviation of command risk scores across the session. |
| 20 | `high_or_critical_ratio` | Heuristic | Fraction of commands with risk score $\ge 7.0$ (High or Critical). |
| 21 | `path_command_ratio` | Syntax | Ratio of commands containing explicit directory paths (`/bin/`, `/tmp/`, `../`) to $N$. |
| 22 | `pipe_ratio` | Syntax | Ratio of commands containing pipe operators (`\|`) to $N$. |
| 23 | `redirect_ratio` | Syntax | Ratio of commands containing redirect operators (`>`, `>>`, `<`) to $N$. |
| 24 | `mean_command_length` | Syntax | Average character length of raw command strings: $\frac{1}{N} \sum \text{len}(c_i)$. |
| 25 | `mean_argument_count` | Syntax | Average number of whitespace-delimited arguments per command: $\frac{1}{N} \sum (\text{words}(c_i) - 1)$. |

---

## 11. Feature Provenance: Observed Telemetry vs. Heuristic Enrichment

To maintain academic and forensic integrity, features are explicitly divided into two classes:
1. **Directly Observed Telemetry (20 Features):**
   * Features 0–3: Volume and unique binary counts.
   * Features 6–11: Precise temporal metrics computed strictly from Cowrie RFC-3339 event timestamps.
   * Features 12–16: Lexical keyword pattern ratios.
   * Features 21–25: Structural syntax characteristics (pipes, redirects, argument lengths).
   * *Status:* Fully verifiable against raw sensor logs.
2. **Deterministic Heuristic Enrichment (6 Features):**
   * Features 4–5: MITRE tactics and technique counts mapped via keyword lookup tables (`MITRE_ATTACK_MAPPING`).
   * Features 17–20: Heuristic risk metrics calculated from predefined severity rules.
   * *Status:* Transparent rule-based enrichments. They do not constitute external ground truth or kernel-verified MITRE tags.

---

## 12. Frozen Model and Scaler Management

* **Pre-scaling Guarantee:** The standard feature scaler (`cowrie_adapter_scaler.joblib`) was fit during training and is strictly frozen. The model and scaler are loaded in read-only mode during inference.
* **Exact Fit Parameters:**
  * Scaler Type: Scikit-learn `StandardScaler`.
  * Feature Dimension: 26.
* **Hash Verification:** To guarantee immutability, the SHA-256 hashes of all artifacts are verified at runtime:
  * `binary_weaponization_model.joblib`: `1cb17b111b25b837b6de36bf5a4cf1075c666c8336786da31f088142de18e057`
  * `multilabel_intent_model.joblib`: `f0f1d092820143e0985a08fd7316843748676cb9e73ae6f642ed5a13a1459c10`
  * `cowrie_adapter_scaler.joblib`: `bb9e8c6893452a915379a4d34d67c375620f17f85c1418649df243d261f64157`
  * `model_metadata.json`: `6d255d6e07836fd01d8d35d262411d9965a188a6ee92688c2a0643fb9769ddba`

---

## 13. Output A: Binary Weaponization Classification

* **Algorithm:** Random Forest Classifier (`n_estimators=100`, `max_depth=6`, `class_weight="balanced"`, `random_state=42`).
* **Objective:** Differentiate between automated, shallow reconnaissance scans (`low_interaction_probe`, class 0) and targeted intrusion attempts seeking weaponization, ingress tool downloads, or exploitation (`weaponized_intrusion`, class 1).
* **Confidence Metric:** The prediction confidence is the class probability output from `predict_proba()` for the predicted label:
  $$\text{Confidence} = \max(P(y=0 \mid \mathbf{x}), P(y=1 \mid \mathbf{x}))$$

---

## 14. Output B: Multi-Label Attacker Intent Prediction

* **Algorithm:** `MultiOutputClassifier(RandomForestClassifier(n_estimators=100, max_depth=6, class_weight="balanced"))`.
* **Supported Targets:**
  1. `reconnaissance` (Discovery of host, network, or user environment)
  2. `execution` (Script execution, shell invocation, binary execution)
  3. `persistence` (Account creation, cron configuration, startup modification)
  4. `defense_evasion` (Log cleaning, history suppression, process renaming)
* **Intent Detection Threshold:** Any intent with a predicted probability $P(\text{intent}_k) \ge 0.5$ is flagged as detected.
* **Explicit Exclusion Disclosure:**
  * `credential_access` was excluded from the supervised model. In the 1,000-session training distribution, only 3 sessions exhibited credential access patterns (0.3% support). Attempting supervised training on 3 positive instances would yield high generalization error and misleading confidence scores.

---

## 15. Explainable AI: SHAP Local Feature Attribution

* **Methodology:** `shap.TreeExplainer` applied directly to the trained Random Forest binary classifier.
* **Interpretation:**
  * SHAP calculates the Shapley value $\phi_i$ for each canonical feature:
    $$f(\mathbf{x}) = \phi_0 + \sum_{i=1}^{26} \phi_i$$
  * $\phi_i > 0$: The feature pushes the model prediction toward `weaponized_intrusion` (`supports_weaponized_intrusion`).
  * $\phi_i < 0$: The feature reduces the likelihood of weaponized intrusion, pushing the model toward `low_interaction_probe` (`opposes_weaponized_intrusion`).
* **Operational Caution:** SHAP explains the *mathematical decision boundary of the machine learning model*. It is not forensic proof of malicious intent.

---

## 16. Module 4: Adaptive Deception Strategy Selection

Module 4 maps classification outputs and detected intents to calibrated deception profiles using deterministic rules:

| Predicted Label | Primary Detected Intent | Confidence | Selected Deception Strategy | Simulated Profile Name |
|---|---|---|---|---|
| `low_interaction_probe` | Any / None | $\ge 0.65$ | `standard_observation` | `profile_standard_observation` |
| `weaponized_intrusion` | `persistence` | $\ge 0.65$ | `simulated_persistence_artifacts` | `profile_simulated_persistence` |
| `weaponized_intrusion` | `defense_evasion` | $\ge 0.65$ | `monitoring_evasion_observation_profile` | `profile_simulated_evasion_observation` |
| `weaponized_intrusion` | `execution` | $\ge 0.65$ | `controlled_execution_deception` | `profile_simulated_execution_deception` |
| `weaponized_intrusion` | `reconnaissance` | $\ge 0.65$ | `reconnaissance_decoy_profile` | `profile_simulated_recon_decoy` |
| Any | None supported | Any | `safe_observation_fallback` | `profile_safe_observation` |
| Any | Any | $< 0.65$ | `safe_observation_fallback` | `profile_safe_observation` |

* **Intent Priority Resolution:** If an attacker exhibits multiple simultaneous intents, Module 4 resolves conflicts using strict defensive priority:
  $$\text{persistence} \succ \text{defense\_evasion} \succ \text{execution} \succ \text{reconnaissance}$$

---

## 17. Confidence Thresholds and Fail-Safe Fallbacks

A critical vulnerability of naive AI-driven security systems is erratic behavior when handling out-of-distribution inputs. Module 4 incorporates defensive fail-safes:
1. **Confidence Floor (`MIN_CONFIDENCE = 0.65`):** If the binary classifier confidence drops below 65%, the system refuses to escalate deception and invokes `safe_observation_fallback`.
2. **Missing Intent Fallback:** If a session is labeled `weaponized_intrusion` but no supported intent achieves $P \ge 0.5$, the engine triggers `safe_observation_fallback`.
3. **Audit Justification:** Every decision payload includes an explicit `decision_basis` string array documenting exactly which rules and conditions fired.

---

## 18. Execution Adapter: Simulation-Only Validation

The execution adapter (`module4_decision_engine/execution_adapter.py`) enforces strict defensive containment:
* **Allowlist Enforcement:** Rejects any strategy string not present in `ALLOWED_PROFILES`.
* **State Check:** Verifies that incoming decisions have `requires_execution_layer == True` and `execution_status == 'pending'`.
* **Strict Simulation Guarantee:** Sets `applied_to_cowrie: False` and `commands_executed: False`. The adapter simulates the assignment of profile configurations without modifying honeypot daemon settings, firewall rules, or executing commands.

---

## 19. Dashboard Architecture and Backend Integration

```
+-------------------------------------------------------------------------------+
|                            BROWSER CLIENT                                     |
|   React 18 Single Page Application | TypeScript Interfaces | Tailwind CSS    |
+-------------------------------------------------------------------------------+
        |                                                               ^
        | HTTP GET / POST                                               | JSON Response
        v                                                               |
+-------------------------------------------------------------------------------+
|                   PYTHON HTTP SERVER (dashboard/server.py)                    |
|   ThreadingHTTPServer on 127.0.0.1:8000 (Pure Python Stdlib)                 |
+-------------------------------------------------------------------------------+
   |                      |                      |                       |
   v                      v                      v                       v
/api/status            /api/run-demo          /api/data               /api/export
- Validates model      - Invokes offline      - Reads current         - Generates CSV
  file hashes &          pipeline via safe      integration report      or formatted
  schema presence        module functions       cache                   JSON export
```

* **No Terminal Dependencies:** The user clicks a single button in the GUI to execute the entire offline pipeline.
* **Thread Safety:** The server manages concurrent UI requests using standard library synchronization primitives, preventing conflicting runs.

---

## 20. Report Generation and Audit Records

* **JSON Master Report:** Saved to `output/cowrie_integration_demo.json`. Contains overall metadata, safety attestations, limitation disclosures, and the full session array.
* **Audit Trail per Session:** Each session object records:
  1. `session_id` and unique `source_ips`.
  2. Complete `commands_observed` list.
  3. `raw_features` (26 canonical values) and `feature_provenance`.
  4. `module3_prediction` (class, confidence, intent scores, top SHAP features).
  5. `module4_decision` (strategy, threat level, rationale).
  6. `module4_simulation` (simulated profile name, timestamp, simulation confirmation).
* **Downloadable Exports:** The dashboard provides one-click export buttons for sanitized JSON and tabular CSV reports.

---

## 21. Running the Demonstration via GUI

1. Open a terminal in the project directory:
   ```bash
   cd ~/adaptive-honeypot-integration/ai-honeypot
   ```
2. Launch the dashboard server:
   ```bash
   ./run_dashboard.sh
   ```
   *(Or activate the virtualenv and run: `python dashboard/server.py`)*
3. Open a browser to:
   ```
   http://127.0.0.1:8000
   ```
4. **Operations Walkthrough:**
   * **Executive Overview:** View global metrics (11 sessions, 42 commands, model status).
   * **Interactive Demo:** Click **"RUN END-TO-END DEMONSTRATION"** to execute the pipeline in real time.
   * **Session Explorer:** Select predefined scenarios (Reconnaissance, Suspicious Activity, Safe Fallback) to inspect individual sessions.
   * **AI Explainability:** Inspect SHAP contribution bars illustrating why the model classified the session.
   * **Adaptive Deception:** Review the Module 4 decision ladder and simulated profile response.
   * **Documentation:** Read this complete technical reference manual directly in the GUI.

---

## 22. Troubleshooting Common Issues

* **Port 8000 in use:** Launch on an alternate port:
  ```bash
  python dashboard/server.py --port 8080
  ```
* **Virtualenv activation mismatch:** Verify the Python environment:
  ```bash
  which python # Should point to .venv-sklearn-test/bin/python
  ```
* **Artifact hash failure:** If `test_integration_parity.py` fails on artifact hashes, ensure no retraining script was executed. The models must remain frozen.
* **Missing Cowrie logs:** Ensure `~/cowrie/var/log/cowrie/cowrie.json*` files exist and are readable.

---

## 23. Security Boundaries and Known Limitations

### Security Safeguards
1. **Localhost Binding Only:** Server listens exclusively on `127.0.0.1`.
2. **Zero Arbitrary Execution:** Under no circumstances are commands found in attacker logs executed on the host.
3. **No Sudo / Root Requirements:** The entire stack operates strictly within user permissions.
4. **Frozen Model Immutability:** No online learning or refitting occurs during inference.

### Technical Limitations Disclosed to Jury
1. **Provisional Target Labels:** The ML models were trained on heuristic, rule-derived targets rather than verified external ground truth.
2. **Botnet Repetition Overlap:** High model confidence reflects learned script archetypes rather than universal attack generalization.
3. **Offline Historical Logs:** Telemetry is processed from historical logs; real-time streaming ingestion is an architectural roadmap item.
4. **Uncorrelated Kernel Telemetry:** Module 1 kernel tracing is not session-correlated in this offline demonstration.

---

## 24. Current Implementation Status Matrix

| Subsystem | Component | Implementation Status | Verification Status |
|---|---|---|---|
| **Data Ingestion** | Cowrie JSON Log Reader | **Implemented** | Verified (42 commands, 11 sessions) |
| **Telemetry** | Module 1 eBPF Tracing | **Implemented Standalone** | Not correlated with Cowrie sessions |
| **Feature Extraction** | Canonical 26-Feature Engine | **Implemented** | Verified (Exact schema & parity) |
| **Model Scaler** | StandardScaler (`cowrie_adapter_scaler.joblib`) | **Frozen Artifact** | Verified (SHA-256 match) |
| **Output A** | Binary Random Forest Model | **Frozen Artifact** | Verified (SHA-256 match) |
| **Output B** | Multi-Output Intent Model | **Frozen Artifact** | Verified (SHA-256 match) |
| **XAI** | SHAP TreeExplainer Local Attribution | **Implemented** | Verified (5 top features signed) |
| **Decision Engine** | Module 4 Deterministic Rule Base | **Implemented** | Verified (Priority & Fallback logic) |
| **Execution Layer** | Deception Execution Adapter | **Simulation Only** | Verified (Zero live changes applied) |
| **Operations UI** | React + TypeScript + Tailwind GUI | **Implemented** | Verified (Full 9-page dashboard) |

---

## 25. Realistic Enterprise Deployment Roadmap

```
+-----------------------------------------------------------------------------------+
|                        FUTURE ENTERPRISE DEPLOYMENT BLUEPRINT                     |
+-----------------------------------------------------------------------------------+
  Attacker Traffic
        |
        v
+------------------+         +--------------------+         +--------------------+
| Edge Deception   |         | Kernel Sensor      |         | Network Mirror     |
| Honeypots (K8s)  |         | (eBPF / Tetragon)  |         | (Zeek / Suricata)  |
+------------------+         +--------------------+         +--------------------+
        |                              |                              |
        +------------------------------+------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     | Real-Time Stream Broker (Kafka)   |
                     +-----------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     | Stream Processing Engine (Flink)  |
                     | - Session Correlation (cgroup ID) |
                     | - Sliding 30-sec Feature Windows  |
                     +-----------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     | High-Throughput ML Microservice   |
                     | (Triton / ONNX Runtime, <10ms)    |
                     +-----------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     | Policy Decision Controller (OPA)  |
                     | - Zero-Trust Rule Validation      |
                     | - Human-in-the-Loop Approval Gate |
                     +-----------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     | Dynamic Mesh Orchestrator (SDN)   |
                     | - In-memory Synthetic Filesystem  |
                     | - Dynamic Network Tarpits         |
                     | - Instant Kill-Switch Rollback    |
                     +-----------------------------------+
```

### Key Production Requirements
1. **Kernel Session Correlation:** Leverage Linux kernel cgroups and network namespaces to tag eBPF syscall telemetry with honeypot session UUIDs.
2. **Sliding Time Windows:** Transition from post-session batch analysis to 30-second sliding windows for live, mid-session adaptation.
3. **Hardened Containment:** Deploy deception targets in disposable micro-VMs (e.g., Firecracker or Kata Containers) that reset immediately upon session termination.
4. **Automated Kill-Switch:** Provide immediate physical and SDN circuit breakers to instantly quarantine any honeypot node that attempts outbound network traversal.

---

## 26. Jury Presentation Script and Demonstration Guide

### Step 1: Context & Vision (1 Minute)
> *"Esteemed members of the jury: Traditional cyber defenses present a static target—either terminating the attacker's connection immediately or displaying static honeypot decoys that attackers quickly fingerprint. Our project implements an **AI-Driven Adaptive Deception Mesh** that analyzes incoming attacker commands, predicts their multi-stage intent, explains why using SHAP, and dynamically recommends calibrated deception responses while keeping the attacker safely contained."*

### Step 2: Live Offline Pipeline Execution (1 Minute)
> *"Notice our central operations dashboard. With a single click on **'Run End-to-End Demonstration'**, our system reads historical Cowrie honeypot logs, extracts our canonical 26-feature behavioral vector, runs our frozen two-output machine learning model, generates SHAP explainability attributions, and feeds the output into our Module 4 decision engine."*

### Step 3: Scenario Inspection (2 Minutes)
* **Show Scenario 1 (Reconnaissance - Session `2d5b8b398402`):**
  > *"Here, the attacker runs simple discovery commands (`uname -a`, `id`). Our model predicts `low_interaction_probe` with 97% confidence. Module 4 assigns `standard_observation`—preventing unnecessary resource waste."*
* **Show Scenario 2 (Weaponized Intrusion - Session `31c0f469aa06`):**
  > *"Here, the attacker executes `curl --version` alongside reconnaissance probes. Our model flags `weaponized_intrusion` with 88% confidence and detects `execution` intent. Our SHAP visualizer shows that `network_utility_ratio` and `unique_processes` drove this prediction. Module 4 selects `controlled_execution_deception`."*
* **Show Scenario 3 (Safe Fallback - Session `689276e8601d`):**
  > *"Here, an ambiguous sequence produces 57% confidence. Because this falls below our defensive safety threshold of 65%, Module 4 triggers `safe_observation_fallback`. The system never makes unverified guesses."*

### Step 4: Security Rigor & Honesty (1 Minute)
> *"Notice our system-health audit view: all model artifacts and scalers are verified via SHA-256 hashes. Furthermore, our execution adapter operates in simulation-only mode—no live commands were executed, and no host configurations were modified. This represents a safe, auditable, and academically rigorous cyber deception architecture."*
