# Phase 1 & 2 Audit and Training Decision

**Date:** 2026-10-19  
**Location:** `experiments/cowrie_labeling_review/AUDIT_AND_TRAINING_DECISION.md`  
**Dataset:** 1,000 unique command-bearing Cowrie sessions extracted from `data/raw/logs/`

---

## 1. Verified Counts from Artifacts

* **Total Command-Bearing Sessions Extracted:** 1,000
* **Canonical 26-Feature Featurization:** 1,000 / 1,000 valid, 0 NaNs, 0 Infs, 0 constant features.
* **Binary Target (`is_weaponized_intrusion`):**
  * `0` (Low-Interaction Probing): 879 sessions (87.9%)
  * `1` (Active Weaponization): 118 sessions (11.8%)
  * `unresolved`: 3 sessions (0.3%) — correctly held out from training splits.
* **Multi-Label Intent Targets:**
  * `reconnaissance`: 889 positive (88.9%) / 111 negative (11.1%)
  * `credential_access`: 3 positive (0.3%) / 997 negative (99.7%)
  * `persistence`: 64 positive (6.4%) / 936 negative (93.6%)
  * `defense_evasion`: 57 positive (5.7%) / 943 negative (94.3%)
  * `execution`: 64 positive (6.4%) / 936 negative (93.6%)
* **Partitions (Stratified on 997 Resolved Sessions):**
  * Training Split: 797 sessions (80.0%)
  * Held-Out Test Split: 200 sessions (20.0%)

---

## 2. Feature-Label Leakage Audit

### The Mechanism of Circularity
The canonical 26-feature vector includes 6 heuristic enrichment features and 5 keyword pattern ratios:
1. `mean_risk_score`, `max_risk_score`, `risk_score_std`, `high_or_critical_ratio`
2. `unique_mitre_tactics`, `unique_mitre_techniques`
3. `credential_keyword_ratio`, `download_utility_ratio`, `network_utility_ratio`, `identity_command_ratio`

In [`training/cowrie_adapter.py`](file:///D:/MINIPROJECT/module3_ai_xai_engine/training/cowrie_adapter.py), the heuristic enrichment function assigns high risk scores ($\ge 7.5$) and MITRE techniques based on keywords (`shadow`, `passwd`, `curl`, `wget`, `cat /proc/self/exe`). Simultaneously, [`training/provisional_labeler.py`](file:///D:/MINIPROJECT/module3_ai_xai_engine/training/provisional_labeler.py) defines `WEAP_01_CRED_TAMPER` and `WEAP_05_PAYLOAD_DOWNLOAD_EXEC` using the identical command patterns.

### Specific Leakage Risks:
* **Binary Classification:** `high_or_critical_ratio > 0` directly encodes the presence of weaponized keywords. A model trained on the full 26 features will achieve near-perfect metrics simply by memorizing the heuristic risk rule rather than learning behavioral patterns.
* **Intent Prediction:** `credential_keyword_ratio > 0` directly encodes the `credential_access` intent rule; `identity_command_ratio == 1.0` strongly signals `reconnaissance`.

### Leakage Mitigation & Experimental Design:
To prevent inflated claims of ML capability:
1. **Model Specification (Canonical 26-Feature Integration):** We train on the required 26-feature canonical interface to fulfill Module 2's specification.
2. **Leakage-Controlled Benchmark (19 Telemetry-Only Features):** We compare performance against a model trained strictly on genuine telemetry measurements (counts, timing statistics, command lengths, shell syntax, and process counts), excluding the 6 heuristic risk/MITRE features.

---

## 3. Repeated-Session & Command Archetype Overlap Audit

### The Repetition Finding
Across the 1,000 sessions, there are **only 13 unique command-sequence archetypes**:
1. `['uname -s -v -n -r -m']`: **863 sessions** (86.3% of the dataset)
2. Mirai dropper (`['sh', 'shell', ..., '/bin/busybox cat /proc/self/exe']`): **54 sessions** (5.4%)
3. SSH persistence & file locking (`['cd ~; chattr -ia .ssh; lockr ...']`): **54 sessions** (5.4%)
4. Multi-command reconnaissance (`["cat /etc/*release* ...", 'file /sbin/init']`): **14 sessions** (1.4%)
5. Miner setup script (`['chmod +x clean.sh; sh clean.sh; ...']`): **7 sessions** (0.7%)
6. Other minor variants and singletons: **8 sessions** (0.8%)

### Overlap Between Train and Test Splits:
* In the random 80/20 split, **100% of the 200 test sessions belong to command archetypes present in the training set**.
* **Role of Timing Jitter:** Every session has a unique 26-feature numeric vector solely because `session_duration_seconds` and `mean_inter_event_seconds` vary due to network latency and server response time. Behaviorally, however, the test set is an exact replay of training archetypes.
* **Grouped Archetype Holdout Feasibility:** A pure group-by-archetype split (e.g., holding out all 863 `uname` sessions) would leave only 137 sessions for training and create an 86% holdout test set with severely distorted class balance. 
* **Evaluation Strategy:** We evaluate on the stratified test split to measure operational stream performance, but explicitly disclose that high test accuracy reflects archetype recognition within identical bot campaigns.

---

## 4. Target Quality & Training Gate Decisions

| Target | Class Balance / Support | Gate Decision | Rationale |
| :--- | :---: | :---: | :--- |
| **Output A: `is_weaponized_intrusion`** | 118 positive (11.8%) / 879 negative (87.9%) | **PASSED** | Sufficient positive support to train a balanced binary classifier (`class_weight='balanced'`). |
| **Output B: Intent `reconnaissance`** | 889 positive (88.9%) / 111 negative (11.1%) | **PASSED** | Strong support across both classes. |
| **Output B: Intent `execution`** | 64 positive (6.4%) / 936 negative (93.6%) | **PASSED** | Modest but viable support across multiple script and dropper archetypes. |
| **Output B: Intent `persistence`** | 64 positive (6.4%) / 936 negative (93.6%) | **PASSED** | Modest but viable support across SSH and attribute locking sessions. |
| **Output B: Intent `defense_evasion`** | 57 positive (5.7%) / 943 negative (94.3%) | **PASSED** | Modest but viable support across process killing and file attribute locking sessions. |
| **Output B: Intent `credential_access`** | **3 positive (0.3%)** / 997 negative (99.7%) | **FAILED (BLOCKED)** | **Severely insufficient support.** In an 80/20 split, only 0–1 sample can exist in the test set. Supervised ML cannot be reliably trained or evaluated on 3 samples. Must be flagged as UNSUPPORTED for ML inference. |

---

## 5. Final Decision

* **PROCEED TO EXPERIMENTAL TRAINING** for:
  1. Supervised Binary Classifier: `is_weaponized_intrusion`.
  2. Multi-Label Intent Predictor: 4 supported intents (`reconnaissance`, `execution`, `persistence`, `defense_evasion`).
* **BLOCK & FLAG AS UNSUPPORTED:** `credential_access` intent (omitted from supervised ML target matrix; handled via transparent heuristic fallback with explicit limitation disclosure).
* **MODEL ARTIFACT DIRECTORY:** All trained models and honest evaluation metrics will be isolated under `experiments/two_output_model_v1/`.

