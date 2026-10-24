// @ts-nocheck
/**
 * AI-Driven Adaptive Deception Mesh — Master Operations Dashboard
 * Powered by React, TypeScript, and Tailwind CSS.
 */

const { useState, useEffect } = React;

// ---------------------------------------------------------------------------
// Constants & Metadata
// ---------------------------------------------------------------------------
const FEATURE_METADATA = {
  total_events: { domain: "Volume", desc: "Total interaction records recorded for session", isHeuristic: false },
  command_count: { domain: "Volume", desc: "Total number of shell commands executed", isHeuristic: false },
  unique_commands: { domain: "Diversity", desc: "Distinct full command strings executed", isHeuristic: false },
  unique_processes: { domain: "Diversity", desc: "Distinct executable binaries tokenized", isHeuristic: false },
  unique_mitre_tactics: { domain: "Heuristic", desc: "MITRE ATT&CK tactics matched via keyword dictionary", isHeuristic: true },
  unique_mitre_techniques: { domain: "Heuristic", desc: "MITRE ATT&CK technique IDs matched via dictionary", isHeuristic: true },
  session_duration_seconds: { domain: "Temporal", desc: "Elapsed time between first and last event", isHeuristic: false },
  mean_inter_event_seconds: { domain: "Temporal", desc: "Mean delta time between consecutive commands", isHeuristic: false },
  std_inter_event_seconds: { domain: "Temporal", desc: "Standard deviation of inter-event timing intervals", isHeuristic: false },
  min_inter_event_seconds: { domain: "Temporal", desc: "Shortest delay between commands (automated bot detector)", isHeuristic: false },
  max_inter_event_seconds: { domain: "Temporal", desc: "Longest pause between commands (idle human detector)", isHeuristic: false },
  commands_per_minute: { domain: "Temporal", desc: "Command execution rate normalized per minute", isHeuristic: false },
  network_utility_ratio: { domain: "Pattern", desc: "Fraction of commands using curl, wget, nc, ssh, etc.", isHeuristic: false },
  file_inspection_ratio: { domain: "Pattern", desc: "Fraction of commands using cat, head, tail, grep, find", isHeuristic: false },
  identity_command_ratio: { domain: "Pattern", desc: "Fraction of commands using whoami, id, uname, hostname", isHeuristic: false },
  credential_keyword_ratio: { domain: "Pattern", desc: "Fraction of commands referencing shadow, passwd, id_rsa", isHeuristic: false },
  download_utility_ratio: { domain: "Pattern", desc: "Fraction of commands using ingress transfer tools", isHeuristic: false },
  mean_risk_score: { domain: "Heuristic", desc: "Average command severity score assigned by heuristic rules", isHeuristic: true },
  max_risk_score: { domain: "Heuristic", desc: "Maximum command risk score observed in the session", isHeuristic: true },
  risk_score_std: { domain: "Heuristic", desc: "Standard deviation of command risk ratings", isHeuristic: true },
  high_or_critical_ratio: { domain: "Heuristic", desc: "Fraction of commands classified as High or Critical", isHeuristic: true },
  path_command_ratio: { domain: "Syntax", desc: "Commands with explicit path notation (/bin/, /tmp/, ./)", isHeuristic: false },
  pipe_ratio: { domain: "Syntax", desc: "Commands using shell pipe (|) redirection", isHeuristic: false },
  redirect_ratio: { domain: "Syntax", desc: "Commands using shell file redirection (>, >>, <)", isHeuristic: false },
  mean_command_length: { domain: "Syntax", desc: "Average character length of executed command strings", isHeuristic: false },
  mean_argument_count: { domain: "Syntax", desc: "Average number of whitespace-delimited arguments", isHeuristic: false },
};

const STRATEGY_CATALOG = [
  {
    intent: "reconnaissance",
    strategy: "reconnaissance_decoy_profile",
    profile: "profile_simulated_recon_decoy",
    description: "Serves synthetic directory trees, harmless decoy credentials, and dummy network routing tables.",
  },
  {
    intent: "execution",
    strategy: "controlled_execution_deception",
    profile: "profile_simulated_execution_deception",
    description: "Simulates script execution with controlled mock outputs to delay adversary tooling without host risk.",
  },
  {
    intent: "persistence",
    strategy: "simulated_persistence_artifacts",
    profile: "profile_simulated_persistence",
    description: "Appears to accept cron jobs and startup modifications into isolated ephemeral storage.",
  },
  {
    intent: "defense_evasion",
    strategy: "monitoring_evasion_observation_profile",
    profile: "profile_simulated_evasion_observation",
    description: "Fakes successful log clearing (e.g., history -c, /var/log wipe) while silently continuing capture.",
  },
  {
    intent: "low_interaction",
    strategy: "standard_observation",
    profile: "profile_standard_observation",
    description: "Standard passive honeypot observation for shallow botnet port scanning and automated probes.",
  },
  {
    intent: "fallback",
    strategy: "safe_observation_fallback",
    profile: "profile_safe_observation",
    description: "Conservative fail-safe engaged whenever confidence is below 65% or intent is unsupported.",
  },
];

const ROADMAP_PILLARS = [
  {
    phase: "Phase 1: Telemetry Correlation",
    status: "Architecture Defined",
    title: "Kernel-to-Honeypot Session Binding",
    desc: "Tag Linux kernel eBPF tracepoints with Cowrie SSH connection session UUIDs using Linux cgroups v2 and network namespaces. Eliminates ambiguity between background OS processes and attacker actions.",
  },
  {
    phase: "Phase 2: Streaming Ingestion",
    status: "Design Specification",
    title: "Event-Driven Stream Ingestion",
    desc: "Migrate from static JSONL file ingestion to an Apache Kafka / Redpanda distributed event stream. Telemetry events are normalized and ingested within <5 milliseconds of keystroke arrival.",
  },
  {
    phase: "Phase 3: Sliding Windows",
    status: "Design Specification",
    title: "Sliding Feature-Window Aggregator",
    desc: "Compute the canonical 26-feature vector across 30-second sliding temporal windows (using Apache Flink or Faust). Allows mid-session deception adaptation before the attacker terminates their connection.",
  },
  {
    phase: "Phase 4: Low-Latency Inference",
    status: "Prototyped in ONNX",
    title: "High-Throughput ML Microservice",
    desc: "Export trained Random Forest models to ONNX Runtime or Triton Inference Server. Achieves sub-millisecond evaluation latency, enabling real-time interactive deception responses.",
  },
  {
    phase: "Phase 5: Policy Governance",
    status: "Specification Ready",
    title: "Open Policy Agent (OPA) Guardrails",
    desc: "Embed an enterprise policy engine with human-in-the-loop escalation rules. Deception responses for high-value networks require dual authorization before decoy deployment.",
  },
  {
    phase: "Phase 6: Micro-VM Containment",
    status: "Cloud Native Blueprint",
    title: "Ephemeral Micro-VM Deception Sandboxes",
    desc: "Execute deception targets inside disposable Firecracker or Kata Containers micro-VMs. Each session receives a dedicated ephemeral sandbox that is instantly scrubbed upon session disconnect.",
  },
  {
    phase: "Phase 7: Circuit Breakers",
    status: "Safety Requirement",
    title: "Automated Kill-Switch & Network Quotas",
    desc: "Hardware and SDN-enforced egress firewall rules that instantly sever outbound connections if an attacker attempts lateral traversal or DDoS relay from the honeypot mesh.",
  },
];

// ---------------------------------------------------------------------------
// Tab 1: Executive Overview
// ---------------------------------------------------------------------------
const OverviewTab = ({ dataset, health, onNavigateToDemo, onSelectScenario }) => {
  const sessions = dataset?.sessions || [];
  const totalSessions = sessions.length;
  const totalEvents = dataset?.command_events_processed || 0;

  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-slate-900 via-slate-800 to-indigo-950 border border-indigo-900/50 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              Jury Demonstration Ready — Simulation Mode Active
            </div>
            <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight">
              AI-Driven Adaptive Deception Mesh
            </h1>
            <p className="text-slate-300 text-xs md:text-sm mt-2 max-w-3xl leading-relaxed">
              An intelligent, policy-governed cyber deception framework that analyzes SSH honeypot keystrokes,
              evaluates multi-stage attacker intent using supervised machine learning, generates local SHAP explanations,
              and deterministically proposes calibrated deception profiles without modifying host infrastructure.
            </p>
          </div>
          <button
            onClick={onNavigateToDemo}
            className="px-5 py-3 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium shadow-lg shadow-cyan-900/30 flex items-center justify-center gap-2 transition-all transform hover:-translate-y-0.5 whitespace-nowrap text-xs md:text-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Run End-to-End Demo
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Historical Sessions</div>
          <div className="text-3xl font-bold text-white mt-1">{totalSessions}</div>
          <div className="text-[11px] text-slate-500 mt-1">Aggregated from Cowrie logs</div>
        </div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Commands Processed</div>
          <div className="text-3xl font-bold text-cyan-400 mt-1">{totalEvents}</div>
          <div className="text-[11px] text-slate-500 mt-1">Keystroke input events</div>
        </div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Decisions Generated</div>
          <div className="text-3xl font-bold text-indigo-400 mt-1">{totalSessions}</div>
          <div className="text-[11px] text-slate-500 mt-1">Module 4 deterministic rules</div>
        </div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Simulated Responses</div>
          <div className="text-3xl font-bold text-emerald-400 mt-1">{totalSessions}</div>
          <div className="text-[11px] text-emerald-500/80 mt-1">Simulation only (0 live changes)</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-6">
          <h2 className="text-base font-bold text-white mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Key Innovations Over Conventional Honeypots
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-4">
              <div className="text-xs font-semibold text-cyan-300">Canonical 26-Feature Behavioral Model</div>
              <p className="text-[11px] text-slate-300 mt-1.5 leading-relaxed">
                Replaces simplistic IP blocking with continuous behavioral modeling across 20 directly observed
                telemetry metrics (lexical patterns, inter-arrival timing, syntax) and 6 transparent heuristic metrics.
              </p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-4">
              <div className="text-xs font-semibold text-cyan-300">Supervised Two-Output AI Inference</div>
              <p className="text-[11px] text-slate-300 mt-1.5 leading-relaxed">
                Concurrently solves binary threat prediction (probing vs. weaponized intrusion) and multi-label intent
                attribution (reconnaissance, execution, persistence, evasion) using frozen Random Forest models.
              </p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-4">
              <div className="text-xs font-semibold text-cyan-300">Local Explainability (SHAP)</div>
              <p className="text-[11px] text-slate-300 mt-1.5 leading-relaxed">
                Eliminates opaque black-box decisions by generating signed Shapley value attributions for every prediction,
                clarifying exactly which commands or ratios influenced the model.
              </p>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-4">
              <div className="text-xs font-semibold text-cyan-300">Policy-Constrained Decision Engine</div>
              <p className="text-[11px] text-slate-300 mt-1.5 leading-relaxed">
                AI predictions never trigger live changes directly. Module 4 enforces defensive confidence thresholds,
                applies deterministic intent priority, and falls back to conservative observation upon uncertainty.
              </p>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-bold text-white mb-4 flex items-center gap-2">
              <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Implementation Status
            </h2>
            <div className="space-y-2.5">
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Feature Extraction (26 features)</span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-medium text-[10px]">Implemented</span>
              </div>
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Module 3 ML &amp; SHAP</span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-medium text-[10px]">Implemented (Frozen)</span>
              </div>
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Module 4 Decision Rules</span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-medium text-[10px]">Implemented</span>
              </div>
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Execution Adapter</span>
                <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 font-medium text-[10px]">Simulation Only</span>
              </div>
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Module 1 eBPF Correlation</span>
                <span className="px-2 py-0.5 rounded bg-slate-700 text-slate-400 font-medium text-[10px]">Roadmap Item</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">Live Dynamic Mesh SDN</span>
                <span className="px-2 py-0.5 rounded bg-slate-700 text-slate-400 font-medium text-[10px]">Roadmap Item</span>
              </div>
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400 bg-slate-800/30 p-2 rounded">
            <span className="font-semibold text-amber-400">Security Guarantee:</span> Read-only simulation mode. 0 commands executed; 0 network changes made.
          </div>
        </div>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <h2 className="text-base font-bold text-white mb-1 flex items-center gap-2">
          <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
          </svg>
          Recommended Jury Demonstration Scenarios
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Click any scenario below to automatically inspect the corresponding historical session in the Session Explorer.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div
            onClick={() => onSelectScenario("reconnaissance")}
            className="group cursor-pointer bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/70 hover:border-cyan-500/50 rounded-lg p-5 transition-all"
          >
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-0.5 rounded text-[10px] font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                Scenario 1
              </span>
              <span className="text-[11px] text-slate-400 font-mono">Session 2d5b8b398402</span>
            </div>
            <h3 className="text-sm font-bold text-white mt-3 group-hover:text-cyan-300 transition-colors">
              Basic Reconnaissance Probe
            </h3>
            <p className="text-xs text-slate-300 mt-2 line-clamp-2">
              Attacker executes discovery commands (`uname -a`, `id`). High confidence probe classification triggers standard observation.
            </p>
            <div className="mt-4 flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-700/40 pt-3">
              <span>Strategy: <strong className="text-cyan-400">standard_observation</strong></span>
              <span className="text-emerald-400 font-semibold">97% Conf</span>
            </div>
          </div>

          <div
            onClick={() => onSelectScenario("suspicious")}
            className="group cursor-pointer bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/70 hover:border-red-500/50 rounded-lg p-5 transition-all"
          >
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-0.5 rounded text-[10px] font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                Scenario 2
              </span>
              <span className="text-[11px] text-slate-400 font-mono">Session 31c0f469aa06</span>
            </div>
            <h3 className="text-sm font-bold text-white mt-3 group-hover:text-red-300 transition-colors">
              Suspicious Ingress Download
            </h3>
            <p className="text-xs text-slate-300 mt-2 line-clamp-2">
              Attacker issues `curl --version` with path traversal. High confidence weaponized intrusion triggers controlled execution deception.
            </p>
            <div className="mt-4 flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-700/40 pt-3">
              <span>Strategy: <strong className="text-red-400">controlled_execution</strong></span>
              <span className="text-red-400 font-semibold">88% Conf</span>
            </div>
          </div>

          <div
            onClick={() => onSelectScenario("fallback")}
            className="group cursor-pointer bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/70 hover:border-amber-500/50 rounded-lg p-5 transition-all"
          >
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                Scenario 3
              </span>
              <span className="text-[11px] text-slate-400 font-mono">Session 689276e8601d</span>
            </div>
            <h3 className="text-sm font-bold text-white mt-3 group-hover:text-amber-300 transition-colors">
              Low Confidence Safe Fallback
            </h3>
            <p className="text-xs text-slate-300 mt-2 line-clamp-2">
              Ambiguous command sequence yields 57% confidence (below 65% floor). Module 4 safely engages safe observation fallback.
            </p>
            <div className="mt-4 flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-700/40 pt-3">
              <span>Strategy: <strong className="text-amber-400">safe_fallback</strong></span>
              <span className="text-amber-400 font-semibold">57% Conf</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tab 2: Interactive Demo Runner
// ---------------------------------------------------------------------------
const InteractiveDemoTab = ({ dataset, isRunning, onRunDemo, onSelectSession }) => {
  const [pipelineLogs, setPipelineLogs] = useState([]);
  const [activeStep, setActiveStep] = useState(dataset ? 6 : 0);

  const handleRun = async () => {
    setActiveStep(1);
    setPipelineLogs(["[00:00:01] Initializing offline demonstration pipeline..."]);

    const timer1 = setTimeout(() => {
      setActiveStep(2);
      setPipelineLogs((prev) => [
        ...prev,
        "[00:00:02] Ingesting Cowrie logs from ~/cowrie/var/log/cowrie...",
        "[00:00:02] Found 5 JSON log files. Aggregating command.input events...",
      ]);
    }, 400);

    const timer2 = setTimeout(() => {
      setActiveStep(3);
      setPipelineLogs((prev) => [
        ...prev,
        "[00:00:03] Extracted 42 command events across 11 sessions.",
        "[00:00:03] Computing canonical 26-feature behavioral vectors (Module 2 contract)...",
      ]);
    }, 900);

    const timer3 = setTimeout(() => {
      setActiveStep(4);
      setPipelineLogs((prev) => [
        ...prev,
        "[00:00:04] Loading frozen Module 3 models & scaler (SHA-256 verified)...",
        "[00:00:04] Executing TwoOutputPredictor (Binary weaponization + Multi-label intent)...",
        "[00:00:04] Generating local SHAP TreeExplainer attribution vectors...",
      ]);
    }, 1400);

    const timer4 = setTimeout(() => {
      setActiveStep(5);
      setPipelineLogs((prev) => [
        ...prev,
        "[00:00:05] Applying Module 4 deterministic deception rules (confidence floor: 0.65)...",
      ]);
    }, 1900);

    const timer5 = setTimeout(() => {
      setActiveStep(6);
      setPipelineLogs((prev) => [
        ...prev,
        "[00:00:06] Executing Module 4 simulation adapter (Profile validation complete)...",
        "[00:00:06] SAFETY VERIFIED: 0 commands executed. 0 Cowrie configs changed.",
        "[00:00:06] Demonstration dataset updated successfully.",
      ]);
    }, 2400);

    try {
      await onRunDemo();
    } finally {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      clearTimeout(timer4);
      clearTimeout(timer5);
      setActiveStep(6);
    }
  };

  const steps = [
    { num: 1, title: "Initialize Pipeline", desc: "Verify virtualenv & models" },
    { num: 2, title: "Cowrie Ingestion", desc: "Read JSON logs & group sessions" },
    { num: 3, title: "26-Feature Extraction", desc: "Compute Module 2 canonical contract" },
    { num: 4, title: "Module 3 ML & SHAP", desc: "Classify threat, intents & attributions" },
    { num: 5, title: "Module 4 Decision Engine", desc: "Evaluate policy rules & fallbacks" },
    { num: 6, title: "Simulation Adapter", desc: "Validate profile (simulation-only)" },
  ];

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <svg className="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              One-Click Offline Pipeline Execution
            </h2>
            <p className="text-xs md:text-sm text-slate-300 mt-1 max-w-2xl">
              Execute the complete cybersecurity processing pipeline: from raw historical Cowrie honeypot logs to
              canonical feature extraction, two-output supervised AI inference, SHAP explanations, and policy-governed
              deception simulation.
            </p>
          </div>

          <button
            onClick={handleRun}
            disabled={isRunning}
            className={`px-6 py-3.5 rounded-lg font-bold text-white shadow-xl flex items-center gap-3 transition-all text-xs md:text-sm ${
              isRunning
                ? "bg-slate-700 cursor-not-allowed opacity-80"
                : "bg-gradient-to-r from-emerald-600 via-teal-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 shadow-emerald-900/40 hover:scale-105"
            }`}
          >
            {isRunning ? (
              <>
                <svg className="animate-spin h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Processing Pipeline...
              </>
            ) : (
              <>
                <svg className="w-5 h-5 text-emerald-200" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clipRule="evenodd" />
                </svg>
                RUN END-TO-END DEMONSTRATION
              </>
            )}
          </button>
        </div>

        <div className="mt-8 grid grid-cols-2 md:grid-cols-6 gap-3">
          {steps.map((s) => {
            const isCompleted = activeStep >= s.num;
            const isCurrent = activeStep === s.num && isRunning;
            return (
              <div
                key={s.num}
                className={`p-3 rounded-lg border text-center transition-all ${
                  isCurrent
                    ? "bg-cyan-950/50 border-cyan-500 shadow-lg shadow-cyan-950"
                    : isCompleted
                    ? "bg-slate-800/80 border-emerald-500/50"
                    : "bg-slate-900/40 border-slate-800 opacity-60"
                }`}
              >
                <div className="flex items-center justify-center mb-1.5">
                  <span
                    className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                      isCurrent
                        ? "bg-cyan-500 text-slate-950 animate-pulse"
                        : isCompleted
                        ? "bg-emerald-500 text-slate-950"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {isCompleted && !isCurrent ? "✓" : s.num}
                  </span>
                </div>
                <div className="text-xs font-bold text-white">{s.title}</div>
                <div className="text-[10px] text-slate-400 mt-0.5">{s.desc}</div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div className="bg-slate-900/90 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
            <span className="text-xs font-mono text-slate-400 ml-2">pipeline_execution_audit.log</span>
          </div>
          <span className="text-[11px] font-mono text-emerald-400">Simulation Mode Active</span>
        </div>
        <div className="p-4 font-mono text-xs text-slate-300 h-44 overflow-y-auto space-y-1 bg-black/40">
          {pipelineLogs.length > 0 ? (
            pipelineLogs.map((log, idx) => (
              <div key={idx} className={log.includes("SAFETY") ? "text-emerald-400 font-bold" : ""}>
                {log}
              </div>
            ))
          ) : (
            <div className="text-slate-500 italic">
              Click &quot;RUN END-TO-END DEMONSTRATION&quot; to execute offline pipeline and stream execution audit logs...
            </div>
          )}
        </div>
      </div>

      {dataset && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white">Processed Historical Sessions ({dataset.sessions?.length})</h3>
              <p className="text-xs text-slate-400">Click any row to jump to detailed explanation in Session Explorer</p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2.5 py-1 rounded border border-cyan-800/40">
              42 Command Events Aggregated
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-800/60 text-slate-300 font-semibold uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-3 rounded-l">Session ID</th>
                  <th className="py-2.5 px-3">Commands</th>
                  <th className="py-2.5 px-3">Classification</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3">Detected Intents</th>
                  <th className="py-2.5 px-3">Selected Strategy</th>
                  <th className="py-2.5 px-3 rounded-r">Simulation Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono">
                {dataset.sessions?.map((sess) => {
                  const label = sess.module3_prediction?.classification?.predicted_label;
                  const isWeaponized = label === "weaponized_intrusion";
                  const conf = sess.module3_prediction?.classification?.confidence;
                  const strat = sess.module4_decision?.selected_strategy;
                  const isFallback = strat === "safe_observation_fallback";

                  return (
                    <tr
                      key={sess.session_id}
                      onClick={() => onSelectSession(sess.session_id)}
                      className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 px-3 text-cyan-400 font-medium">{sess.session_id}</td>
                      <td className="py-2.5 px-3 text-slate-300">{sess.event_count} cmds</td>
                      <td className="py-2.5 px-3 font-sans">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            isWeaponized
                              ? "bg-red-500/20 text-red-400 border border-red-500/30"
                              : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                          }`}
                        >
                          {label}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        {typeof conf === "number" ? `${(conf * 100).toFixed(0)}%` : "N/A"}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 font-sans">
                        {sess.module3_prediction?.intent?.detected_intents?.length
                          ? sess.module3_prediction.intent.detected_intents.join(", ")
                          : "none"}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`text-[11px] ${
                            isFallback ? "text-amber-400" : isWeaponized ? "text-red-400" : "text-emerald-400"
                          }`}
                        >
                          {strat}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px] font-medium border border-emerald-500/20">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                          simulated_only
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tab 3: Session Explorer
// ---------------------------------------------------------------------------
const SessionExplorerTab = ({ dataset, selectedSessionId, onSelectSession }) => {
  const [filterScenario, setFilterScenario] = useState("all");
  const sessions = dataset?.sessions || [];

  let filteredSessions = sessions;
  if (filterScenario === "reconnaissance") {
    filteredSessions = sessions.filter(
      (s) => s.module4_decision?.selected_strategy === "standard_observation"
    );
  } else if (filterScenario === "suspicious") {
    filteredSessions = sessions.filter(
      (s) => s.module4_decision?.selected_strategy === "controlled_execution_deception"
    );
  } else if (filterScenario === "fallback") {
    filteredSessions = sessions.filter(
      (s) => s.module4_decision?.selected_strategy === "safe_observation_fallback"
    );
  }

  const activeSession =
    sessions.find((s) => s.session_id === selectedSessionId) || filteredSessions[0] || sessions[0];

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider mr-1">Filter Scenario:</span>
          <button
            onClick={() => setFilterScenario("all")}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              filterScenario === "all"
                ? "bg-cyan-600 text-white shadow-md shadow-cyan-900/40"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            All Sessions ({sessions.length})
          </button>
          <button
            onClick={() => setFilterScenario("reconnaissance")}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              filterScenario === "reconnaissance"
                ? "bg-blue-600 text-white shadow-md shadow-blue-900/40"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            Scenario 1: Reconnaissance
          </button>
          <button
            onClick={() => setFilterScenario("suspicious")}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              filterScenario === "suspicious"
                ? "bg-red-600 text-white shadow-md shadow-red-900/40"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            Scenario 2: Suspicious Download
          </button>
          <button
            onClick={() => setFilterScenario("fallback")}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              filterScenario === "fallback"
                ? "bg-amber-600 text-white shadow-md shadow-amber-900/40"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            Scenario 3: Safe Fallback
          </button>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <label className="text-xs text-slate-400 font-medium">Session ID:</label>
          <select
            value={activeSession?.session_id || ""}
            onChange={(e) => onSelectSession(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-white text-xs rounded-lg px-3 py-2 font-mono focus:ring-2 focus:ring-cyan-500 outline-none w-full md:w-48"
          >
            {filteredSessions.map((s) => (
              <option key={s.session_id} value={s.session_id}>
                {s.session_id} ({s.event_count} cmds)
              </option>
            ))}
          </select>
        </div>
      </div>

      {activeSession ? (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Session Identifier</span>
              <div className="text-sm font-mono font-bold text-cyan-400 mt-1 truncate">{activeSession.session_id}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">Source IP: {activeSession.source_ips?.join(", ") || "unknown"}</div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Module 3 Classification</span>
              <div className="text-sm font-bold text-white mt-1 flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-xs ${
                    activeSession.module3_prediction?.classification?.predicted_label === "weaponized_intrusion"
                      ? "bg-red-500/20 text-red-400"
                      : "bg-blue-500/20 text-blue-400"
                  }`}
                >
                  {activeSession.module3_prediction?.classification?.predicted_label}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  ({((activeSession.module3_prediction?.classification?.confidence || 0) * 100).toFixed(0)}%)
                </span>
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                Intents: {activeSession.module3_prediction?.intent?.detected_intents?.join(", ") || "none detected"}
              </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Module 4 Decision</span>
              <div className="text-xs font-mono font-bold text-indigo-300 mt-1 truncate">
                {activeSession.module4_decision?.selected_strategy}
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                Threat Level: <span className="uppercase font-semibold">{activeSession.module4_decision?.threat_level}</span>
              </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Simulated Profile</span>
              <div className="text-xs font-mono text-emerald-400 mt-1 truncate">
                {activeSession.module4_simulation?.simulated_profile || "profile_safe_observation"}
              </div>
              <div className="text-[11px] text-emerald-500/80 mt-0.5">
                Status: {activeSession.module4_simulation?.status} (simulation-only)
              </div>
            </div>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-bold text-white mb-3 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                Observed Keystroke Sequence ({activeSession.commands_observed?.length} Commands)
              </span>
              <span className="text-xs text-slate-400">
                Duration: {activeSession.raw_features?.session_duration_seconds?.toFixed(2)}s
              </span>
            </h3>

            <div className="space-y-2">
              {activeSession.commands_observed?.map((cmd, idx) => (
                <div
                  key={idx}
                  className="bg-black/40 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between font-mono text-xs"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-slate-500 text-[10px] w-6">#{idx + 1}</span>
                    <span className="text-cyan-300 font-semibold">{cmd}</span>
                  </div>
                  <span className="text-[10px] text-slate-500 bg-slate-800/50 px-2 py-0.5 rounded">
                    token: {cmd.trim().split(" ")[0]}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  Canonical 26-Feature Behavioral Vector (Module 2 Contract)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Pre-scaling values fed into the frozen TwoOutputPredictor. Clearly distinguishes observed sensor metrics from heuristic enrichments.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-800/70 text-slate-300 font-semibold sticky top-0 uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3 rounded-l">#</th>
                    <th className="py-2.5 px-3">Feature Name</th>
                    <th className="py-2.5 px-3">Domain</th>
                    <th className="py-2.5 px-3">Raw Value</th>
                    <th className="py-2.5 px-3">Provenance</th>
                    <th className="py-2.5 px-3 rounded-r">Interpretation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
                  {Object.entries(activeSession.raw_features || {}).map(([key, val], idx) => {
                    const meta = FEATURE_METADATA[key] || { domain: "General", desc: "Behavioral metric", isHeuristic: false };
                    const formattedVal = typeof val === "number" ? (Number.isInteger(val) ? val : val.toFixed(4)) : val;

                    return (
                      <tr key={key} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-2 px-3 text-slate-500">{idx}</td>
                        <td className="py-2 px-3 font-semibold text-slate-200">{key}</td>
                        <td className="py-2 px-3 text-slate-400">{meta.domain}</td>
                        <td className="py-2 px-3 text-cyan-300 font-bold">{formattedVal}</td>
                        <td className="py-2 px-3">
                          {meta.isHeuristic ? (
                            <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 text-[10px] border border-amber-500/20">
                              Heuristic Enrichment
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px] border border-emerald-500/20">
                              Direct Observed Telemetry
                            </span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-slate-400 font-sans text-xs">{meta.desc}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
          No session selected. Please select a session above.
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tab 4: AI & XAI Explainability (SHAP)
// ---------------------------------------------------------------------------
const XaiExplainerTab = ({ dataset, selectedSessionId, onSelectSession }) => {
  const sessions = dataset?.sessions || [];
  const activeSession = sessions.find((s) => s.session_id === selectedSessionId) || sessions[0];

  const prediction = activeSession?.module3_prediction;
  const classification = prediction?.classification;
  const intent = prediction?.intent;
  const shap = prediction?.shap_explanation;
  const deviations = prediction?.explanations || [];

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            Explainable AI (XAI) Attribution Inspector
          </h2>
          <p className="text-xs text-slate-400">
            Inspect local SHAP values and feature deviations for session:{" "}
            <span className="font-mono text-cyan-400 font-semibold">{activeSession?.session_id}</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-xs text-slate-400">Change Session:</label>
          <select
            value={activeSession?.session_id || ""}
            onChange={(e) => onSelectSession(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-white text-xs rounded-lg px-3 py-1.5 font-mono focus:ring-2 focus:ring-cyan-500 outline-none"
          >
            {sessions.map((s) => (
              <option key={s.session_id} value={s.session_id}>
                {s.session_id} ({s.module3_prediction?.classification?.predicted_label})
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <div>
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Output A</span>
              <h3 className="text-base font-bold text-white">Binary Threat Classification</h3>
            </div>
            <span className="px-2.5 py-1 rounded text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Random Forest (100 Trees)
            </span>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-300">Predicted Threat Class:</span>
              <span
                className={`px-3 py-1 rounded font-bold text-xs uppercase tracking-wider ${
                  classification?.predicted_label === "weaponized_intrusion"
                    ? "bg-red-500/20 text-red-400 border border-red-500/30"
                    : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                }`}
              >
                {classification?.predicted_label}
              </span>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-slate-400">Calibrated Confidence:</span>
                <span className="font-mono font-bold text-white">
                  {typeof classification?.confidence === "number"
                    ? `${(classification.confidence * 100).toFixed(1)}%`
                    : "N/A"}
                </span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                <div
                  className={`h-2.5 rounded-full transition-all duration-500 ${
                    classification?.predicted_label === "weaponized_intrusion"
                      ? "bg-gradient-to-r from-orange-500 to-red-500"
                      : "bg-gradient-to-r from-cyan-500 to-blue-500"
                  }`}
                  style={{ width: `${(classification?.confidence || 0) * 100}%` }}
                ></div>
              </div>
              <div className="flex justify-between text-[10px] text-slate-500 mt-1">
                <span>0% (Uncertain)</span>
                <span className="text-amber-400 font-semibold">65% (Module 4 Safety Floor)</span>
                <span>100% (Certain)</span>
              </div>
            </div>

            <div className="bg-slate-800/40 p-3 rounded-lg text-xs text-slate-400">
              <span className="font-semibold text-slate-300">Classification Basis: </span>
              {classification?.classification_basis || "Supervised Random Forest on provisional targets"}
            </div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <div>
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Output B</span>
              <h3 className="text-base font-bold text-white">Multi-Label Attacker Intent</h3>
            </div>
            <span className="px-2.5 py-1 rounded text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              MultiOutput Classifier
            </span>
          </div>

          <div className="space-y-3">
            <div className="text-xs text-slate-300 mb-2">
              Detected Intents:{" "}
              {intent?.detected_intents?.length ? (
                intent.detected_intents.map((it) => (
                  <span
                    key={it}
                    className="ml-1.5 px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono text-[11px] font-semibold"
                  >
                    {it}
                  </span>
                ))
              ) : (
                <span className="text-slate-500 italic ml-1">None detected (all below 0.5 threshold)</span>
              )}
            </div>

            {intent?.intent_scores &&
              Object.entries(intent.intent_scores).map(([intentName, score]) => (
                <div key={intentName}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="font-mono text-slate-300 capitalize">{intentName}:</span>
                    <span className="font-mono text-xs text-cyan-400 font-bold">{(score * 100).toFixed(0)}%</span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className={`h-1.5 rounded-full ${
                        score >= 0.5 ? "bg-emerald-400" : "bg-slate-600"
                      }`}
                      style={{ width: `${score * 100}%` }}
                    ></div>
                  </div>
                </div>
              ))}

            <div className="bg-slate-800/40 p-2.5 rounded text-[11px] text-amber-400/90 border border-amber-500/20 mt-3">
              <span className="font-semibold">Explicit Model Disclosure: </span>
              {intent?.unsupported_intents?.join(", ")} is unsupported by supervised ML due to 0.3% low training support
              and is safely excluded to avoid false confidence.
            </div>
          </div>
        </div>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
              </svg>
              SHAP TreeExplainer: Top Contributing Features
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Signed Shapley value attributions for binary classification. Positive values push toward{" "}
              <strong className="text-red-400 font-mono">weaponized_intrusion</strong>; negative values push toward{" "}
              <strong className="text-blue-400 font-mono">low_interaction_probe</strong>.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400 bg-slate-800 px-3 py-1 rounded">
            Explainer: SHAP TreeExplainer
          </span>
        </div>

        <div className="space-y-4 my-6">
          {shap?.top_features?.map((f, idx) => {
            const isPositive = f.shap_value > 0;
            const absVal = Math.min(Math.abs(f.shap_value) * 200, 100);

            return (
              <div key={idx} className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
                <div className="flex items-center justify-between text-xs mb-1.5 font-mono">
                  <span className="font-bold text-white">{f.feature_name}</span>
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        isPositive ? "bg-red-500/20 text-red-400" : "bg-cyan-500/20 text-cyan-400"
                      }`}
                    >
                      {isPositive ? "+ Supports Weaponization" : "− Opposes Weaponization"}
                    </span>
                    <span className="font-bold text-slate-200">{f.shap_value.toFixed(4)}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-1 bg-slate-900 h-3 rounded-full overflow-hidden p-0.5">
                  <div className="flex justify-end">
                    {!isPositive && (
                      <div
                        className="bg-gradient-to-l from-cyan-400 to-blue-600 h-full rounded-l-full"
                        style={{ width: `${absVal}%` }}
                      ></div>
                    )}
                  </div>
                  <div className="flex justify-start">
                    {isPositive && (
                      <div
                        className="bg-gradient-to-r from-orange-400 to-red-500 h-full rounded-r-full"
                        style={{ width: `${absVal}%` }}
                      ></div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-3 text-xs text-slate-400">
          <span className="font-bold text-cyan-400">XAI Interpretation Note: </span>
          {shap?.interpretation_note ||
            "SHAP values measure feature impact on model decision boundaries. They do not constitute forensic proof of malicious intent."}
        </div>
      </div>

      {deviations.length > 0 && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-2">Training Baseline Deviations (Z-Scores)</h3>
          <p className="text-xs text-slate-400 mb-4">
            Highlights features that deviate significantly from the baseline training distribution.
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-800/60 text-slate-300 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-2 px-3 rounded-l">Feature Name</th>
                  <th className="py-2 px-3">Observed Value</th>
                  <th className="py-2 px-3">Baseline Mean</th>
                  <th className="py-2 px-3">Baseline Std</th>
                  <th className="py-2 px-3">Z-Score Deviation</th>
                  <th className="py-2 px-3 rounded-r font-sans">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-[11px]">
                {deviations.slice(0, 5).map((dev, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40">
                    <td className="py-2 px-3 font-semibold text-white">{dev.feature_name}</td>
                    <td className="py-2 px-3 text-cyan-300 font-bold">{dev.observed_value.toFixed(2)}</td>
                    <td className="py-2 px-3 text-slate-400">{dev.reference_mean.toFixed(2)}</td>
                    <td className="py-2 px-3 text-slate-400">{dev.reference_std.toFixed(2)}</td>
                    <td className="py-2 px-3">
                      <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 font-bold">
                        {dev.deviation_score.toFixed(1)}σ
                      </span>
                    </td>
                    <td className="py-2 px-3 font-sans text-xs text-slate-300">{dev.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tab 5: Adaptive Deception Decisions
// ---------------------------------------------------------------------------
const DecisionEngineTab = ({ dataset, selectedSessionId, onSelectSession }) => {
  const sessions = dataset?.sessions || [];
  const activeSession = sessions.find((s) => s.session_id === selectedSessionId) || sessions[0];

  const decision = activeSession?.module4_decision;
  const simulation = activeSession?.module4_simulation;
  const prediction = activeSession?.module3_prediction;

  return (
    <div className="space-y-6">
      <div className="bg-amber-950/40 border-2 border-amber-500/60 rounded-xl p-5 shadow-lg flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 font-bold text-lg">
            ⚠️
          </div>
          <div>
            <h2 className="text-base font-bold text-amber-300 uppercase tracking-wider">
              SIMULATION ONLY — NO LIVE DECEPTION APPLIED
            </h2>
            <p className="text-xs text-amber-200/80 mt-0.5">
              The execution adapter strictly simulates profile assignment. No shell commands are executed, no honeypot
              daemon configuration is modified, and no live network listeners are spawned.
            </p>
          </div>
        </div>
        <span className="px-3 py-1.5 rounded bg-amber-500/20 text-amber-300 font-mono text-xs font-semibold border border-amber-500/40 whitespace-nowrap">
          Simulation Adapter v1.0.0
        </span>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              Module 4 Decision &amp; Simulation Flow
            </h3>
            <p className="text-xs text-slate-400">
              Session: <strong className="text-cyan-400 font-mono">{activeSession?.session_id}</strong>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400">Session:</label>
            <select
              value={activeSession?.session_id || ""}
              onChange={(e) => onSelectSession(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-white text-xs rounded-lg px-3 py-1 font-mono focus:ring-2 focus:ring-cyan-500 outline-none"
            >
              {sessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  {s.session_id} ({s.module4_decision?.selected_strategy})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 my-4 text-center">
          <div className="bg-slate-950/70 border border-indigo-900/60 rounded-lg p-3">
            <span className="text-[10px] font-bold text-indigo-400 uppercase tracking-wider">1. ML Input</span>
            <div className="text-xs font-bold text-white mt-1 truncate">
              {prediction?.classification?.predicted_label}
            </div>
            <div className="text-[11px] text-slate-400 font-mono mt-0.5">
              conf: {((prediction?.classification?.confidence || 0) * 100).toFixed(0)}%
            </div>
          </div>

          <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">2. Safety Gate</span>
            <div className="text-xs font-bold text-white mt-1">
              {(prediction?.classification?.confidence || 0) >= 0.65 ? (
                <span className="text-emerald-400">Pass (≥ 65%)</span>
              ) : (
                <span className="text-amber-400">Fail (&lt; 65%)</span>
              )}
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">Floor: 0.65 min</div>
          </div>

          <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">3. Intent Priority</span>
            <div className="text-xs font-mono font-bold text-cyan-300 mt-1 truncate">
              {decision?.detected_intent_used || "none (probe)"}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">Persist &gt; Evas &gt; Exec &gt; Recon</div>
          </div>

          <div className="bg-slate-950/70 border border-cyan-800/60 rounded-lg p-3">
            <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider">4. Selected Strategy</span>
            <div className="text-xs font-mono font-bold text-white mt-1 truncate">
              {decision?.selected_strategy}
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5 uppercase font-semibold">
              threat: {decision?.threat_level}
            </div>
          </div>

          <div className="bg-slate-950/70 border border-emerald-800/60 rounded-lg p-3">
            <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">5. Simulation Profile</span>
            <div className="text-xs font-mono font-bold text-emerald-300 mt-1 truncate">
              {simulation?.simulated_profile || "profile_safe_observation"}
            </div>
            <div className="text-[11px] text-emerald-500 mt-0.5">Status: {simulation?.status}</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
            <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Audit Trail &amp; Decision Basis
          </h3>
          <div className="space-y-2">
            {decision?.decision_basis?.map((reason, idx) => (
              <div key={idx} className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5">
                <span className="text-cyan-400 font-bold">•</span>
                <span>{reason}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400">
            <span className="font-semibold text-white">Execution Layer Note: </span>
            {decision?.execution_note}
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
            <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
            </svg>
            Simulation Adapter Execution Record
          </h3>

          <div className="space-y-3 font-mono text-xs">
            <div className="flex justify-between pb-2 border-b border-slate-800">
              <span className="text-slate-400">Session ID:</span>
              <span className="text-white font-bold">{simulation?.session_id}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-800">
              <span className="text-slate-400">Execution Mode:</span>
              <span className="text-amber-400 font-bold">{simulation?.execution_mode}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-800">
              <span className="text-slate-400">Applied to Cowrie:</span>
              <span className="text-emerald-400 font-bold">{simulation?.applied_to_cowrie ? "TRUE" : "FALSE"}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-800">
              <span className="text-slate-400">Commands Executed:</span>
              <span className="text-emerald-400 font-bold">{simulation?.commands_executed ? "TRUE" : "FALSE"}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-800">
              <span className="text-slate-400">Requested Strategy:</span>
              <span className="text-cyan-400 font-bold">{simulation?.requested_strategy}</span>
            </div>
            <div className="flex justify-between pb-2 border-b border-slate-800">
              <span className="text-slate-400">Simulated Profile:</span>
              <span className="text-emerald-400 font-bold">{simulation?.simulated_profile}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Validation Timestamp:</span>
              <span className="text-slate-300">{simulation?.timestamp}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <h3 className="text-sm font-bold text-white mb-2">Predefined Deception Strategy Mappings</h3>
        <p className="text-xs text-slate-400 mb-4">
          Deterministic strategy lookup matrix utilized by Module 4 and validated by the simulation adapter.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-800/70 text-slate-300 uppercase tracking-wider text-[11px]">
              <tr>
                <th className="py-2.5 px-3 rounded-l">Triggering Intent</th>
                <th className="py-2.5 px-3">Assigned Strategy</th>
                <th className="py-2.5 px-3">Simulated Profile Target</th>
                <th className="py-2.5 px-3 rounded-r">Deception Concept &amp; Defense Objective</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {STRATEGY_CATALOG.map((cat) => (
                <tr key={cat.strategy} className="hover:bg-slate-800/40">
                  <td className="py-2.5 px-3 font-semibold text-cyan-400 font-mono capitalize">{cat.intent}</td>
                  <td className="py-2.5 px-3 font-mono font-bold text-white">{cat.strategy}</td>
                  <td className="py-2.5 px-3 font-mono text-emerald-400">{cat.profile}</td>
                  <td className="py-2.5 px-3 text-slate-300 font-sans">{cat.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tab 6: Architecture & Telemetry Data Flow
// ---------------------------------------------------------------------------
const TelemetryFlowTab = () => {
  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <svg className="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
          System Architecture &amp; Telemetry Data Flow
        </h2>
        <p className="text-xs md:text-sm text-slate-300 mt-1 max-w-3xl">
          Complete structural map of the AI-Driven Adaptive Deception Mesh. Explicitly identifies implemented connections,
          simulated adapters, and standalone research components.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold font-mono text-cyan-400 bg-cyan-950/60 px-2.5 py-1 rounded border border-cyan-800/40">
                MODULE 1
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">
                Standalone / Roadmap Link
              </span>
            </div>
            <h3 className="text-base font-bold text-white">Kernel Telemetry Collector</h3>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed">
              Monitors low-level kernel execution via eBPF probes (`ebpf_exec_monitor.py` / `ebpf_telemetry.py`). Traces
              `execve` syscalls, parent/child process IDs, and memory access.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-amber-400/90 bg-amber-950/20 p-2.5 rounded border border-amber-900/30">
            <strong>Honest Disclosure:</strong> Module 1 exists as a standalone tool in `~/adaptive-honeypot-integration/module1`.
            Kernel events are <em>not</em> session-correlated with Cowrie in this offline demonstration.
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold font-mono text-indigo-400 bg-indigo-950/60 px-2.5 py-1 rounded border border-indigo-800/40">
                MODULE 2
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                Fully Implemented &amp; Tested
              </span>
            </div>
            <h3 className="text-base font-bold text-white">Canonical 26-Feature Extraction</h3>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed">
              Parses Cowrie JSONL events, validates timestamps, aggregates commands into sessions, extracts tokenized binaries,
              and generates the canonical 26-feature behavioral vector.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-300 bg-slate-800/30 p-2.5 rounded">
            <strong>Contract:</strong> Immutable schema of 20 directly observed metrics + 6 transparent heuristic features.
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold font-mono text-cyan-400 bg-cyan-950/60 px-2.5 py-1 rounded border border-cyan-800/40">
                MODULE 3
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                Frozen ML Models &amp; XAI
              </span>
            </div>
            <h3 className="text-base font-bold text-white">AI Decision &amp; XAI Engine</h3>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed">
              Executes `TwoOutputPredictor`: Output A binary Random Forest for weaponization detection, Output B multi-output
              Random Forest for multi-stage intent prediction, and SHAP TreeExplainer for local feature attributions.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-300 bg-slate-800/30 p-2.5 rounded">
            <strong>Artifacts:</strong> Scaler and models frozen with verified SHA-256 signatures.
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold font-mono text-purple-400 bg-purple-950/60 px-2.5 py-1 rounded border border-purple-800/40">
                MODULE 4
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                Fully Implemented &amp; Tested
              </span>
            </div>
            <h3 className="text-base font-bold text-white">Rule-Based Decision Engine</h3>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed">
              Deterministic policy controller (`decide()`). Enforces a 65% confidence safety floor, applies defensive
              intent priority resolution, and invokes conservative fallbacks upon ambiguity.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-300 bg-slate-800/30 p-2.5 rounded">
            <strong>Governance:</strong> AI predictions never mutate systems directly; decisions are strictly rule-mediated.
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold font-mono text-amber-400 bg-amber-950/60 px-2.5 py-1 rounded border border-amber-800/40">
                EXECUTION ADAPTER
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                Simulation Only
              </span>
            </div>
            <h3 className="text-base font-bold text-white">Deception Simulation Adapter</h3>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed">
              Validates decisions against allowlisted profile definitions (`simulate_decision()`). Simulates the assignment
              of deception profiles while enforcing zero host execution and zero Cowrie mutation.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-amber-400/90 bg-amber-950/20 p-2.5 rounded border border-amber-900/30">
            <strong>Simulation Guarantee:</strong> `applied_to_cowrie: False` and `commands_executed: False`.
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold font-mono text-emerald-400 bg-emerald-950/60 px-2.5 py-1 rounded border border-emerald-800/40">
                DASHBOARD
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                Jury Operations GUI
              </span>
            </div>
            <h3 className="text-base font-bold text-white">Operations &amp; Demonstration GUI</h3>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed">
              React + TypeScript + Tailwind CSS interface served via pure Python standard library `http.server`. Provides
              one-click demo execution, scenario exploration, XAI visualization, and report export.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-300 bg-slate-800/30 p-2.5 rounded">
            <strong>Security:</strong> Bound strictly to localhost `127.0.0.1:8000` with zero public exposure.
          </div>
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tab 7: Technical Documentation Viewer
// ---------------------------------------------------------------------------
const TechnicalDocsTab = () => {
  const [doc, setDoc] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [activeHeading, setActiveHeading] = useState("");

  useEffect(() => {
    fetch("/api/documentation")
      .then((res) => res.json())
      .then((data) => {
        setDoc(data);
        if (data.headings && data.headings.length > 0) {
          setActiveHeading(data.headings[0]);
        }
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load documentation:", err);
        setLoading(false);
      });
  }, []);

  const filteredHeadings = doc?.headings?.filter((h) =>
    h.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <svg className="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
            </svg>
            System Technical Guide &amp; Architecture Specification
          </h2>
          <p className="text-xs text-slate-300 mt-1">
            Comprehensive reference manual covering all 26 technical dimensions, codebase structure, formulas, and security boundaries.
          </p>
        </div>

        <a
          href="/api/documentation"
          download="PROJECT_TECHNICAL_GUIDE.md"
          className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-2 border border-slate-700 transition-colors"
        >
          <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          Download Markdown
        </a>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1 bg-slate-900/80 border border-slate-800 rounded-xl p-4 h-fit max-h-[750px] flex flex-col">
          <div className="mb-3">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
              Table of Contents
            </span>
            <input
              type="text"
              placeholder="Search sections..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:ring-1 focus:ring-cyan-500 outline-none"
            />
          </div>

          <div className="overflow-y-auto space-y-1 pr-1 flex-1">
            {filteredHeadings.map((heading) => (
              <a
                key={heading}
                href={`#section-${heading.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase()}`}
                onClick={() => setActiveHeading(heading)}
                className={`block text-xs py-1.5 px-2.5 rounded transition-colors truncate ${
                  activeHeading === heading
                    ? "bg-cyan-950/70 text-cyan-300 font-semibold border-l-2 border-cyan-400"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                }`}
                title={heading}
              >
                {heading}
              </a>
            ))}
          </div>
        </div>

        <div className="lg:col-span-3 bg-slate-900/80 border border-slate-800 rounded-xl p-6 lg:p-8 max-h-[750px] overflow-y-auto">
          {loading ? (
            <div className="text-center py-12 text-slate-400">Loading documentation...</div>
          ) : doc ? (
            <div className="text-slate-300 text-xs leading-relaxed space-y-6">
              {doc.content_markdown.split(/\n(?=## )/).map((sec, idx) => {
                const lines = sec.trim().split("\n");
                const headingLine = lines[0] || "";
                const headingText = headingLine.replace(/^##\s+/, "");
                const body = lines.slice(1).join("\n");
                const sectionId = `section-${headingText.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase()}`;

                return (
                  <div key={idx} id={sectionId} className="pt-4 border-t border-slate-800/60 first:border-0 first:pt-0">
                    {headingLine.startsWith("## ") ? (
                      <h2 className="text-base font-bold text-white mb-3 text-cyan-300 flex items-center gap-2">
                        <span className="w-2 h-2 rounded bg-cyan-400"></span>
                        {headingText}
                      </h2>
                    ) : (
                      <h1 className="text-lg font-extrabold text-white mb-4">{headingLine.replace(/^#\s+/, "")}</h1>
                    )}
                    <div className="whitespace-pre-wrap font-sans text-xs text-slate-300 leading-relaxed">
                      {body}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-12 text-red-400">Failed to render documentation.</div>
          )}
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tab 8: Real-Time Deployment Roadmap
// ---------------------------------------------------------------------------
const RoadmapTab = () => {
  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-2">
          Engineering Roadmap — Post-Demonstration Path
        </div>
        <h2 className="text-xl md:text-2xl font-extrabold text-white">
          Real-Time Implementation &amp; Enterprise Production Roadmap
        </h2>
        <p className="text-xs md:text-sm text-slate-300 mt-2 max-w-3xl leading-relaxed">
          The current project represents a rigorous, verified <strong>offline historical-log demonstration</strong>.
          To transition this architecture into an active enterprise production deployment, the following 7-phase
          engineering blueprint defines the requirements for streaming ingestion, micro-VM sandboxing, and SDN circuit breakers.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
            <h3 className="text-sm font-bold text-cyan-400 uppercase tracking-wider">
              Current Demonstration Status (A)
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-semibold">
              Verified Complete
            </span>
          </div>
          <ul className="space-y-2.5 text-xs text-slate-300">
            <li className="flex items-start gap-2">
              <span className="text-emerald-400 font-bold">✓</span>
              <span><strong>Data Source:</strong> Historical Cowrie JSONL log files (5 files, 42 commands).</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400 font-bold">✓</span>
              <span><strong>Timing:</strong> Post-session batch aggregation across complete sessions.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400 font-bold">✓</span>
              <span><strong>Inference:</strong> Scikit-learn Random Forest + SHAP TreeExplainer in Python.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400 font-bold">✓</span>
              <span><strong>Execution:</strong> Simulation-only adapter; zero live modifications applied.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400 font-bold">✓</span>
              <span><strong>Containment:</strong> Localhost read-only binding; completely safe demonstration.</span>
            </li>
          </ul>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
            <h3 className="text-sm font-bold text-indigo-400 uppercase tracking-wider">
              Future Production Architecture (B)
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-500/20 text-indigo-400 font-semibold">
              Architectural Roadmap
            </span>
          </div>
          <ul className="space-y-2.5 text-xs text-slate-300">
            <li className="flex items-start gap-2">
              <span className="text-indigo-400 font-bold">→</span>
              <span><strong>Data Source:</strong> Real-time Kafka event streams correlated with eBPF cgroups.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-indigo-400 font-bold">→</span>
              <span><strong>Timing:</strong> 30-second sliding temporal feature windows for mid-session adaptation.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-indigo-400 font-bold">→</span>
              <span><strong>Inference:</strong> Low-latency Triton/ONNX microservices (&lt;10ms latency).</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-indigo-400 font-bold">→</span>
              <span><strong>Execution:</strong> Dynamic synthetic filesystem &amp; decoy delivery via SDN.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-indigo-400 font-bold">→</span>
              <span><strong>Containment:</strong> Ephemeral Firecracker micro-VMs with automated egress kill-switches.</span>
            </li>
          </ul>
        </div>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <h3 className="text-base font-bold text-white mb-4">Production Deployment Pillars</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {ROADMAP_PILLARS.map((p, idx) => (
            <div key={idx} className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between text-[10px] mb-1.5">
                  <span className="font-mono text-cyan-400 font-bold uppercase">{p.phase}</span>
                  <span className="text-slate-500">{p.status}</span>
                </div>
                <h4 className="text-sm font-bold text-white mb-2">{p.title}</h4>
                <p className="text-xs text-slate-300 leading-relaxed">{p.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tab 9: System Health & Security Audit
// ---------------------------------------------------------------------------
const SystemHealthTab = ({ health }) => {
  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            System Status: {health?.status?.toUpperCase() || "CHECKING..."}
          </div>
          <h2 className="text-xl md:text-2xl font-bold text-white">System Integrity &amp; Security Audit</h2>
          <p className="text-xs text-slate-300 mt-1">
            Verification of frozen model artifact signatures, honeypot log integrity, and demonstration safety invariants.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <a
            href="/api/export?format=json"
            download="adaptive_deception_report.json"
            className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-2 transition-colors shadow-lg shadow-cyan-950"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Export JSON
          </a>
          <a
            href="/api/export?format=csv"
            download="adaptive_deception_report.csv"
            className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-2 transition-colors shadow-lg shadow-emerald-950"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Export CSV
          </a>
        </div>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Frozen ML Artifacts — SHA-256 Hash Verification
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Guarantees models and scalers remain completely unaltered from their verified training baseline.
            </p>
          </div>
          <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-3 py-1 rounded border border-emerald-800/40">
            Immutable Baseline
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-800/60 text-slate-300 uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-2.5 px-3 rounded-l">Artifact Name</th>
                <th className="py-2.5 px-3">Expected SHA-256</th>
                <th className="py-2.5 px-3">Actual SHA-256</th>
                <th className="py-2.5 px-3 rounded-r text-right">Integrity Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-[11px]">
              {health?.artifacts &&
                Object.entries(health.artifacts).map(([filename, art]) => (
                  <tr key={filename} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 font-semibold text-white">{filename}</td>
                    <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs">{art.expected_sha256}</td>
                    <td className="py-2.5 px-3 text-cyan-300 truncate max-w-xs">{art.actual_sha256 || "N/A"}</td>
                    <td className="py-2.5 px-3 text-right">
                      {art.valid ? (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
                          VERIFIED MATCH
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-bold border border-red-500/30">
                          HASH MISMATCH
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
            <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
            </svg>
            Demonstration Safety Boundaries
          </h3>
          <div className="space-y-2.5 text-xs">
            <div className="flex items-center justify-between p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-slate-300">Root / Sudo Privileges Required</span>
              <span className="font-mono text-emerald-400 font-bold">FALSE (Standard User Only)</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-slate-300">Attacker Commands Executed on Host</span>
              <span className="font-mono text-emerald-400 font-bold">FALSE (Zero Execution)</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-slate-300">Cowrie Configuration Modified</span>
              <span className="font-mono text-emerald-400 font-bold">FALSE (Read-Only Mode)</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-slate-300">Network Binding Exposure</span>
              <span className="font-mono text-cyan-400 font-bold">127.0.0.1 (Localhost Only)</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-slate-300">Module 4 Execution Adapter</span>
              <span className="font-mono text-amber-400 font-bold">SIMULATION ONLY</span>
            </div>
            <div className="flex items-center justify-between p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <span className="text-slate-300">Model &amp; Scaler Refit During Demo</span>
              <span className="font-mono text-emerald-400 font-bold">FROZEN (Read-Only)</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
              <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
              </svg>
              Cowrie Log Source Verification
            </h3>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between pb-1.5 border-b border-slate-800">
                <span className="text-slate-400">Log Directory:</span>
                <span className="text-slate-200">{health?.cowrie_logs?.directory_path}</span>
              </div>
              <div className="flex justify-between pb-1.5 border-b border-slate-800">
                <span className="text-slate-400">Directory Exists:</span>
                <span className="text-emerald-400 font-bold">
                  {health?.cowrie_logs?.directory_exists ? "YES" : "NO"}
                </span>
              </div>
              <div className="flex justify-between pb-1.5 border-b border-slate-800">
                <span className="text-slate-400">Log Files Found:</span>
                <span className="text-cyan-400 font-bold">{health?.cowrie_logs?.log_files_count} files</span>
              </div>
            </div>
            <div className="mt-3">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">
                Discovered Files:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {health?.cowrie_logs?.log_files?.map((f) => (
                  <span key={f} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400">
            Last Pipeline Run: <strong className="text-white">{health?.pipeline_state?.last_run_timestamp || "Not executed in this session"}</strong>
          </div>
        </div>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-bold text-amber-400 mb-2 flex items-center gap-2">
          <svg className="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          Academic &amp; Operational Disclosures (Jury Transparency)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-slate-300 mt-2">
          {health?.disclosures?.map((disc, idx) => (
            <div key={idx} className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 flex items-start gap-2">
              <span className="text-amber-400 font-bold">•</span>
              <span>{disc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Main App Component & Navigation Coordinator
// ---------------------------------------------------------------------------
const App = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const [dataset, setDataset] = useState(null);
  const [health, setHealth] = useState(null);
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const refreshData = async () => {
    try {
      const [healthRes, dataRes] = await Promise.all([
        fetch("/api/status"),
        fetch("/api/data"),
      ]);

      if (healthRes.ok) {
        const hData = await healthRes.json();
        setHealth(hData);
      }

      if (dataRes.ok) {
        const dData = await dataRes.json();
        setDataset(dData);
        if (!selectedSessionId && dData.sessions && dData.sessions.length > 0) {
          setSelectedSessionId(dData.sessions[0].session_id);
        }
      }
    } catch (err) {
      console.error("Failed to load initial data:", err);
      setErrorMsg("Network error connecting to operations backend on localhost:8000.");
    }
  };

  useEffect(() => {
    refreshData();
  }, []);

  const handleRunDemo = async () => {
    setIsRunning(true);
    setErrorMsg(null);
    try {
      const res = await fetch("/api/run-demo", { method: "POST" });
      const result = await res.json();
      if (!res.ok) {
        throw new Error(result.error || "Demo pipeline failed to execute.");
      }
      if (result.data) {
        setDataset(result.data);
      } else {
        await refreshData();
      }
    } catch (err) {
      console.error("Run demo error:", err);
      setErrorMsg(err.message || "Pipeline execution encountered an error.");
    } finally {
      setIsRunning(false);
    }
  };

  const handleSelectScenario = (scenario) => {
    if (!dataset?.sessions) return;
    let targetSess = null;
    if (scenario === "reconnaissance") {
      targetSess = dataset.sessions.find(
        (s) => s.module4_decision?.selected_strategy === "standard_observation"
      );
    } else if (scenario === "suspicious") {
      targetSess = dataset.sessions.find(
        (s) => s.module4_decision?.selected_strategy === "controlled_execution_deception"
      );
    } else if (scenario === "fallback") {
      targetSess = dataset.sessions.find(
        (s) => s.module4_decision?.selected_strategy === "safe_observation_fallback"
      );
    }

    if (targetSess) {
      setSelectedSessionId(targetSess.session_id);
    }
    setActiveTab("session-explorer");
  };

  const handleSelectSessionAndInspect = (sessionId) => {
    setSelectedSessionId(sessionId);
    setActiveTab("session-explorer");
  };

  const navItems = [
    { key: "overview", label: "Executive Overview", badge: null },
    { key: "interactive-demo", label: "Live Demo Runner", badge: "Action" },
    { key: "session-explorer", label: "Session Explorer", badge: dataset?.sessions?.length || "11" },
    { key: "xai-explainer", label: "AI & XAI Engine", badge: "SHAP" },
    { key: "decision-engine", label: "Adaptive Decisions", badge: "Rules" },
    { key: "telemetry-flow", label: "Data Flow & Mesh", badge: null },
    { key: "technical-docs", label: "Technical Docs", badge: "Guide" },
    { key: "roadmap", label: "Real-Time Roadmap", badge: "Future" },
    { key: "system-health", label: "System Health & Audit", badge: health?.status || "OK" },
  ];

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      <header className="bg-slate-950/90 border-b border-slate-800/80 sticky top-0 z-50 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-900/40">
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <div className="text-sm font-extrabold tracking-tight text-white flex items-center gap-2">
                <span>ADAPTIVE DECEPTION MESH</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                  v1.0-JURY
                </span>
              </div>
              <div className="text-[10px] text-slate-400">Autonomous Cyber Deception &amp; Explainable AI Mesh</div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span className="text-slate-300">Localhost Server:</span>
              <span className="font-mono text-emerald-400 font-bold">127.0.0.1:8000</span>
            </div>

            <div className="px-3 py-1.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-semibold flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
              <span>SIMULATION ONLY</span>
            </div>
          </div>
        </div>

        <div className="border-t border-slate-900 bg-slate-950/60 overflow-x-auto">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 py-1">
            {navItems.map((item) => {
              const isActive = activeTab === item.key;
              return (
                <button
                  key={item.key}
                  onClick={() => setActiveTab(item.key)}
                  className={`px-3 py-2 text-xs font-medium rounded-lg transition-all flex items-center gap-2 whitespace-nowrap ${
                    isActive
                      ? "bg-slate-800 text-cyan-300 font-semibold shadow-inner border border-slate-700/60"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
                  }`}
                >
                  {item.label}
                  {item.badge && (
                    <span
                      className={`text-[9px] px-1.5 py-0.2 rounded font-mono ${
                        isActive
                          ? "bg-cyan-500/20 text-cyan-300"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {errorMsg && (
          <div className="mb-6 p-4 rounded-xl bg-red-950/50 border border-red-500/50 text-red-200 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-red-400 font-bold text-sm">⚠ Error:</span>
              <span>{errorMsg}</span>
            </div>
            <button
              onClick={() => setErrorMsg(null)}
              className="text-red-300 hover:text-white font-bold ml-4"
            >
              ✕
            </button>
          </div>
        )}

        {activeTab === "overview" && (
          <OverviewTab
            dataset={dataset}
            health={health}
            onNavigateToDemo={() => setActiveTab("interactive-demo")}
            onSelectScenario={handleSelectScenario}
          />
        )}

        {activeTab === "interactive-demo" && (
          <InteractiveDemoTab
            dataset={dataset}
            isRunning={isRunning}
            onRunDemo={handleRunDemo}
            onSelectSession={handleSelectSessionAndInspect}
          />
        )}

        {activeTab === "session-explorer" && (
          <SessionExplorerTab
            dataset={dataset}
            selectedSessionId={selectedSessionId}
            onSelectSession={(sid) => setSelectedSessionId(sid)}
          />
        )}

        {activeTab === "xai-explainer" && (
          <XaiExplainerTab
            dataset={dataset}
            selectedSessionId={selectedSessionId}
            onSelectSession={(sid) => setSelectedSessionId(sid)}
          />
        )}

        {activeTab === "decision-engine" && (
          <DecisionEngineTab
            dataset={dataset}
            selectedSessionId={selectedSessionId}
            onSelectSession={(sid) => setSelectedSessionId(sid)}
          />
        )}

        {activeTab === "telemetry-flow" && <TelemetryFlowTab />}

        {activeTab === "technical-docs" && <TechnicalDocsTab />}

        {activeTab === "roadmap" && <RoadmapTab />}

        {activeTab === "system-health" && <SystemHealthTab health={health} />}
      </main>

      <footer className="bg-slate-950 border-t border-slate-900 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>AI-Driven Adaptive Deception Mesh • Senior Cybersecurity Demonstration Deliverable</span>
          <div className="flex items-center gap-4 text-[11px]">
            <span>Security: Localhost Only</span>
            <span>•</span>
            <span>Models: Frozen</span>
            <span>•</span>
            <span>Adapter: Simulation Only</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

// Mount Application
const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
