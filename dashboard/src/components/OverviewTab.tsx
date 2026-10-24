import React from "react";
import { DemoDataset, SystemHealth } from "../types";

interface Props {
  dataset: DemoDataset | null;
  health: SystemHealth | null;
  onNavigateToDemo: () => void;
  onSelectScenario: (scenario: "reconnaissance" | "suspicious" | "fallback") => void;
}

export const OverviewTab: React.FC<Props> = ({
  dataset,
  health,
  onNavigateToDemo,
  onSelectScenario,
}) => {
  const sessions = dataset?.sessions || [];
  const totalSessions = sessions.length;
  const totalEvents = dataset?.command_events_processed || 0;

  // Compute distributions
  const probesCount = sessions.filter(
    (s) => s.module3_prediction?.classification?.predicted_label === "low_interaction_probe"
  ).length;
  const weaponizedCount = sessions.filter(
    (s) => s.module3_prediction?.classification?.predicted_label === "weaponized_intrusion"
  ).length;

  const fallbackCount = sessions.filter(
    (s) => s.module4_decision?.selected_strategy === "safe_observation_fallback"
  ).length;
  const standardObsCount = sessions.filter(
    (s) => s.module4_decision?.selected_strategy === "standard_observation"
  ).length;
  const controlledExecCount = sessions.filter(
    (s) => s.module4_decision?.selected_strategy === "controlled_execution_deception"
  ).length;

  return (
    <div className="space-y-6">
      {/* Executive Briefing Banner */}
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
            <p className="text-slate-300 text-sm md:text-base mt-2 max-w-3xl leading-relaxed">
              An intelligent, policy-governed cyber deception framework that analyzes SSH honeypot keystrokes,
              evaluates multi-stage attacker intent using supervised machine learning, generates local SHAP explanations,
              and deterministically proposes calibrated deception profiles without modifying host infrastructure.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
            <button
              onClick={onNavigateToDemo}
              className="px-5 py-3 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium shadow-lg shadow-cyan-900/30 flex items-center justify-center gap-2 transition-all transform hover:-translate-y-0.5"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Run End-to-End Demo
            </button>
          </div>
        </div>
      </div>

      {/* Primary KPI Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Historical Sessions</div>
          <div className="text-3xl font-bold text-white mt-1">{totalSessions}</div>
          <div className="text-xs text-slate-500 mt-1">Aggregated from Cowrie logs</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Commands Processed</div>
          <div className="text-3xl font-bold text-cyan-400 mt-1">{totalEvents}</div>
          <div className="text-xs text-slate-500 mt-1">Keystroke input events</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Decisions Generated</div>
          <div className="text-3xl font-bold text-indigo-400 mt-1">{totalSessions}</div>
          <div className="text-xs text-slate-500 mt-1">Module 4 deterministic rules</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Simulated Responses</div>
          <div className="text-3xl font-bold text-emerald-400 mt-1">{totalSessions}</div>
          <div className="text-xs text-emerald-500/80 mt-1">Simulation only (0 live changes)</div>
        </div>
      </div>

      {/* What is Innovative & System Status Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Core Innovations Card */}
        <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-6">
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Key Innovations Over Conventional Honeypots
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-4">
              <div className="text-sm font-semibold text-cyan-300">Canonical 26-Feature Behavioral Model</div>
              <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                Replaces simplistic IP blocking with continuous behavioral modeling across 20 directly observed
                telemetry metrics (lexical patterns, inter-arrival time distributions, syntax) and 6 transparent heuristic metrics.
              </p>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-4">
              <div className="text-sm font-semibold text-cyan-300">Supervised Two-Output AI Inference</div>
              <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                Concurrently solves binary threat prediction (probing vs. weaponized intrusion) and multi-label intent
                attribution (reconnaissance, execution, persistence, evasion) using frozen Random Forest models.
              </p>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-4">
              <div className="text-sm font-semibold text-cyan-300">Local Explainability (SHAP)</div>
              <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                Eliminates opaque black-box decisions by generating signed Shapley value attributions for every prediction,
                clarifying exactly which commands or ratios influenced the model.
              </p>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/60 rounded-lg p-4">
              <div className="text-sm font-semibold text-cyan-300">Policy-Constrained Decision Engine</div>
              <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
                AI predictions never trigger live changes directly. Module 4 enforces defensive confidence thresholds,
                applies deterministic intent priority, and falls back to conservative observation upon uncertainty.
              </p>
            </div>
          </div>
        </div>

        {/* Feature Maturity & Safety Matrix */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
              <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Implementation Status
            </h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Feature Extraction (26 features)</span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-medium">Implemented</span>
              </div>
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Module 3 ML & SHAP Inference</span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-medium">Implemented (Frozen)</span>
              </div>
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Module 4 Decision Rules</span>
                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-medium">Implemented</span>
              </div>
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Execution Adapter</span>
                <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 font-medium">Simulation Only</span>
              </div>
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800">
                <span className="text-slate-300">Module 1 eBPF Correlation</span>
                <span className="px-2 py-0.5 rounded bg-slate-700 text-slate-400 font-medium">Roadmap Item</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">Live Dynamic Mesh SDN</span>
                <span className="px-2 py-0.5 rounded bg-slate-700 text-slate-400 font-medium">Roadmap Item</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400 bg-slate-800/30 p-2.5 rounded">
            <span className="font-semibold text-amber-400">Security Guarantee:</span> All demonstration actions are
            strictly read-only and simulation-mode. Zero attacker commands are executed; zero network changes are made.
          </div>
        </div>
      </div>

      {/* Preset Jury Demonstration Scenarios */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <h2 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
          <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
          </svg>
          Recommended Jury Demonstration Scenarios
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Click any scenario below to automatically load the corresponding real historical session in the Session Explorer.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Scenario 1: Reconnaissance */}
          <div
            onClick={() => onSelectScenario("reconnaissance")}
            className="group cursor-pointer bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/70 hover:border-cyan-500/50 rounded-lg p-5 transition-all duration-200"
          >
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                Scenario 1
              </span>
              <span className="text-xs text-slate-400 font-mono">Session 2d5b8b398402</span>
            </div>
            <h3 className="text-base font-bold text-white mt-3 group-hover:text-cyan-300 transition-colors">
              Basic Reconnaissance Probe
            </h3>
            <p className="text-xs text-slate-300 mt-2 line-clamp-2">
              Attacker issues discovery commands (`uname -a`, `id`). High confidence low interaction classification leads to standard observation.
            </p>
            <div className="mt-4 flex items-center justify-between text-xs text-slate-400 border-t border-slate-700/40 pt-3">
              <span>Strategy: <strong className="text-cyan-400">standard_observation</strong></span>
              <span className="text-emerald-400 font-semibold">97% Confidence</span>
            </div>
          </div>

          {/* Scenario 2: Suspicious Activity */}
          <div
            onClick={() => onSelectScenario("suspicious")}
            className="group cursor-pointer bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/70 hover:border-red-500/50 rounded-lg p-5 transition-all duration-200"
          >
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                Scenario 2
              </span>
              <span className="text-xs text-slate-400 font-mono">Session 31c0f469aa06</span>
            </div>
            <h3 className="text-base font-bold text-white mt-3 group-hover:text-red-300 transition-colors">
              Suspicious Ingress Download
            </h3>
            <p className="text-xs text-slate-300 mt-2 line-clamp-2">
              Attacker executes `curl --version` with directory inspection. High confidence weaponized intrusion triggers controlled execution deception.
            </p>
            <div className="mt-4 flex items-center justify-between text-xs text-slate-400 border-t border-slate-700/40 pt-3">
              <span>Strategy: <strong className="text-red-400">controlled_execution</strong></span>
              <span className="text-red-400 font-semibold">88% Confidence</span>
            </div>
          </div>

          {/* Scenario 3: Safe Fallback */}
          <div
            onClick={() => onSelectScenario("fallback")}
            className="group cursor-pointer bg-slate-800/40 hover:bg-slate-800/80 border border-slate-700/70 hover:border-amber-500/50 rounded-lg p-5 transition-all duration-200"
          >
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                Scenario 3
              </span>
              <span className="text-xs text-slate-400 font-mono">Session 689276e8601d</span>
            </div>
            <h3 className="text-base font-bold text-white mt-3 group-hover:text-amber-300 transition-colors">
              Low Confidence Safe Fallback
            </h3>
            <p className="text-xs text-slate-300 mt-2 line-clamp-2">
              Ambiguous command sequence yields 57% confidence (below 65% floor). Module 4 gracefully invokes safe observation fallback.
            </p>
            <div className="mt-4 flex items-center justify-between text-xs text-slate-400 border-t border-slate-700/40 pt-3">
              <span>Strategy: <strong className="text-amber-400">safe_fallback</strong></span>
              <span className="text-amber-400 font-semibold">57% Confidence</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
