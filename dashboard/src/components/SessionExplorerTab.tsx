import React, { useState } from "react";
import { DemoDataset, SessionReport, ScenarioType } from "../types";

interface Props {
  dataset: DemoDataset | null;
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
}

const FEATURE_METADATA: { [key: string]: { domain: string; desc: string; isHeuristic: boolean } } = {
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

export const SessionExplorerTab: React.FC<Props> = ({
  dataset,
  selectedSessionId,
  onSelectSession,
}) => {
  const [filterScenario, setFilterScenario] = useState<ScenarioType>("all");
  const sessions = dataset?.sessions || [];

  // Filter based on preset scenarios
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

  // Selected session object
  const activeSession: SessionReport | undefined =
    sessions.find((s) => s.session_id === selectedSessionId) || filteredSessions[0] || sessions[0];

  return (
    <div className="space-y-6">
      {/* Scenario Filter and Session Selection Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        {/* Scenario Filter Buttons */}
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

        {/* Session Dropdown */}
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
          {/* Active Session Summary Banner */}
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

          {/* Observed Commands Section */}
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

          {/* Canonical 26-Feature Contract Table */}
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
                    const meta = FEATURE_METADATA[key] || {
                      domain: "General",
                      desc: "Computed behavioral metric",
                      isHeuristic: false,
                    };
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
          No session selected. Please select a session or scenario above.
        </div>
      )}
    </div>
  );
};
