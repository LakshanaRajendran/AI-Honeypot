import React from "react";
import { DemoDataset, SessionReport } from "../types";

interface Props {
  dataset: DemoDataset | null;
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
}

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

export const DecisionEngineTab: React.FC<Props> = ({
  dataset,
  selectedSessionId,
  onSelectSession,
}) => {
  const sessions = dataset?.sessions || [];
  const activeSession: SessionReport | undefined =
    sessions.find((s) => s.session_id === selectedSessionId) || sessions[0];

  const decision = activeSession?.module4_decision;
  const simulation = activeSession?.module4_simulation;
  const prediction = activeSession?.module3_prediction;

  return (
    <div className="space-y-6">
      {/* Simulation Safety Warning Banner */}
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

      {/* Decision Flow Pipeline Diagram */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              Module 4 Decision & Simulation Flow
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

        {/* Visual Multi-Stage Decision Flow */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 my-4 text-center">
          {/* Node 1: Module 3 Prediction */}
          <div className="bg-slate-950/70 border border-indigo-900/60 rounded-lg p-3">
            <span className="text-[10px] font-bold text-indigo-400 uppercase tracking-wider">1. ML Input</span>
            <div className="text-xs font-bold text-white mt-1 truncate">
              {prediction?.classification?.predicted_label}
            </div>
            <div className="text-[11px] text-slate-400 font-mono mt-0.5">
              conf: {((prediction?.classification?.confidence || 0) * 100).toFixed(0)}%
            </div>
          </div>

          {/* Node 2: Safety Threshold Filter */}
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

          {/* Node 3: Intent Priority Evaluation */}
          <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">3. Intent Priority</span>
            <div className="text-xs font-mono font-bold text-cyan-300 mt-1 truncate">
              {decision?.detected_intent_used || "none (probe)"}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">Persist &gt; Evas &gt; Exec &gt; Recon</div>
          </div>

          {/* Node 4: Selected Strategy */}
          <div className="bg-slate-950/70 border border-cyan-800/60 rounded-lg p-3">
            <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider">4. Selected Strategy</span>
            <div className="text-xs font-mono font-bold text-white mt-1 truncate">
              {decision?.selected_strategy}
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5 uppercase font-semibold">
              threat: {decision?.threat_level}
            </div>
          </div>

          {/* Node 5: Simulated Profile */}
          <div className="bg-slate-950/70 border border-emerald-800/60 rounded-lg p-3">
            <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">5. Simulation Profile</span>
            <div className="text-xs font-mono font-bold text-emerald-300 mt-1 truncate">
              {simulation?.simulated_profile || "profile_safe_observation"}
            </div>
            <div className="text-[11px] text-emerald-500 mt-0.5">Status: {simulation?.status}</div>
          </div>
        </div>
      </div>

      {/* Decision Rationale Details */}
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

        {/* Simulation Execution Record */}
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

      {/* Predefined Deception Strategies Catalog */}
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
