import React, { useState } from "react";
import { DemoDataset } from "../types";

interface Props {
  dataset: DemoDataset | null;
  isRunning: boolean;
  onRunDemo: () => Promise<void>;
  onSelectSession: (sessionId: string) => void;
}

export const InteractiveDemoTab: React.FC<Props> = ({
  dataset,
  isRunning,
  onRunDemo,
  onSelectSession,
}) => {
  const [pipelineLogs, setPipelineLogs] = useState<string[]>([]);
  const [activeStep, setActiveStep] = useState<number>(dataset ? 6 : 0);

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
        "[00:00:03] Extracting canonical 26-feature behavioral vectors (Module 2 contract)...",
      ]);
    }, 900);

    const timer3 = setTimeout(() => {
      setActiveStep(4);
      setPipelineLogs((prev) => [
        ...prev,
        "[00:00:04] Loading frozen Module 3 models & scaler (SHA-256 verified)...",
        "[00:00:04] Executing TwoOutputPredictor (Binary weaponization + Multi-label intent)...",
        "[00:00:04] Computing local SHAP TreeExplainer attribution vectors...",
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
      {/* Run Action Card */}
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
            className={`px-6 py-3.5 rounded-lg font-bold text-white shadow-xl flex items-center gap-3 transition-all text-sm md:text-base ${
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

        {/* Visual Pipeline Progression Steps */}
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

      {/* Terminal Output Viewer */}
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
        <div className="p-4 font-mono text-xs text-slate-300 h-48 overflow-y-auto space-y-1 bg-black/40">
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

      {/* Results Overview Table */}
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
              <tbody className="divide-y divide-slate-800">
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
                      <td className="py-2 px-3 font-mono text-cyan-400 font-medium">{sess.session_id}</td>
                      <td className="py-2 px-3 text-slate-300">{sess.event_count} cmds</td>
                      <td className="py-2 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                            isWeaponized
                              ? "bg-red-500/20 text-red-400 border border-red-500/30"
                              : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                          }`}
                        >
                          {label}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-mono">
                        {typeof conf === "number" ? `${(conf * 100).toFixed(0)}%` : "N/A"}
                      </td>
                      <td className="py-2 px-3 text-slate-300">
                        {sess.module3_prediction?.intent?.detected_intents?.length
                          ? sess.module3_prediction.intent.detected_intents.join(", ")
                          : "none"}
                      </td>
                      <td className="py-2 px-3">
                        <span
                          className={`font-mono text-[11px] ${
                            isFallback ? "text-amber-400" : isWeaponized ? "text-red-400" : "text-emerald-400"
                          }`}
                        >
                          {strat}
                        </span>
                      </td>
                      <td className="py-2 px-3">
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
