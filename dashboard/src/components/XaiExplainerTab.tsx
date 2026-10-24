import React from "react";
import { DemoDataset, SessionReport } from "../types";

interface Props {
  dataset: DemoDataset | null;
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
}

export const XaiExplainerTab: React.FC<Props> = ({
  dataset,
  selectedSessionId,
  onSelectSession,
}) => {
  const sessions = dataset?.sessions || [];
  const activeSession: SessionReport | undefined =
    sessions.find((s) => s.session_id === selectedSessionId) || sessions[0];

  const prediction = activeSession?.module3_prediction;
  const classification = prediction?.classification;
  const intent = prediction?.intent;
  const shap = prediction?.shap_explanation;
  const deviations = prediction?.explanations || [];

  return (
    <div className="space-y-6">
      {/* Session Quick Selector Header */}
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

      {/* Model Outputs Side-by-Side: Binary vs Intent */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Output A: Binary Weaponization */}
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

            {/* Confidence Gauge Bar */}
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

        {/* Output B: Multi-Label Attacker Intent */}
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

            {/* Intent Probability Bars */}
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

      {/* Local Explainability: SHAP Feature Attributions */}
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

        {/* SHAP Contribution Bars */}
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

                {/* Dual-direction visual bar */}
                <div className="grid grid-cols-2 gap-1 bg-slate-900 h-3 rounded-full overflow-hidden p-0.5">
                  {/* Left (Negative / Opposes) */}
                  <div className="flex justify-end">
                    {!isPositive && (
                      <div
                        className="bg-gradient-to-l from-cyan-400 to-blue-600 h-full rounded-l-full"
                        style={{ width: `${absVal}%` }}
                      ></div>
                    )}
                  </div>
                  {/* Right (Positive / Supports) */}
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

      {/* Feature Baseline Deviation Table */}
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
