import React from "react";
import { SystemHealth } from "../types";

interface Props {
  health: SystemHealth | null;
}

export const SystemHealthTab: React.FC<Props> = ({ health }) => {
  return (
    <div className="space-y-6">
      {/* Health Status Top Banner */}
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

        {/* Export Data Actions */}
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

      {/* Artifact SHA-256 Signatures Table */}
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

      {/* Security Safeguards Checklist & Log Verification */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Security Checklist */}
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

        {/* Cowrie Logs Source Status */}
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

      {/* Honest Limitations & Disclosures */}
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
