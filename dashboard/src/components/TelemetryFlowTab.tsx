import React from "react";

export const TelemetryFlowTab: React.FC = () => {
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

      {/* Visual Pipeline Flow */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Module 1 */}
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

        {/* Module 2 */}
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

        {/* Module 3 */}
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

        {/* Module 4 */}
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

        {/* Execution Adapter */}
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

        {/* Dashboard */}
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
