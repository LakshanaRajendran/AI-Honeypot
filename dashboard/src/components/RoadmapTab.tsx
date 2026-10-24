import React from "react";

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

export const RoadmapTab: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Overview Banner */}
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

      {/* Comparison: Current vs Production */}
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
              <span className="text-emerald-400">✓</span>
              <span><strong>Data Source:</strong> Historical Cowrie JSONL log files (5 files, 42 commands).</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400">✓</span>
              <span><strong>Timing:</strong> Post-session batch aggregation across complete sessions.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400">✓</span>
              <span><strong>Inference:</strong> Scikit-learn Random Forest + SHAP TreeExplainer in Python.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400">✓</span>
              <span><strong>Execution:</strong> Simulation-only adapter; zero live modifications applied.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400">✓</span>
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
              <span className="text-indigo-400">→</span>
              <span><strong>Data Source:</strong> Real-time Kafka event streams correlated with eBPF cgroups.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-indigo-400">→</span>
              <span><strong>Timing:</strong> 30-second sliding temporal feature windows for mid-session adaptation.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-indigo-400">→</span>
              <span><strong>Inference:</strong> Low-latency Triton/ONNX microservices (&lt;10ms latency).</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-indigo-400">→</span>
              <span><strong>Execution:</strong> Dynamic synthetic filesystem &amp; decoy delivery via SDN.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-indigo-400">→</span>
              <span><strong>Containment:</strong> Ephemeral Firecracker micro-VMs with automated egress kill-switches.</span>
            </li>
          </ul>
        </div>
      </div>

      {/* 7 Engineering Pillars */}
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
