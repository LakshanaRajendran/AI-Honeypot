import React, { useEffect, useState } from "react";
import { DemoDataset, SystemHealth } from "./types";
import { OverviewTab } from "./components/OverviewTab";
import { InteractiveDemoTab } from "./components/InteractiveDemoTab";
import { SessionExplorerTab } from "./components/SessionExplorerTab";
import { XaiExplainerTab } from "./components/XaiExplainerTab";
import { DecisionEngineTab } from "./components/DecisionEngineTab";
import { TelemetryFlowTab } from "./components/TelemetryFlowTab";
import { TechnicalDocsTab } from "./components/TechnicalDocsTab";
import { RoadmapTab } from "./components/RoadmapTab";
import { SystemHealthTab } from "./components/SystemHealthTab";

export type TabKey =
  | "overview"
  | "interactive-demo"
  | "session-explorer"
  | "xai-explainer"
  | "decision-engine"
  | "telemetry-flow"
  | "technical-docs"
  | "roadmap"
  | "system-health";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [dataset, setDataset] = useState<DemoDataset | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Fetch initial data & health
  const refreshData = async () => {
    try {
      const [healthRes, dataRes] = await Promise.all([
        fetch("/api/status"),
        fetch("/api/data"),
      ]);

      if (healthRes.ok) {
        const hData: SystemHealth = await healthRes.json();
        setHealth(hData);
      }

      if (dataRes.ok) {
        const dData: DemoDataset = await dataRes.json();
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
    } catch (err: any) {
      console.error("Run demo error:", err);
      setErrorMsg(err.message || "Pipeline execution encountered an error.");
    } finally {
      setIsRunning(false);
    }
  };

  const handleSelectScenario = (scenario: "reconnaissance" | "suspicious" | "fallback") => {
    if (!dataset?.sessions) return;

    let targetSess: any = null;
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

  const handleSelectSessionAndInspect = (sessionId: string) => {
    setSelectedSessionId(sessionId);
    setActiveTab("session-explorer");
  };

  const navItems = [
    { key: "overview" as TabKey, label: "Executive Overview", badge: null },
    { key: "interactive-demo" as TabKey, label: "Live Demo Runner", badge: "Action" },
    { key: "session-explorer" as TabKey, label: "Session Explorer", badge: dataset?.sessions?.length || "11" },
    { key: "xai-explainer" as TabKey, label: "AI & XAI Engine", badge: "SHAP" },
    { key: "decision-engine" as TabKey, label: "Adaptive Decisions", badge: "Rules" },
    { key: "telemetry-flow" as TabKey, label: "Data Flow & Mesh", badge: null },
    { key: "technical-docs" as TabKey, label: "Technical Docs", badge: "Guide" },
    { key: "roadmap" as TabKey, label: "Real-Time Roadmap", badge: "Future" },
    { key: "system-health" as TabKey, label: "System Health & Audit", badge: health?.status || "OK" },
  ];

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      {/* Top SOC Bar */}
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

        {/* Navigation Tabs Bar */}
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

      {/* Main Operations Container */}
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

        {/* Tab Views */}
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

      {/* Operations Footer */}
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
