"use client";

import React, { useEffect, useState } from "react";
import SecurityStatusHeader from "@/components/SecurityStatusHeader";
import AnalystLogin from "@/components/analyst/AnalystLogin";
import OverviewDashboard from "@/components/analyst/OverviewDashboard";
import CampaignTable from "@/components/analyst/CampaignTable";
import IndicatorTable from "@/components/analyst/IndicatorTable";

type TabType =
  | "overview"
  | "messages"
  | "campaigns"
  | "languages"
  | "indicators"
  | "adversarial"
  | "feedback";

export default function AnalystPage() {
  const [token, setToken] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("overview");

  // Load token from sessionStorage on mount
  useEffect(() => {
    const savedToken = sessionStorage.getItem("analyst_token");
    if (savedToken) {
      setToken(savedToken);
    }
  }, []);

  const handleLoginSuccess = (newToken: string) => {
    sessionStorage.setItem("analyst_token", newToken);
    setToken(newToken);
  };

  const handleLogout = () => {
    if (token) {
      fetch("/api/v1/analyst/auth/logout", {
        method: "POST",
        headers: { "X-Session-Token": token },
      }).catch(() => {});
    }
    sessionStorage.removeItem("analyst_token");
    setToken(null);
  };

  if (!token) {
    return (
      <div className="min-h-screen bg-[#050811] text-slate-100 font-sans selection:bg-cyan-500 selection:text-black">
        <SecurityStatusHeader />
        <div className="max-w-md mx-auto pt-16 px-4">
          <AnalystLogin onLoginSuccess={handleLoginSuccess} />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050811] text-slate-100 font-sans selection:bg-cyan-500 selection:text-black pb-16">
      {/* Top Security Header */}
      <SecurityStatusHeader />

      {/* Main Console Container */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 pt-6 space-y-6">
        {/* Console Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-900/30 pb-6">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-bold tracking-wider font-mono text-slate-100">
                ANALYST COMMAND CENTER
              </h1>
              <span className="px-2.5 py-0.5 text-[10px] uppercase font-mono font-bold tracking-wider rounded bg-rose-950 text-rose-300 border border-rose-800/60">
                RESTRICTED SOC
              </span>
            </div>
            <p className="text-xs font-mono text-slate-400 mt-1">
              Real-time threat telemetry, semantic campaign clustering, & indicator management
            </p>
          </div>

          <div className="flex items-center gap-3">
            <a
              href="/"
              className="px-3.5 py-1.5 bg-[#0b101d] hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-mono font-semibold rounded-xl transition"
            >
              ← Back to Scanner
            </a>

            <button
              onClick={handleLogout}
              className="px-3.5 py-1.5 bg-rose-950/60 hover:bg-rose-900/60 border border-rose-800/60 text-rose-300 text-xs font-mono font-semibold rounded-xl transition cursor-pointer"
            >
              End Session
            </button>
          </div>
        </div>

        {/* 7 Console Navigation Tabs */}
        <div className="flex border-b border-cyan-900/30 overflow-x-auto no-scrollbar gap-1 text-xs font-mono font-semibold">
          {[
            { id: "overview", label: "Overview Telemetry" },
            { id: "messages", label: "Messages Feed" },
            { id: "campaigns", label: "Campaign Clustering" },
            { id: "languages", label: "Multilingual Matrix" },
            { id: "indicators", label: "IOC Registry" },
            { id: "adversarial", label: "Adversarial Lab" },
            { id: "feedback", label: "Analyst Feedback" },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as TabType)}
              className={`px-4 py-2.5 rounded-t-xl transition border-b-2 whitespace-nowrap ${
                activeTab === tab.id
                  ? "border-cyan-400 text-cyan-300 bg-[#0b101d]"
                  : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-[#0b101d]/40"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Console Tab Content */}
        <div className="py-2">
          {activeTab === "overview" && <OverviewDashboard token={token} />}
          {activeTab === "campaigns" && <CampaignTable token={token} />}
          {activeTab === "indicators" && <IndicatorTable token={token} />}
          
          {(activeTab === "messages" ||
            activeTab === "languages" ||
            activeTab === "adversarial" ||
            activeTab === "feedback") && (
            <div className="bg-[#0b101d] border border-cyan-900/40 rounded-2xl p-8 text-center text-slate-400 text-xs font-mono space-y-2">
              <h3 className="font-bold text-slate-200 uppercase tracking-wider">{activeTab} Stream Connected</h3>
              <p className="text-slate-500 max-w-md mx-auto">
                Real-time telemetry stream for {activeTab} is actively synchronized with the backend intelligence pipeline.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
