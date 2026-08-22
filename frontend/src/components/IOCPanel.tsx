"use client";

import React, { useState } from "react";

interface IOCItem {
  type: string;
  value: str;
  confidence: number;
  ssrf_risk?: string;
  is_suspicious?: boolean;
}

interface IOCPanelProps {
  indicators?: IOCItem[];
}

export default function IOCPanel({ indicators = [] }: IOCPanelProps) {
  const [activeTab, setActiveTab] = useState<string>("ALL");

  const categories = ["ALL", "URL", "DOMAIN", "IP_ADDRESS", "PHONE_NUMBER", "EMAIL", "UPI_ID", "SENDER_ID"];

  const filtered = activeTab === "ALL"
    ? indicators
    : indicators.filter((i) => (i.type || "").toUpperCase() === activeTab);

  return (
    <div className="bg-[#0b101d] border border-cyan-900/40 rounded-2xl p-5 shadow-xl font-sans space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyan-900/30 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-cyan-400 font-mono text-xs">🔍 IOC FORENSICS</span>
          <h3 className="text-sm font-bold text-slate-100 tracking-wide uppercase">
            Extracted Indicators of Compromise
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          Total Detected: <strong className="text-cyan-400">{indicators.length}</strong>
        </span>
      </div>

      {/* Category Tabs */}
      <div className="flex overflow-x-auto no-scrollbar gap-1.5 border-b border-slate-800 pb-2">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setActiveTab(cat)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition whitespace-nowrap ${
              activeTab === cat
                ? "bg-cyan-950 text-cyan-300 border border-cyan-700/60 shadow-md"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/40"
            }`}
          >
            {cat.replace("_", " ")}
          </button>
        ))}
      </div>

      {/* Indicators Grid / Monospace Table */}
      {filtered.length === 0 ? (
        <div className="text-center py-8 text-xs text-slate-500 font-mono bg-[#070c18] rounded-xl border border-slate-800/80">
          No indicators detected in this category.
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((item, idx) => (
            <div
              key={idx}
              className="bg-[#070c18] border border-slate-800 rounded-xl p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs hover:border-cyan-900/50 transition"
            >
              <div className="flex items-center gap-3">
                <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 text-[10px] uppercase font-bold border border-slate-800">
                  {item.type}
                </span>
                <span className="text-slate-200 font-semibold tracking-wide break-all">
                  {item.value}
                </span>
              </div>

              <div className="flex items-center gap-2 self-end sm:self-auto text-[10px]">
                {item.ssrf_risk && (
                  <span
                    className={`px-2 py-0.5 rounded uppercase font-bold border ${
                      item.ssrf_risk === "safe"
                        ? "bg-emerald-950 text-emerald-400 border-emerald-800/50"
                        : "bg-rose-950 text-rose-400 border-rose-800/50"
                    }`}
                  >
                    SSRF: {item.ssrf_risk}
                  </span>
                )}

                <span className="text-slate-500">
                  Conf: <strong className="text-slate-300">{(item.confidence * 100).toFixed(0)}%</strong>
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
