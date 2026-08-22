"use client";

import React from "react";

interface CampaignDNAPanelProps {
  campaignId?: string;
  dnaHash?: string;
  confidence?: number;
  family?: string;
  memberCount?: number;
}

export default function CampaignDNAPanel({
  campaignId = "132fa723-5b49-4faf-9673-390091c783c1",
  dnaHash = "dna_3434510ce7b7391a",
  confidence = 1.0,
  family = "BANK_KYC",
  memberCount = 1,
}: CampaignDNAPanelProps) {
  return (
    <div className="bg-[#0b101d] border border-cyan-900/40 rounded-2xl p-5 shadow-xl font-sans space-y-4">
      <div className="flex items-center justify-between border-b border-cyan-900/30 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-cyan-400 font-mono text-xs">🧬 SCAM DNA</span>
          <h3 className="text-sm font-bold text-slate-100 tracking-wide uppercase">
            Semantic Campaign Fingerprinting & Intelligence
          </h3>
        </div>

        <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800/60 uppercase">
          16-Dim Fingerprint Active
        </span>
      </div>

      {/* Campaign Details Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
        <div className="bg-[#070c18] border border-slate-800 rounded-xl p-3">
          <span className="text-[10px] text-slate-500 uppercase block">Campaign ID</span>
          <span className="text-slate-200 font-bold text-[11px] truncate block">{campaignId}</span>
        </div>

        <div className="bg-[#070c18] border border-slate-800 rounded-xl p-3">
          <span className="text-[10px] text-slate-500 uppercase block">DNA Hash</span>
          <span className="text-cyan-400 font-bold text-[11px] block">{dnaHash}</span>
        </div>

        <div className="bg-[#070c18] border border-slate-800 rounded-xl p-3">
          <span className="text-[10px] text-slate-500 uppercase block">Scam Archetype</span>
          <span className="text-amber-400 font-bold text-[11px] block">{family}</span>
        </div>

        <div className="bg-[#070c18] border border-slate-800 rounded-xl p-3">
          <span className="text-[10px] text-slate-500 uppercase block">Cluster Association</span>
          <span className="text-emerald-400 font-bold text-[11px] block">
            {(confidence * 100).toFixed(0)}% ({memberCount} msg{memberCount > 1 ? "s" : ""})
          </span>
        </div>
      </div>

      {/* Node Relationship Diagram */}
      <div className="bg-[#070c18] border border-slate-800/80 rounded-xl p-4 text-center space-y-3 font-mono text-xs">
        <span className="text-[10px] text-slate-500 uppercase font-semibold tracking-wider block">
          Structural Entity & Threat Topology Graph
        </span>

        <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-4 pt-2">
          <div className="px-3 py-2 rounded-xl bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 text-[11px] font-bold shadow-md">
            [CAMPAIGN CLUSTER]
          </div>

          <span className="text-slate-600">➔</span>

          <div className="px-3 py-2 rounded-xl bg-amber-950/60 border border-amber-800/50 text-amber-300 text-[11px] font-bold shadow-md">
            [SCAM DNA: {dnaHash.slice(0, 10)}]
          </div>

          <span className="text-slate-600">➔</span>

          <div className="px-3 py-2 rounded-xl bg-rose-950/60 border border-rose-800/50 text-rose-300 text-[11px] font-bold shadow-md">
            [IOC: SENDER + URL]
          </div>
        </div>
      </div>
    </div>
  );
}
