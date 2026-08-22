"use client";

import React from "react";

interface BrandImpersonationPanelProps {
  claimedBrand?: string;
  impersonationDetected?: boolean;
  confidence?: number;
  evidence?: string[];
  legitimateDomains?: string[];
  officialSupportUrl?: string;
}

export default function BrandImpersonationPanel({
  claimedBrand = "State Bank of India",
  impersonationDetected = true,
  confidence = 0.96,
  evidence = ["Malicious lookalike domain detected: 'sbi-kyc-update.xyz' (impersonating State Bank of India)."],
  legitimateDomains = ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
  officialSupportUrl = "https://onlinesbi.sbi",
}: BrandImpersonationPanelProps) {
  if (!claimedBrand) return null;

  return (
    <div className="bg-[#0b101d] border border-cyan-900/40 rounded-2xl p-5 shadow-xl font-sans space-y-4">
      <div className="flex items-center justify-between border-b border-cyan-900/30 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-cyan-400 font-mono text-xs">🏛️ BRAND REGISTRY</span>
          <h3 className="text-sm font-bold text-slate-100 tracking-wide uppercase">
            Brand & Government Impersonation Telemetry
          </h3>
        </div>

        <span
          className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase tracking-wider border ${
            impersonationDetected
              ? "bg-rose-950/80 text-rose-300 border-rose-800/60"
              : "bg-emerald-950/80 text-emerald-300 border-emerald-800/60"
          }`}
        >
          {impersonationDetected ? "● IMPERSONATION DETECTED" : "✓ VERIFIED OFFICIAL BRAND"}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Claimed Brand & Forensic Findings */}
        <div className="bg-[#070c18] border border-slate-800 rounded-xl p-4 space-y-3">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase">Target Organization</span>
            <h4 className="text-base font-bold text-white tracking-tight">{claimedBrand}</h4>
          </div>

          <div className="space-y-2">
            <span className="text-[10px] font-mono text-slate-400 uppercase">Forensic Evidence:</span>
            {evidence.map((ev, i) => (
              <div key={i} className="text-xs text-rose-300 bg-rose-950/30 border border-rose-900/30 p-2.5 rounded-lg flex items-start gap-2">
                <span className="text-rose-400">⚠️</span>
                <span>{ev}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Verified Official Reference Guidance */}
        <div className="bg-[#070c18] border border-slate-800 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-emerald-400 uppercase font-semibold">
              Verified Official Reference Information
            </span>
            <span className="text-[10px] font-mono text-slate-500">Registry v1.0</span>
          </div>

          <div className="space-y-2">
            <span className="text-xs text-slate-400 block">Verified Official Domains:</span>
            <div className="flex flex-wrap gap-1.5 font-mono text-xs">
              {legitimateDomains.map((dom, i) => (
                <span key={i} className="px-2.5 py-1 rounded bg-slate-900 text-emerald-300 border border-emerald-900/50">
                  {dom}
                </span>
              ))}
            </div>
          </div>

          {officialSupportUrl && (
            <div className="pt-2">
              <a
                href={officialSupportUrl}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 text-xs font-mono text-cyan-400 hover:text-cyan-300 underline"
              >
                <span>Official Support Portal ↗</span>
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
