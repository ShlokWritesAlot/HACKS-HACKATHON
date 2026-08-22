"use client";

import React from "react";

export default function SecurityStatusHeader() {
  return (
    <div className="bg-[#070c18]/90 border-b border-cyan-900/30 px-4 py-2 text-xs font-mono flex flex-wrap items-center justify-between gap-3 backdrop-blur-md">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-emerald-400 font-bold tracking-wider uppercase text-[11px]">
            SYSTEM STATUS: OPERATIONAL
          </span>
        </div>

        <span className="text-slate-700">|</span>

        <span className="text-slate-400 text-[11px]">
          NODE: <span className="text-cyan-400 font-semibold">IN-DELHI-01</span>
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[10px]">
        <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/40 flex items-center gap-1">
          <span className="text-emerald-400">✓</span> SSRF PROTECTION
        </span>
        <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/40 flex items-center gap-1">
          <span className="text-emerald-400">✓</span> PROMPT INJECTION DEFENSE
        </span>
        <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/40 flex items-center gap-1 hidden md:inline-flex">
          <span className="text-emerald-400">✓</span> FILE VALIDATION
        </span>
        <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/40 flex items-center gap-1 hidden lg:inline-flex">
          <span className="text-emerald-400">✓</span> PRIVATE DATA MASKING
        </span>
      </div>
    </div>
  );
}
