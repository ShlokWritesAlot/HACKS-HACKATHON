"use client";

import React from "react";

interface Props {
  evidence: string[];
}

export default function EvidenceList({ evidence }: Props) {
  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
      <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2 mb-1">
        <span>🔎</span> Extracted Evidence & IOCs
      </h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
        Verifiable elements observed directly in the message
      </p>

      {evidence.length === 0 ? (
        <p className="text-xs text-slate-400 italic">No concrete indicators or links identified.</p>
      ) : (
        <ul className="space-y-2.5">
          {evidence.map((item, idx) => (
            <li
              key={idx}
              className="flex items-start gap-2.5 text-xs text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-800/50 p-3 rounded-xl border border-slate-200 dark:border-slate-700/60 break-words"
            >
              <span className="text-indigo-500 font-bold mt-0.5">▪</span>
              <span className="leading-relaxed">{item}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
