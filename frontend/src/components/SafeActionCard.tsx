"use client";

import React from "react";

interface Props {
  action: string;
  riskScore: number;
}

export default function SafeActionCard({ action, riskScore }: Props) {
  const isHighRisk = riskScore >= 60;

  return (
    <div
      className={`rounded-2xl p-6 border shadow-sm transition-all ${
        isHighRisk
          ? "bg-rose-50/50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/50"
          : "bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/50"
      }`}
    >
      <div className="flex items-start gap-4">
        <div
          className={`p-3 rounded-xl text-xl flex items-center justify-center ${
            isHighRisk
              ? "bg-rose-100 dark:bg-rose-900/50 text-rose-600 dark:text-rose-300"
              : "bg-emerald-100 dark:bg-emerald-900/50 text-emerald-600 dark:text-emerald-300"
          }`}
        >
          {isHighRisk ? "🛑" : "🛡️"}
        </div>

        <div className="space-y-1.5 flex-1">
          <div className="flex items-center justify-between">
            <span
              className={`text-xs font-bold font-mono uppercase tracking-wider ${
                isHighRisk ? "text-rose-600 dark:text-rose-400" : "text-emerald-600 dark:text-emerald-400"
              }`}
            >
              Recommended Safety Action
            </span>
          </div>

          <p className="text-sm sm:text-base font-semibold text-slate-900 dark:text-slate-100 leading-snug">
            {action}
          </p>

          <div className="text-xs text-slate-600 dark:text-slate-400 pt-1 space-y-1">
            <div className="flex items-center gap-1.5">
              <span>✓</span> Always open official mobile banking or agency applications directly.
            </div>
            <div className="flex items-center gap-1.5">
              <span>✕</span> Never dial telephone numbers or click links contained inside suspicious messages.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
