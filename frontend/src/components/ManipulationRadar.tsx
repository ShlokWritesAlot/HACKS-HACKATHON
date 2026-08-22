"use client";

import React from "react";
import { ManipulationFingerprint } from "@/types/api";

interface Props {
  fingerprint: ManipulationFingerprint;
}

interface Dimension {
  key: keyof ManipulationFingerprint;
  label: string;
  description: string;
  icon: string;
}

const DIMENSIONS: Dimension[] = [
  { key: "fear", label: "Fear & Threats", description: "Account block, legal action, arrest", icon: "🛡️" },
  { key: "urgency", label: "Artificial Urgency", description: "Expires today, immediate action required", icon: "⏱️" },
  { key: "authority_impersonation", label: "Impersonation", description: "Pretending to be Bank, Police, Govt, Courier", icon: "🏛️" },
  { key: "credential_request", label: "Credential Harvesting", description: "Requesting OTP, PIN, password, or CVV", icon: "🔑" },
  { key: "financial_request", label: "Financial Demand", description: "Direct request for payment, fee, or deposit", icon: "💳" },
  { key: "suspicious_link", label: "Unverified Link", description: "Shortened, unverified, or masked URL", icon: "🔗" },
  { key: "call_to_action_pressure", label: "Direct Action Pressure", description: "Forced call, click, or APK install", icon: "⚡" },
];

export default function ManipulationRadar({ fingerprint }: Props) {
  const getBarColor = (val: number) => {
    if (val >= 0.7) return "bg-rose-500 shadow-rose-500/30";
    if (val >= 0.4) return "bg-amber-500 shadow-amber-500/30";
    return "bg-slate-300 dark:bg-slate-700";
  };

  const getBadgeColor = (val: number) => {
    if (val >= 0.7) return "text-rose-600 bg-rose-50 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800";
    if (val >= 0.4) return "text-amber-600 bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800";
    return "text-slate-500 bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700";
  };

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <span>🧠</span> Manipulation Fingerprint
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Psychological pressure vectors detected in the message
          </p>
        </div>
      </div>

      <div className="space-y-4">
        {DIMENSIONS.map((dim) => {
          const value = fingerprint[dim.key] ?? 0;
          const percentage = Math.round(value * 100);

          return (
            <div key={dim.key} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 font-medium text-slate-700 dark:text-slate-300">
                  <span>{dim.icon}</span>
                  <span>{dim.label}</span>
                </div>
                <span className={`px-2 py-0.5 rounded-full text-xs font-mono font-semibold border ${getBadgeColor(value)}`}>
                  {percentage}%
                </span>
              </div>

              <div className="h-2 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ease-out ${getBarColor(value)}`}
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
