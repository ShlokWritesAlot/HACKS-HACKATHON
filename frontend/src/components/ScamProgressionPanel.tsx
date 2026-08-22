"use client";

import React, { useState } from "react";

const STAGES = [
  { id: "CONTACT", label: "Contact", icon: "💬" },
  { id: "TRUST_BUILDING", label: "Trust Building", icon: "🤝" },
  { id: "AUTHORITY_CLAIM", label: "Authority Claim", icon: "🏛️" },
  { id: "FEAR_OR_URGENCY", label: "Fear / Urgency", icon: "⚠️" },
  { id: "CREDENTIAL_REQUEST", label: "Credential Request", icon: "🔑" },
  { id: "PAYMENT_REQUEST", label: "Payment Request", icon: "💳" },
  { id: "REMOTE_ACCESS", label: "Remote Access", icon: "📲" },
  { id: "ACCOUNT_TAKEOVER", label: "Account Takeover", icon: "🔓" },
  { id: "EXIT", label: "Exit", icon: "🚪" },
];

interface ScamProgressionPanelProps {
  currentState?: string;
  likelyNextAction?: string;
  probability?: number;
  uncertainty?: number;
  reasoning?: string;
}

export default function ScamProgressionPanel({
  currentState = "FEAR_OR_URGENCY",
  likelyNextAction = "REQUEST_OTP",
  probability = 0.72,
  uncertainty = 0.28,
  reasoning = "Likely next step: the attacker may request a one-time password (OTP) under the pretense of account verification or KYC.",
}: ScamProgressionPanelProps) {
  const [expanded, setExpanded] = useState(false);

  const activeIndex = STAGES.findIndex((s) => s.id === currentState);

  return (
    <div className="bg-[#0b101d] border border-cyan-900/40 rounded-2xl p-5 shadow-xl font-sans relative overflow-hidden">
      <div className="flex items-center justify-between border-b border-cyan-900/30 pb-3 mb-4">
        <div className="flex items-center gap-2">
          <span className="text-cyan-400 font-mono text-xs">● STATE MACHINE</span>
          <h3 className="text-sm font-bold text-slate-100 tracking-wide uppercase">
            Scam Lifecycle Progression
          </h3>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 transition"
        >
          {expanded ? "[- Collapse]" : "[+ Expand Telemetry]"}
        </button>
      </div>

      {/* 9-Stage Pipeline Track */}
      <div className="grid grid-cols-3 sm:grid-cols-5 md:grid-cols-9 gap-1.5 mb-5">
        {STAGES.map((stage, idx) => {
          const isCurrent = stage.id === currentState;
          const isPassed = activeIndex >= 0 && idx < activeIndex;

          return (
            <div
              key={stage.id}
              className={`p-2 rounded-xl border text-center transition-all flex flex-col items-center justify-center min-h-[64px] ${
                isCurrent
                  ? "bg-rose-950/60 border-rose-500/80 text-rose-300 ring-2 ring-rose-500/30 shadow-lg shadow-rose-900/20"
                  : isPassed
                  ? "bg-amber-950/40 border-amber-500/40 text-amber-300 opacity-90"
                  : "bg-slate-950/60 border-slate-800/80 text-slate-500 opacity-60"
              }`}
            >
              <span className="text-xs mb-0.5">{stage.icon}</span>
              <span className="text-[9px] font-mono font-bold leading-tight uppercase tracking-tighter">
                {stage.label}
              </span>
              {isCurrent && (
                <span className="mt-1 w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping"></span>
              )}
            </div>
          );
        })}
      </div>

      {/* Likely Next Attacker Action Prediction */}
      <div className="bg-[#070c18] border border-cyan-900/30 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/40">
              Probabilistic Prediction
            </span>
            <span className="text-xs font-mono text-slate-400">
              Confidence: <strong className="text-cyan-400">{(probability * 100).toFixed(0)}%</strong> (Uncertainty: {(uncertainty * 100).toFixed(0)}%)
            </span>
          </div>
          <h4 className="text-sm font-bold text-slate-100 font-mono">
            ESTIMATED NEXT ACTION: <span className="text-rose-400">{likelyNextAction.replace(/_/g, " ")}</span>
          </h4>
          <p className="text-xs text-slate-400 max-w-xl">
            {reasoning}
          </p>
        </div>

        <div className="flex sm:flex-col items-center justify-center px-4 py-2 bg-slate-950 rounded-xl border border-slate-800 text-center min-w-[120px]">
          <span className="text-xl font-extrabold font-mono text-cyan-400">
            {(probability * 100).toFixed(0)}%
          </span>
          <span className="text-[9px] font-mono text-slate-500 uppercase">
            Est. Probability
          </span>
        </div>
      </div>
    </div>
  );
}
