"use client";

import React, { useState, useEffect } from "react";
import { AnalyzeResponse } from "@/types/api";

interface Props {
  analysis: AnalyzeResponse;
}

const STAGES = [
  { id: 1, title: "1. Raw Obfuscation", subtitle: "What arrived on the device" },
  { id: 2, title: "2. Normalized Text", subtitle: "De-cloaked phonetics & leetspeak" },
  { id: 3, title: "3. Decoded Meaning", subtitle: "Attacker's true objective" },
  { id: 4, title: "4. Manipulation Pressures", subtitle: "Psychological triggers" },
  { id: 5, title: "5. Threat Verdict", subtitle: "Final threat category" },
];

export default function AttackerRevealStage({ analysis }: Props) {
  const [currentStage, setCurrentStage] = useState(1);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isPlaying) {
      timer = setInterval(() => {
        setCurrentStage((prev) => {
          if (prev >= 5) {
            setIsPlaying(false);
            return 5;
          }
          return prev + 1;
        });
      }, 2000);
    }
    return () => clearInterval(timer);
  }, [isPlaying]);

  const handlePlay = () => {
    setCurrentStage(1);
    setIsPlaying(true);
  };

  return (
    <div className="bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 border border-indigo-800/40 rounded-2xl p-6 text-white shadow-xl relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute -top-24 -right-24 w-64 h-64 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 border-b border-indigo-800/30 pb-4">
        <div>
          <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400 font-mono">
            Signature Forensic Inspection
          </span>
          <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2 mt-0.5">
            <span>🔍</span> &ldquo;Show me what the attacker tried to hide&rdquo;
          </h3>
        </div>

        <button
          onClick={handlePlay}
          disabled={isPlaying}
          className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white transition-all shadow-lg shadow-indigo-600/30 cursor-pointer"
        >
          <span>{isPlaying ? "▶ Reconstructing..." : "↺ Play Stepped Reveal"}</span>
        </button>
      </div>

      {/* Stage Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 mb-6">
        {STAGES.map((s) => (
          <button
            key={s.id}
            onClick={() => {
              setIsPlaying(false);
              setCurrentStage(s.id);
            }}
            className={`p-2.5 rounded-xl text-left border transition-all text-xs ${
              currentStage === s.id
                ? "bg-indigo-900/60 border-indigo-400 text-white shadow-md shadow-indigo-500/20"
                : "bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700"
            }`}
          >
            <div className="font-semibold text-slate-200">{s.title}</div>
            <div className="text-[10px] text-slate-400 truncate mt-0.5">{s.subtitle}</div>
          </button>
        ))}
      </div>

      {/* Interactive Display Area */}
      <div className="bg-slate-950/80 rounded-xl p-5 border border-indigo-900/50 min-h-[160px] flex flex-col justify-center transition-all duration-300">
        {currentStage === 1 && (
          <div className="space-y-2 animate-fadeIn">
            <div className="flex items-center gap-2 text-xs font-mono text-amber-400">
              <span>●</span> Raw Carrier SMS with Obfuscations
            </div>
            <p className="font-mono text-sm sm:text-base text-slate-200 bg-slate-900/90 p-4 rounded-lg border border-slate-800 break-words select-all">
              {analysis.original_text}
            </p>
            {analysis.obfuscation_fingerprint.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {analysis.obfuscation_fingerprint.map((ob, idx) => (
                  <span key={idx} className="text-[11px] font-mono px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40">
                    {ob}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {currentStage === 2 && (
          <div className="space-y-2 animate-fadeIn">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <span>●</span> De-cloaked & Normalized Script Representation
            </div>
            <p className="font-mono text-sm sm:text-base text-cyan-100 bg-cyan-950/30 p-4 rounded-lg border border-cyan-800/40 break-words">
              {analysis.normalized_text}
            </p>
            <span className="text-xs text-slate-400 inline-block">
              Language detected: <strong className="uppercase text-slate-200">{analysis.language}</strong>
            </span>
          </div>
        )}

        {currentStage === 3 && (
          <div className="space-y-2 animate-fadeIn">
            <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
              <span>●</span> Plain-Language Attacker Objective
            </div>
            <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-emerald-100 text-sm sm:text-base leading-relaxed">
              {analysis.decoded_meaning}
            </div>
          </div>
        )}

        {currentStage === 4 && (
          <div className="space-y-2 animate-fadeIn">
            <div className="flex items-center gap-2 text-xs font-mono text-rose-400">
              <span>●</span> Pressure Mechanisms Activated
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Fear Threat</span>
                <span className="text-base font-bold text-rose-400">{Math.round(analysis.manipulation_fingerprint.fear * 100)}%</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Urgency Pressure</span>
                <span className="text-base font-bold text-amber-400">{Math.round(analysis.manipulation_fingerprint.urgency * 100)}%</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Impersonation</span>
                <span className="text-base font-bold text-indigo-400">{Math.round(analysis.manipulation_fingerprint.authority_impersonation * 100)}%</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Credential Risk</span>
                <span className="text-base font-bold text-purple-400">{Math.round(analysis.manipulation_fingerprint.credential_request * 100)}%</span>
              </div>
            </div>
          </div>
        )}

        {currentStage === 5 && (
          <div className="space-y-3 animate-fadeIn text-center sm:text-left">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span className="text-xs font-mono text-indigo-300">● Threat Classification Verdict</span>
              <span className="text-xs font-mono text-slate-400">ID: {analysis.analysis_id.slice(0, 8)}...</span>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <span className="px-4 py-1.5 rounded-xl font-mono font-bold text-sm bg-rose-500/20 text-rose-300 border border-rose-500/40">
                {analysis.scam_family}
              </span>
              <span className="px-3 py-1.5 rounded-xl font-mono text-xs bg-slate-800 text-slate-300 border border-slate-700">
                Risk Tier: <strong className="text-white">{analysis.risk_level}</strong>
              </span>
              <span className="px-3 py-1.5 rounded-xl font-mono text-xs bg-slate-800 text-slate-300 border border-slate-700">
                Risk Score: <strong className="text-white">{analysis.risk_score}/100</strong>
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
