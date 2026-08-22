"use client";

import React, { useState } from "react";
import { apiClient } from "@/lib/api-client";
import { PerturbationType, PlaygroundResponse, RedTeamEvaluationReport } from "@/types/playground";

interface Props {
  onInspectVariant?: (variantText: string) => void;
}

interface PerturbationOption {
  type: PerturbationType;
  label: string;
  desc: string;
  icon: string;
}

const PERTURBATION_OPTIONS: PerturbationOption[] = [
  // Original 10
  { type: "vowel_deletion", label: "Vowel Deletion", desc: "e.g., 'acnt', 'updt'", icon: "✂️" },
  { type: "adjacent_swap", label: "Character Swap", desc: "e.g., 'bnak', 'updtae'", icon: "🔄" },
  { type: "number_substitution", label: "Leetspeak / Numbers", desc: "e.g., 'v3rify', 'upd8'", icon: "🔢" },
  { type: "repeated_chars", label: "Repeated Chars", desc: "e.g., 'uuurgent', 'plzz'", icon: "🔁" },
  { type: "whitespace_manipulation", label: "Whitespace Camouflage", desc: "e.g., 'Youraccount'", icon: "␣" },
  { type: "phonetic_transliteration", label: "Phonetic Transliteration", desc: "e.g., 'khata', 'band'", icon: "🗣️" },
  { type: "hinglish_synthesis", label: "Hinglish Code-Mixing", desc: "Full bilingual synthesis", icon: "🇮🇳" },
  { type: "mixed_scripts", label: "Mixed Devanagari", desc: "e.g., 'बैंक', 'अपडेट'", icon: "✍️" },
  { type: "punctuation_insertion", label: "Punctuation Camouflage", desc: "e.g., 'K.Y.C', 'b_a_n_k'", icon: "🔣" },
  { type: "informal_abbreviations", label: "SMS Abbreviations", desc: "e.g., 'plz', '2day', 'b4'", icon: "💬" },

  // New 9
  { type: "unicode_confusables", label: "Unicode Homoglyphs", desc: "e.g., Cyrillic 'а', 'е', 'о'", icon: "🌐" },
  { type: "zero_width_chars", label: "Zero-Width Chars", desc: "Non-printable separators", icon: "👻" },
  { type: "unicode_normalization", label: "Unicode Normalization", desc: "Decomposition attack", icon: "🧬" },
  { type: "multilingual_switching", label: "Multilingual Switching", desc: "Mid-sentence code-switch", icon: "🔀" },
  { type: "nested_obfuscation", label: "Nested Obfuscation", desc: "Multi-layered mutation", icon: "🧅" },
  { type: "ocr_corruption", label: "OCR Corruption", desc: "e.g., 'rn'→'m', 'l'→'1'", icon: "👁️" },
  { type: "realistic_typos", label: "Realistic QWERTY Typos", desc: "Adjacent key swaps", icon: "⌨️" },
  { type: "domain_obfuscation", label: "Domain Obfuscation", desc: "e.g., 'sbi[.]co[.]in'", icon: "🔗" },
  { type: "sender_id_mutation", label: "Sender ID Mutation", desc: "Header string mutation", icon: "🏷️" },
];

const PRESET_TEMPLATES = [
  {
    title: "Bank KYC Threat",
    text: "Your bank account will be blocked. Update KYC immediately at bit.ly/kyc-sbi",
  },
  {
    title: "Bijli Bill Disconnect",
    text: "Electricity power will be cut tonight at 9:30 PM due to unpaid bill. Call 9876543210 immediately.",
  },
  {
    title: "Courier Detention",
    text: "Your FedEx parcel is detained at customs. Pay pending clearance fee at http://fedex-customs.live",
  },
];

export default function AdversarialPlayground({ onInspectVariant }: Props) {
  const [activeSubTab, setActiveSubTab] = useState<"variants" | "redteam">("variants");
  const [template, setTemplate] = useState(PRESET_TEMPLATES[0].text);
  const [selectedTypes, setSelectedTypes] = useState<PerturbationType[]>(
    PERTURBATION_OPTIONS.map((o) => o.type)
  );
  const [intensity, setIntensity] = useState<"low" | "medium" | "high" | "extreme">("medium");
  const [seed, setSeed] = useState<number>(42);
  const [isLoading, setIsLoading] = useState(false);
  const [report, setReport] = useState<PlaygroundResponse | null>(null);
  const [redteamReport, setRedteamReport] = useState<RedTeamEvaluationReport | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const toggleType = (type: PerturbationType) => {
    setSelectedTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  const selectAll = () => setSelectedTypes(PERTURBATION_OPTIONS.map((o) => o.type));
  const deselectAll = () => setSelectedTypes([]);

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!template.trim() || selectedTypes.length === 0) return;

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await apiClient.post<PlaygroundResponse>("/api/v1/playground/simulate", {
        message: template.trim(),
        perturbations: selectedTypes,
        intensity,
        seed,
      });
      setReport(response);
    } catch (err: any) {
      console.error("Simulation failed:", err);
      setErrorMessage(err.message || "Failed to run simulation. Ensure backend is active.");
      setReport(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunRedTeam = async () => {
    if (!template.trim()) return;

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await apiClient.post<RedTeamEvaluationReport>("/api/v1/playground/redteam", {
        message: template.trim(),
        max_depth: 3,
        seed,
      });
      setRedteamReport(response);
      setActiveSubTab("redteam");
    } catch (err: any) {
      console.error("Red-team evaluation failed:", err);
      setErrorMessage(err.message || "Red-team stress test failed.");
      setRedteamReport(null);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header Banner */}
      <div className="bg-[#0b101d] border border-cyan-900/40 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800/50 uppercase">
                🧪 ADVERSARIAL RED-TEAM ENGINE
              </span>
              <span className="text-[11px] font-mono text-slate-500">19 Perturbations Active</span>
            </div>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight">
              Adversarial Stress Testing & Robustness Profiling
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Test detector resilience against obfuscated, leetspeak, zero-width, homoglyph, and multilingual scam variations.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveSubTab("variants")}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-semibold transition ${
                activeSubTab === "variants"
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-700/60 shadow-md"
                  : "text-slate-400 hover:text-slate-200 bg-slate-900/60"
              }`}
            >
              19-Variant Suite
            </button>

            <button
              onClick={handleRunRedTeam}
              disabled={isLoading}
              className="px-4 py-2 rounded-xl text-xs font-mono font-bold bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-900/30 transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <span>🔥</span>
              <span>RUN ADAPTIVE RED-TEAM</span>
            </button>
          </div>
        </div>
      </div>

      {/* Preset Selectors */}
      <div className="bg-[#0b101d] border border-slate-800 rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <label className="text-xs font-mono text-slate-400 uppercase font-semibold">
            Base Scam Message Template
          </label>
          <div className="flex items-center gap-2">
            {PRESET_TEMPLATES.map((tmpl, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setTemplate(tmpl.text)}
                className="px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 text-[11px] font-mono text-slate-300 border border-slate-800 transition"
              >
                {tmpl.title}
              </button>
            ))}
          </div>
        </div>

        <textarea
          value={template}
          onChange={(e) => setTemplate(e.target.value)}
          rows={3}
          className="w-full p-3.5 rounded-xl bg-[#070c18] border border-slate-800 text-slate-100 placeholder:text-slate-600 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-cyan-500"
        />

        {/* 19 Perturbation Category Toggles */}
        <div className="space-y-2 pt-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 font-semibold uppercase">
              Perturbation Matrix ({selectedTypes.length}/19 Selected)
            </span>
            <div className="flex items-center gap-3">
              <button onClick={selectAll} className="text-cyan-400 hover:underline">Select All</button>
              <button onClick={deselectAll} className="text-slate-500 hover:underline">Clear</button>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
            {PERTURBATION_OPTIONS.map((opt) => {
              const isSel = selectedTypes.includes(opt.type);
              return (
                <button
                  key={opt.type}
                  type="button"
                  onClick={() => toggleType(opt.type)}
                  className={`p-2.5 rounded-xl border text-left transition flex items-center justify-between ${
                    isSel
                      ? "bg-cyan-950/40 border-cyan-800/60 text-cyan-300 shadow-md"
                      : "bg-[#070c18] border-slate-800/80 text-slate-500 opacity-70"
                  }`}
                >
                  <div className="truncate">
                    <span className="text-xs mr-1">{opt.icon}</span>
                    <span className="text-[11px] font-mono font-semibold">{opt.label}</span>
                  </div>
                  <span className="text-[10px]">{isSel ? "✓" : "+"}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            onClick={handleSimulate}
            disabled={isLoading || selectedTypes.length === 0}
            className="px-6 py-2.5 rounded-xl font-mono text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-600/20 transition disabled:opacity-50 cursor-pointer"
          >
            {isLoading ? "Running Simulations..." : "Generate 19 Variants & Stress-Test"}
          </button>
        </div>
      </div>

      {/* Error View */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs">
          ⚠️ {errorMessage}
        </div>
      )}

      {/* 19-Variant Evaluation Results */}
      {activeSubTab === "variants" && report && (
        <div className="space-y-4">
          {/* Robustness Summary Card */}
          <div className="bg-[#0b101d] border border-cyan-900/40 rounded-2xl p-5 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div>
              <span className="text-[10px] font-mono text-slate-500 uppercase">Detector Robustness Index</span>
              <h3 className="text-2xl font-extrabold font-mono text-cyan-400">
                {report.robustness_score.toFixed(1)}% ROBUST
              </h3>
              <p className="text-xs text-slate-400">
                Correctly detected {report.detected_variants} of {report.total_variants} adversarial variants.
              </p>
            </div>

            <div className="w-full sm:w-48 bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-xs text-center">
              <span className="text-[10px] text-slate-500 block uppercase">Baseline Risk Score</span>
              <span className="text-lg font-bold text-amber-400">{report.baseline_risk_score} / 100</span>
            </div>
          </div>

          {/* Variants Table */}
          <div className="bg-[#0b101d] border border-slate-800 rounded-2xl p-4 overflow-x-auto font-mono text-xs space-y-2">
            <h4 className="text-xs font-semibold text-slate-300 uppercase mb-3">Evaluated Variants Matrix</h4>
            {report.variants.map((v, i) => (
              <div
                key={i}
                className="bg-[#070c18] border border-slate-800/80 rounded-xl p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-cyan-400 border border-slate-800">
                      {v.perturbation_name}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        v.is_detected_as_scam
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800/50"
                          : "bg-rose-950 text-rose-400 border border-rose-800/50"
                      }`}
                    >
                      {v.is_detected_as_scam ? "✓ FLAGGED" : "⚠️ BYPASSED"}
                    </span>
                  </div>
                  <p className="text-slate-300 font-mono text-[11px] break-all">{v.variant_text}</p>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-auto">
                  <span className="text-slate-400">
                    Risk: <strong className={v.risk_score >= 40 ? "text-rose-400" : "text-emerald-400"}>{v.risk_score}</strong>
                  </span>
                  {onInspectVariant && (
                    <button
                      onClick={() => onInspectVariant(v.variant_text)}
                      className="px-2.5 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/50 text-[10px] hover:bg-cyan-900 transition"
                    >
                      Inspect X-Ray ↗
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Red-Team Multi-Depth Report */}
      {activeSubTab === "redteam" && redteamReport && (
        <div className="space-y-4">
          <div className="bg-[#0b101d] border border-rose-900/40 rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-rose-900/30 pb-3">
              <div>
                <span className="text-[10px] font-mono text-rose-400 uppercase">Adaptive Red-Team Results</span>
                <h3 className="text-lg font-bold font-mono text-white">
                  Tested {redteamReport.total_mutations_tested} Iterative Mutations
                </h3>
              </div>
              <span className="text-xl font-extrabold font-mono text-rose-400">
                {redteamReport.robustness_score.toFixed(1)}% Robustness
              </span>
            </div>

            {/* Confusion Matrix */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs text-center">
              <div className="bg-[#070c18] p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">True Positive</span>
                <span className="text-base font-bold text-emerald-400">{redteamReport.confusion_matrix.true_positive}</span>
              </div>
              <div className="bg-[#070c18] p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">False Negative (Bypasses)</span>
                <span className="text-base font-bold text-rose-400">{redteamReport.confusion_matrix.false_negative}</span>
              </div>
              <div className="bg-[#070c18] p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">False Positive</span>
                <span className="text-base font-bold text-amber-400">{redteamReport.confusion_matrix.false_positive}</span>
              </div>
              <div className="bg-[#070c18] p-3 rounded-xl border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block">True Negative</span>
                <span className="text-base font-bold text-cyan-400">{redteamReport.confusion_matrix.true_negative}</span>
              </div>
            </div>

            {/* Per-Transformation Accuracy Breakdown */}
            {redteamReport.per_transformation_score && Object.keys(redteamReport.per_transformation_score).length > 0 && (
              <div className="bg-[#070c18] border border-slate-800 p-4 rounded-xl space-y-3">
                <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider block">
                  Resilience Score per Transformation Category
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                  {Object.entries(redteamReport.per_transformation_score).map(([key, val]) => (
                    <div key={key} className="bg-[#0b101d] p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300 capitalize">{key.replace(/_/g, " ")}</span>
                      <strong className={val >= 70 ? "text-emerald-400" : "text-amber-400"}>
                        {val.toFixed(1)}%
                      </strong>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Failure Examples */}
            {redteamReport.failure_examples.length > 0 && (
              <div className="space-y-2 pt-2">
                <span className="text-xs font-mono text-rose-400 uppercase font-semibold block">
                  Sanitized Detection Bypasses ({redteamReport.failure_examples.length} found):
                </span>
                <div className="space-y-1.5 font-mono text-xs">
                  {redteamReport.failure_examples.map((fail, i) => (
                    <div key={i} className="bg-rose-950/20 border border-rose-900/40 p-2.5 rounded-lg text-rose-300 break-all">
                      {fail}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
