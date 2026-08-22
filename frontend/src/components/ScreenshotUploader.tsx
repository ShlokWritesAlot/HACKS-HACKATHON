"use client";

import React, { useState } from "react";
import { AnalyzeResponse } from "@/types/api";

interface Props {
  onAnalysisComplete: (result: AnalyzeResponse, extractedText: string) => void;
  onError: (msg: string) => void;
}

export default function ScreenshotUploader({ onAnalysisComplete, onError }: Props) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  const handleFileChange = (file: File | null) => {
    if (!file) return;
    if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
      onError("Invalid image format. Please upload a PNG, JPEG, or WebP image.");
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      onError("Image file is too large. Maximum allowed size is 10 MB.");
      return;
    }
    setSelectedFile(file);
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const res = await fetch("/api/v1/analyze/screenshot", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error?.message || errData.detail || "Failed to process screenshot.");
      }

      const data = await res.json();
      // Map screenshot analysis output to AnalyzeResponse schema
      const mappedResponse: AnalyzeResponse = {
        analysis_id: `ocr-${Date.now()}`,
        risk_score: data.analysis.risk_score,
        risk_level: data.analysis.risk_level,
        scam_family: data.analysis.scam_family,
        language: "multilingual",
        original_text: data.extracted_text,
        normalized_text: data.analysis.cleaned_text,
        decoded_meaning: data.analysis.decoded_meaning,
        manipulation_fingerprint: data.analysis.manipulation,
        obfuscation_fingerprint: data.analysis.obfuscation || [],
        evidence: [
          `OCR Confidence: ${(data.ocr_confidence * 100).toFixed(0)}%`,
          `Image Dimensions: ${data.dimensions}`,
          ...(data.analysis.evidence || []),
        ],
        safe_action: data.analysis.recommended_action,
        model_version: "v1.0.0-ocr-xray",
      };

      onAnalysisComplete(mappedResponse, data.extracted_text);
    } catch (err: any) {
      onError(err.message || "Failed to analyze screenshot.");
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragActive(false);
          if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleFileChange(e.dataTransfer.files[0]);
          }
        }}
        className={`border-2 border-dashed rounded-2xl p-6 text-center transition-all ${
          dragActive
            ? "border-indigo-500 bg-indigo-500/10"
            : "border-slate-800 bg-slate-950/60 hover:border-slate-700"
        }`}
      >
        <input
          type="file"
          id="screenshot-input"
          accept="image/png,image/jpeg,image/webp"
          onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
          className="hidden"
        />

        <label
          htmlFor="screenshot-input"
          className="cursor-pointer flex flex-col items-center justify-center space-y-2"
        >
          <div className="w-12 h-12 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-xl text-indigo-400">
            📷
          </div>
          <div>
            <span className="text-xs font-semibold text-indigo-400 hover:underline">
              Choose a screenshot
            </span>{" "}
            <span className="text-xs text-slate-400">or drag and drop</span>
          </div>
          <span className="text-[10px] text-slate-500">
            PNG, JPEG, WebP up to 10MB (Decompression bomb protected)
          </span>
        </label>

        {selectedFile && (
          <div className="mt-4 p-2.5 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between text-xs text-slate-200">
            <span className="truncate max-w-[200px] font-mono">{selectedFile.name}</span>
            <span className="text-slate-400">{(selectedFile.size / 1024).toFixed(1)} KB</span>
          </div>
        )}
      </div>

      {selectedFile && (
        <button
          type="button"
          onClick={handleUpload}
          disabled={isUploading}
          className="w-full py-3 rounded-xl font-semibold text-xs sm:text-sm bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/30 transition-all disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer"
        >
          {isUploading ? (
            <>
              <span className="inline-block h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span>Extracting Text & Running X-Ray...</span>
            </>
          ) : (
            <>
              <span>⚡</span>
              <span>Analyze Screenshot Threat</span>
            </>
          )}
        </button>
      )}
    </div>
  );
}
