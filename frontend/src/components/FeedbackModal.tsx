"use client";

import React, { useState } from "react";
import { apiClient } from "@/lib/api-client";
import { FeedbackResponse } from "@/types/api";

interface Props {
  analysisId: string;
}

export default function FeedbackModal({ analysisId }: Props) {
  const [submitted, setSubmitted] = useState(false);
  const [isCorrect, setIsCorrect] = useState<boolean | null>(null);
  const [comment, setComment] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showCommentBox, setShowCommentBox] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const handleVote = (correct: boolean) => {
    setIsCorrect(correct);
    setShowCommentBox(true);
    setSubmitError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isCorrect === null) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await apiClient.post<FeedbackResponse>("/api/v1/feedback", {
        analysis_id: analysisId,
        is_correct: isCorrect,
        comment: comment.trim() || undefined,
        analyst_id: "web-client",
      });
      setSubmitted(true);
    } catch (err: any) {
      console.error("Failed to submit feedback:", err);
      setSubmitError(err.message || "Failed to record feedback. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickSubmit = async (correct: boolean) => {
    setIsCorrect(correct);
    setIsSubmitting(true);
    setSubmitError(null);

    try {
      await apiClient.post<FeedbackResponse>("/api/v1/feedback", {
        analysis_id: analysisId,
        is_correct: correct,
        analyst_id: "web-client",
      });
      setSubmitted(true);
    } catch (err: any) {
      console.error("Failed to quick-submit feedback:", err);
      setSubmitError(err.message || "Failed to record feedback.");
      setShowCommentBox(true);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (submitted) {
    return (
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm text-center animate-fadeIn">
        <span className="text-emerald-500 text-lg">✓</span>
        <p className="text-xs font-semibold text-slate-700 dark:text-slate-300 mt-1">
          Thank you! Feedback recorded for model calibration.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm transition-all">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <span className="text-xs font-semibold text-slate-900 dark:text-slate-100 block">
            Was this analysis accurate?
          </span>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            Help improve BhashaRakshak&apos;s detection precision
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={isSubmitting}
            aria-label="Vote Accurate"
            onClick={() => {
              if (!showCommentBox) {
                handleVote(true);
              } else {
                setIsCorrect(true);
              }
            }}
            className={`px-3 py-1.5 rounded-xl text-xs font-medium border transition-all cursor-pointer flex items-center gap-1.5 disabled:opacity-50 ${isCorrect === true
              ? "bg-emerald-600 text-white border-emerald-600 shadow-sm shadow-emerald-600/30"
              : "bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:border-slate-300"
              }`}
          >
            <span>👍</span> Accurate
          </button>

          <button
            type="button"
            disabled={isSubmitting}
            aria-label="Vote Inaccurate"
            onClick={() => {
              if (!showCommentBox) {
                handleVote(false);
              } else {
                setIsCorrect(false);
              }
            }}
            className={`px-3 py-1.5 rounded-xl text-xs font-medium border transition-all cursor-pointer flex items-center gap-1.5 disabled:opacity-50 ${isCorrect === false
              ? "bg-rose-600 text-white border-rose-600 shadow-sm shadow-rose-600/30"
              : "bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:border-slate-300"
              }`}
          >
            <span>👎</span> Inaccurate
          </button>
        </div>
      </div>

      {showCommentBox && (
        <form onSubmit={handleSubmit} className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800 space-y-3 animate-slideUp">
          <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
            <label htmlFor="feedback-comment">Add optional notes or corrections:</label>
            <span className="font-mono">{comment.length}/1000</span>
          </div>

          <textarea
            id="feedback-comment"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="e.g., False positive, legitimate bank notification shortcode..."
            rows={2}
            maxLength={1000}
            className="w-full text-xs p-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 text-slate-900 dark:text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-none"
          />

          {submitError && (
            <p className="text-xs text-rose-500 font-medium">⚠️ {submitError}</p>
          )}

          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={() => {
                if (isCorrect !== null) {
                  handleQuickSubmit(isCorrect);
                } else {
                  setShowCommentBox(false);
                }
              }}
              disabled={isSubmitting}
              className="text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 underline cursor-pointer"
            >
              Skip comment &amp; submit
            </button>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setShowCommentBox(false);
                  setIsCorrect(null);
                  setSubmitError(null);
                }}
                className="px-3 py-1.5 rounded-xl text-xs font-medium text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 transition-colors cursor-pointer"
              >
                Cancel
              </button>

              <button
                type="submit"
                disabled={isSubmitting || isCorrect === null}
                className="px-4 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-all disabled:opacity-50 shadow-md shadow-indigo-600/20 cursor-pointer"
              >
                {isSubmitting ? "Submitting..." : "Submit Feedback"}
              </button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
