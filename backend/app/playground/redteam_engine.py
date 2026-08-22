"""
Adaptive Red-Team Evaluation Engine for BhashaRakshak.

Runs an iterative evaluation loop:
  original → mutation → detection → identify failure → generate harder mutation → detection → repeat

Calculates:
  - Robustness score (0-100%)
  - Per-transformation accuracy scores
  - Per-language accuracy scores
  - Confusion matrix
  - Failure examples (sanitized)
  - Hardest examples (lowest risk score)

SECURITY CONTRACT:
  - Defensive security testing only.
  - NEVER generates exploit code, malware, or harmful payloads.
  - All test data stored in reports is HTML-escaped/sanitized.
"""

from __future__ import annotations

import html
import logging
from typing import Dict, List, Optional

from app.playground.generator import AdversarialVariantGenerator
from app.playground.schemas import (
    ConfusionMatrix,
    PerturbationType,
    RedTeamEvaluationReport,
    RedTeamIterationStep,
    RedTeamRequest,
)
from app.xray.engine import ScamXRayEngine

logger = logging.getLogger(__name__)


class AdaptiveRedTeamEngine:
    """
    Iterative red-team evaluation loop engine for detector stress-testing.
    """

    def __init__(self, xray_engine: Optional[ScamXRayEngine] = None):
        self.xray = xray_engine or ScamXRayEngine()

    def evaluate(self, request: RedTeamRequest) -> RedTeamEvaluationReport:
        generator = AdversarialVariantGenerator(seed=request.seed or 42)
        baseline = self.xray.analyze(request.message)
        baseline_score = baseline.risk_score

        iteration_history: List[RedTeamIterationStep] = []
        failure_examples: List[str] = []
        per_trans_correct: Dict[str, int] = {}
        per_trans_total: Dict[str, int] = {}
        per_lang_correct: Dict[str, int] = {"en": 0, "hi": 0, "hinglish": 0}
        per_lang_total: Dict[str, int] = {"en": 0, "hi": 0, "hinglish": 0}

        cm = ConfusionMatrix()

        # Step 0: Record baseline
        cm.true_positive += 1 if baseline.risk_score >= 40 else 0
        cm.false_negative += 1 if baseline.risk_score < 40 else 0

        current_candidates = [(request.message, [])]
        step_counter = 0

        for depth in range(1, request.max_depth + 1):
            next_candidates = []
            intensity = "low" if depth == 1 else "medium" if depth == 2 else "high"

            for parent_text, applied_types in current_candidates:
                variants = generator.generate_all_variants(text=parent_text, intensity=intensity)

                for p_type, p_name, var_text in variants:
                    step_counter += 1
                    analysis = self.xray.analyze(var_text)
                    is_detected = analysis.risk_score >= 40
                    scam_fam = (
                        analysis.scam_family.value
                        if hasattr(analysis.scam_family, "value")
                        else str(analysis.scam_family)
                    )

                    failure_reason = None
                    if not is_detected:
                        failure_reason = f"Obfuscation '{p_name}' successfully bypassed scam detector (risk_score={analysis.risk_score})."
                        sanitized_fail = html.escape(var_text)
                        if sanitized_fail not in failure_examples:
                            failure_examples.append(sanitized_fail)
                        cm.false_negative += 1
                    else:
                        cm.true_positive += 1

                    # Track per-transformation stats
                    p_key = p_type.value
                    per_trans_total[p_key] = per_trans_total.get(p_key, 0) + 1
                    if is_detected:
                        per_trans_correct[p_key] = per_trans_correct.get(p_key, 0) + 1

                    # Track per-language stats
                    raw_lang = getattr(analysis, "language", "en")
                    lang = (raw_lang.value if hasattr(raw_lang, "value") else str(raw_lang)).lower()
                    if lang not in per_lang_total:
                        lang = "en"
                    per_lang_total[lang] += 1
                    if is_detected:
                        per_lang_correct[lang] += 1

                    current_applied = applied_types + [p_key]
                    step = RedTeamIterationStep(
                        iteration=step_counter,
                        depth=depth,
                        variant_text=var_text,
                        perturbations_applied=current_applied,
                        risk_score=analysis.risk_score,
                        is_detected=is_detected,
                        detected_scam_family=scam_fam,
                        failure_identified=failure_reason,
                    )
                    iteration_history.append(step)

                    # If this mutation caused a failure (bypass), use it as seed for next depth iteration
                    if not is_detected and len(next_candidates) < 5:
                        next_candidates.append((var_text, current_applied))

            if next_candidates:
                current_candidates = next_candidates
            else:
                # If no bypasses found, pick up to 3 variants to push deeper
                current_candidates = [(s.variant_text, s.perturbations_applied) for s in iteration_history[-3:]]

        # Calculate metrics
        total_mutations = len(iteration_history)
        detected_mutations = sum(1 for s in iteration_history if s.is_detected)
        robustness_score = (
            round((detected_mutations / total_mutations) * 100.0, 1)
            if total_mutations > 0
            else 100.0
        )

        per_trans_scores = {
            k: round((per_trans_correct.get(k, 0) / total) * 100.0, 1)
            for k, total in per_trans_total.items()
            if total > 0
        }

        per_lang_scores = {
            k: round((per_lang_correct[k] / total) * 100.0, 1) if total > 0 else 100.0
            for k, total in per_lang_total.items()
        }

        # Hardest examples = lowest risk score assigned by analyzer
        hardest = sorted(iteration_history, key=lambda x: x.risk_score)[:5]

        return RedTeamEvaluationReport(
            original_message=request.message,
            baseline_risk_score=baseline_score,
            total_mutations_tested=total_mutations,
            robustness_score=robustness_score,
            per_transformation_score=per_trans_scores,
            per_language_score=per_lang_scores,
            confusion_matrix=cm,
            failure_examples=failure_examples,
            hardest_examples=hardest,
            iteration_history=iteration_history,
        )
