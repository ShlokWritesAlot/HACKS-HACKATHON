"""
Evidence Aggregation Engine for BhashaRakshak.

Combines rule/intel/pattern deterministic detectors and ML signals
into a fully explainable, audit-ready threat evidence report.
"""

from __future__ import annotations

import logging, uuid
from typing import List, Optional

from app.evidence.detectors import run_all_detectors
from app.evidence.schemas import (
    EvidenceCategoryEnum,
    ExplainableEvidenceReport,
    StructuredEvidenceItem,
)
from app.ml.schemas import ScamCategory
from app.xray.schemas import RiskLevelEnum

logger = logging.getLogger(__name__)


class EvidenceAggregationEngine:
    """
    Aggregates threat evidence signals into structured, explainable reports.
    """

    def evaluate(
        self,
        raw_text: str,
        cleaned_text: str,
        transformations: List = None,
        ml_category: Optional[ScamCategory] = None,
        ml_confidence: float = 0.85,
    ) -> ExplainableEvidenceReport:
        # 1. Run all deterministic Python detectors
        evidence_items = run_all_detectors(raw_text, cleaned_text, transformations or [])

        # 2. If ML model signal is provided and high risk, attach model-derived evidence item
        if ml_category and ml_category != ScamCategory.SAFE:
            evidence_items.append(
                StructuredEvidenceItem(
                    evidence_id=f"ev_ml_{uuid.uuid4().hex[:6]}",
                    category=EvidenceCategoryEnum.BANK_IMPERSONATION if "KYC" in ml_category.value else EvidenceCategoryEnum.URGENCY_LANGUAGE,
                    detector="ml_classifier_MiniLM",
                    description=f"ML Classifier intent signal matched category '{ml_category.value}' with probability {ml_confidence:.2f}.",
                    severity_contribution=30.0,
                    confidence=float(ml_confidence),
                    source_span=None,
                    normalized_value=ml_category.value,
                    is_deterministic=False,
                )
            )

        # 3. Calculate composite risk score from aggregated severity contributions
        total_severity = sum(item.severity_contribution for item in evidence_items)
        risk_score = min(100, int(total_severity))

        # 4. Map score to categorical risk tier
        if risk_score >= 80:
            risk_tier = RiskLevelEnum.CRITICAL
        elif risk_score >= 70:
            risk_tier = RiskLevelEnum.HIGH
        elif risk_score >= 50:
            risk_tier = RiskLevelEnum.MEDIUM
        elif risk_score >= 20:
            risk_tier = RiskLevelEnum.LOW
        else:
            risk_tier = RiskLevelEnum.SAFE

        # 5. Determine primary scam category
        if ml_category and ml_category != ScamCategory.SAFE:
            primary_category = ml_category
        else:
            primary_category = self._infer_category_from_evidence(evidence_items, risk_score)

        # 6. Calculate overall confidence & epistemic uncertainty
        if evidence_items:
            conf_sum = sum(item.confidence for item in evidence_items)
            overall_confidence = round(conf_sum / len(evidence_items), 2)
        else:
            overall_confidence = 0.95  # Safe clear text has high confidence of safety

        uncertainty = round(1.0 - overall_confidence, 2)

        return ExplainableEvidenceReport(
            risk_score=risk_score,
            risk_tier=risk_tier,
            scam_category=primary_category,
            structured_evidence=evidence_items,
            overall_confidence=overall_confidence,
            uncertainty=uncertainty,
        )

    def _infer_category_from_evidence(
        self, evidence_items: List[StructuredEvidenceItem], risk_score: int
    ) -> ScamCategory:
        if risk_score < 20 or not evidence_items:
            return ScamCategory.SAFE

        cats = {item.category for item in evidence_items}
        if EvidenceCategoryEnum.BANK_IMPERSONATION in cats or EvidenceCategoryEnum.HOMOGLYPH_DOMAIN in cats:
            return ScamCategory.BANK_KYC
        if EvidenceCategoryEnum.UPI_REQUEST in cats:
            return ScamCategory.UPI_PAYMENT
        if EvidenceCategoryEnum.REMOTE_ACCESS in cats:
            return ScamCategory.REMOTE_ACCESS
        if EvidenceCategoryEnum.OTP_REQUEST in cats or EvidenceCategoryEnum.CREDENTIAL_REQUEST in cats:
            return ScamCategory.BANK_KYC

        return ScamCategory.OTHER_SCAM
