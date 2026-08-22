"""
Multi-Factor Scam DNA Similarity Engine for BhashaRakshak.

Combines:
  1. Semantic vector similarity (cosine)
  2. Structured DNA fingerprint similarity (Jaccard)
  3. IOC overlap
  4. Psychological pressure profile similarity
  5. Scam taxonomy compatibility

ANTI-MERGING GUARDRAIL:
  Incompatible scam archetypes or conflicting structural DNA profiles are
  hard-blocked from merging even if generic text wording is similar.
"""

from __future__ import annotations

import math
from typing import Dict, Tuple

from app.dna.schemas import ScamDNAFingerprint
from app.ml.schemas import ScamCategory


class ScamDNASimilarityEngine:
    """
    Computes multi-factor composite similarity and association confidence.
    """

    def calculate_similarity(
        self, dna1: ScamDNAFingerprint, dna2: ScamDNAFingerprint
    ) -> Tuple[float, float, Dict[str, float]]:
        # 1. Taxonomy Compatibility Check
        taxonomy_compat = self._check_taxonomy_compatibility(dna1.scam_archetype, dna2.scam_archetype)

        # Strict Anti-Merging Guardrail: If taxonomy conflicts, score is 0.0
        if taxonomy_compat == 0.0:
            return 0.0, 0.0, {
                "semantic_sim": 0.0,
                "structural_dna_sim": 0.0,
                "ioc_overlap": 0.0,
                "pressure_profile_sim": 0.0,
                "taxonomy_compatibility": 0.0,
            }

        # 2. Semantic Embedding Similarity (Cosine)
        semantic_sim = self._cosine_similarity(dna1.semantic_embedding, dna2.semantic_embedding)

        # 3. Structural DNA Similarity (Jaccard)
        structural_sim = self._calculate_structural_similarity(dna1, dna2)

        # 4. IOC Overlap (Jaccard on extracted_entities)
        ioc_overlap = self._calculate_ioc_overlap(dna1.extracted_entities, dna2.extracted_entities)

        # 5. Psychological Pressure Profile Similarity (1 - normalized L1 distance)
        pressure_sim = self._calculate_pressure_similarity(dna1.pressure_profile, dna2.pressure_profile)

        # Anti-Merging Guardrail for conflicting pressure vectors
        if pressure_sim < 0.30:
            structural_sim *= 0.5

        # Weighted Composite Score
        composite_score = (
            0.35 * semantic_sim +
            0.25 * structural_sim +
            0.20 * ioc_overlap +
            0.10 * pressure_sim +
            0.10 * taxonomy_compat
        )

        composite_score = round(max(0.0, min(1.0, composite_score)), 4)

        # Association Confidence Calculation
        # Higher confidence when IOC overlap is present or structural similarity is strong
        confidence_multiplier = 1.25 if ioc_overlap > 0.5 else (1.10 if ioc_overlap > 0 else 1.0)
        confidence = round(max(0.0, min(1.0, composite_score * confidence_multiplier)), 2)

        breakdown = {
            "semantic_sim": round(semantic_sim, 4),
            "structural_dna_sim": round(structural_sim, 4),
            "ioc_overlap": round(ioc_overlap, 4),
            "pressure_profile_sim": round(pressure_sim, 4),
            "taxonomy_compatibility": round(taxonomy_compat, 4),
        }

        return composite_score, confidence, breakdown

    def _cosine_similarity(self, vec1: list[float], vec2: list[float]) -> float:
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(b * b for b in vec2))
        if norm1 == 0.0 or norm2 == 0.0:
            return 0.0
        return max(0.0, min(1.0, dot / (norm1 * norm2)))

    def _calculate_structural_similarity(self, dna1: ScamDNAFingerprint, dna2: ScamDNAFingerprint) -> float:
        # Check matching organizational target
        org_match = 1.0 if dna1.impersonated_organization == dna2.impersonated_organization and dna1.impersonated_organization != "NONE" else 0.5 if dna1.impersonated_organization == dna2.impersonated_organization else 0.0

        # Obfuscation Jaccard
        set1 = set(dna1.obfuscation_techniques)
        set2 = set(dna2.obfuscation_techniques)
        obf_jaccard = len(set1 & set2) / len(set1 | set2) if (set1 or set2) else 1.0

        # URL structural match
        url_match = 1.0 if dna1.url_characteristics.get("has_url") == dna2.url_characteristics.get("has_url") else 0.0

        # UPI structural match
        upi_match = 1.0 if dna1.upi_characteristics.get("has_vpa") == dna2.upi_characteristics.get("has_vpa") else 0.0

        return 0.35 * org_match + 0.25 * obf_jaccard + 0.20 * url_match + 0.20 * upi_match

    def _calculate_ioc_overlap(self, list1: list[str], list2: list[str]) -> float:
        set1 = set(list1 or [])
        set2 = set(list2 or [])
        if not set1 or not set2:
            return 0.0
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0

    def _calculate_pressure_similarity(self, p1: dict[str, float], p2: dict[str, float]) -> float:
        keys = ["fear", "urgency", "authority_impersonation", "financial_request", "credential_request", "suspicious_link", "call_to_action_pressure"]
        total_diff = sum(abs(p1.get(k, 0.0) - p2.get(k, 0.0)) for k in keys)
        max_diff = len(keys) * 1.0
        return max(0.0, 1.0 - (total_diff / max_diff))

    def _check_taxonomy_compatibility(self, cat1: ScamCategory, cat2: ScamCategory) -> float:
        if cat1 == cat2:
            return 1.0
        if cat1 == ScamCategory.SAFE or cat2 == ScamCategory.SAFE:
            return 0.0
        if cat1 == ScamCategory.OTHER_SCAM or cat2 == ScamCategory.OTHER_SCAM:
            return 0.5
        # Incompatible distinct archetypes (e.g. BANK_KYC vs JOB vs REMOTE_ACCESS)
        return 0.0
