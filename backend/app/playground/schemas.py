from __future__ import annotations

import enum
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class PerturbationType(str, enum.Enum):
    """The 19 supported adversarial obfuscation transformations."""

    # Original 10
    VOWEL_DELETION = "vowel_deletion"
    ADJACENT_SWAP = "adjacent_swap"
    NUMBER_SUBSTITUTION = "number_substitution"
    REPEATED_CHARS = "repeated_chars"
    WHITESPACE_MANIPULATION = "whitespace_manipulation"
    PHONETIC_TRANSLITERATION = "phonetic_transliteration"
    HINGLISH_SYNTHESIS = "hinglish_synthesis"
    MIXED_SCRIPTS = "mixed_scripts"
    PUNCTUATION_INSERTION = "punctuation_insertion"
    INFORMAL_ABBREVIATIONS = "informal_abbreviations"

    # New 9
    UNICODE_CONFUSABLES = "unicode_confusables"
    ZERO_WIDTH_CHARS = "zero_width_chars"
    UNICODE_NORMALIZATION = "unicode_normalization"
    MULTILINGUAL_SWITCHING = "multilingual_switching"
    NESTED_OBFUSCATION = "nested_obfuscation"
    OCR_CORRUPTION = "ocr_corruption"
    REALISTIC_TYPOS = "realistic_typos"
    DOMAIN_OBFUSCATION = "domain_obfuscation"
    SENDER_ID_MUTATION = "sender_id_mutation"


class PlaygroundRequest(BaseModel):
    """Request payload to simulate adversarial variants."""
    model_config = ConfigDict(extra="forbid")

    message: str = Field(
        ...,
        min_length=5,
        max_length=5000,
        description="The base scam message template to perturb.",
        examples=["Your bank account will be blocked. Update KYC immediately."],
    )
    perturbations: Optional[List[PerturbationType]] = Field(
        default=None,
        description="Specific obfuscations to generate (defaults to all 19).",
    )
    intensity: Literal["low", "medium", "high", "extreme"] = Field(
        default="medium",
        description="Perturbation density and mutation aggressiveness.",
    )
    seed: Optional[int] = Field(
        default=42,
        description="Random seed for reproducible, deterministic perturbation sequences.",
    )


class VariantEvaluation(BaseModel):
    """Evaluation result for an individual perturbed variant."""
    model_config = ConfigDict(extra="forbid")

    variant_id: str
    variant_text: str
    perturbation_type: PerturbationType
    perturbation_name: str
    predicted_scam_family: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    confidence: float
    is_detected_as_scam: bool
    cleaned_text: str


class PlaygroundResponse(BaseModel):
    """Aggregated adversarial stress test report with robustness metrics."""
    model_config = ConfigDict(extra="forbid")

    original_message: str
    baseline_scam_family: str
    baseline_risk_score: int
    total_variants: int
    detected_variants: int
    robustness_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Percentage of adversarial variants correctly detected as malicious (0 to 100%).",
    )
    variants: List[VariantEvaluation]


# ── Red-Team Evaluation Engine Schemas ────────────────────────────────────────

class RedTeamIterationStep(BaseModel):
    """Step record inside an iterative red-team mutation loop."""
    model_config = ConfigDict(extra="forbid")

    iteration: int
    depth: int
    variant_text: str
    perturbations_applied: List[str]
    risk_score: int = Field(..., ge=0, le=100)
    is_detected: bool
    detected_scam_family: str
    failure_identified: Optional[str] = None


class ConfusionMatrix(BaseModel):
    """Confusion matrix metrics for red-team detector evaluation."""
    model_config = ConfigDict(extra="forbid")

    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0


class RedTeamRequest(BaseModel):
    """Request payload for iterative red-team evaluation."""
    model_config = ConfigDict(extra="forbid")

    message: str = Field(
        ...,
        min_length=5,
        max_length=5000,
        description="Scam text template to adaptively stress-test.",
    )
    sender_id: Optional[str] = Field(None, max_length=50)
    max_depth: int = Field(default=3, ge=1, le=5, description="Max mutation depth for iterative refinement.")
    seed: Optional[int] = Field(default=42)


class RedTeamEvaluationReport(BaseModel):
    """Comprehensive Red-Team Evaluation report."""
    model_config = ConfigDict(extra="forbid")

    original_message: str
    baseline_risk_score: int
    total_mutations_tested: int
    robustness_score: float = Field(..., ge=0.0, le=100.0, description="Overall robustness percentage (0-100%).")
    per_transformation_score: dict[str, float] = Field(default_factory=dict, description="Accuracy per mutation type.")
    per_language_score: dict[str, float] = Field(default_factory=dict, description="Accuracy per language (en, hi, hinglish).")
    confusion_matrix: ConfusionMatrix
    failure_examples: List[str] = Field(default_factory=list, description="Sanitized variants that bypassed detection.")
    hardest_examples: List[RedTeamIterationStep] = Field(default_factory=list, description="Top most evasive variants.")
    iteration_history: List[RedTeamIterationStep] = Field(default_factory=list)

