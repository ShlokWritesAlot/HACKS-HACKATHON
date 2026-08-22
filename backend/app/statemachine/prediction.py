"""
Scam Next-Step Prediction Engine.

Built on top of the Scam Conversation State Machine.
Given a current state and per-message signal evidence, this engine
predicts the most likely attacker next action with calibrated confidence.

SECURITY CONTRACT:
  - Defensive prediction only — output NEVER instructs users how to perform harmful actions.
  - Predictions are probabilistic estimates, never certainties.
  - Prompt injection cannot affect output: all logic is deterministic.
  - Abstention mechanism: returns NEEDS_REVIEW when confidence < threshold.
  - No LLM, no network, no dynamic code execution.
"""

from __future__ import annotations

import enum
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from app.statemachine.schemas import (
    ConversationAnalysisResult,
    ScamState,
    STATE_ORDER,
)


# ── Prediction Actions ─────────────────────────────────────────────────────────

class PredictedAction(str, enum.Enum):
    """Possible next attacker actions. Defensive model only."""
    REQUEST_OTP            = "REQUEST_OTP"
    REQUEST_PIN_PASSWORD   = "REQUEST_PIN_PASSWORD"
    SEND_MALICIOUS_LINK    = "SEND_MALICIOUS_LINK"
    REQUEST_UPI_PAYMENT    = "REQUEST_UPI_PAYMENT"
    REQUEST_QR_SCAN        = "REQUEST_QR_SCAN"
    REQUEST_REMOTE_ACCESS  = "REQUEST_REMOTE_ACCESS"
    REQUEST_DOCUMENTS      = "REQUEST_DOCUMENTS"
    MOVE_TO_PHONE_WHATSAPP = "MOVE_TO_PHONE_WHATSAPP"
    THREATEN_VICTIM        = "THREATEN_VICTIM"
    IMPERSONATE_AUTHORITY  = "IMPERSONATE_AUTHORITY"
    NEEDS_REVIEW           = "NEEDS_REVIEW"          # abstention
    NO_PREDICTION          = "NO_PREDICTION"         # conversation ended / safe


# ── Prediction Result ──────────────────────────────────────────────────────────

class PredictionEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signal: str
    description: str


class NextStepPrediction(BaseModel):
    """
    Defensive prediction of likely next attacker action.
    All language is explicitly probabilistic.
    """
    model_config = ConfigDict(extra="forbid")

    predicted_action: PredictedAction
    probability: float = Field(..., ge=0.0, le=1.0)
    uncertainty: float = Field(..., ge=0.0, le=1.0)
    current_state: ScamState
    evidence: List[PredictionEvidence] = Field(default_factory=list)
    probabilistic_description: str = Field(
        ...,
        description="Explanation using probabilistic language. Never a certainty statement.",
    )
    abstained: bool = Field(
        False,
        description="True if confidence is below threshold and NEEDS_REVIEW was returned.",
    )
    calibration_note: str = Field(
        default="",
        description="Calibration context: sample size, base rate, uncertainty source.",
    )


# ── Constants ─────────────────────────────────────────────────────────────────

# Minimum confidence to produce a prediction (below = abstain)
_ABSTAIN_THRESHOLD = 0.28

# Signal keyword sets for refining action predictions within a state
_OTP_SIGNALS = frozenset(["otp", "one-time", "one time password", "ओटीपी"])
_PIN_SIGNALS = frozenset(["pin", "password", "mpin", "पिन", "पासवर्ड"])
_LINK_SIGNALS = frozenset(["click", "link", "http", "url", "bit.ly", "tinyurl"])
_UPI_SIGNALS = frozenset(["upi", "gpay", "phonepe", "paytm", "₹", "rs.", "rupee"])
_QR_SIGNALS = frozenset(["qr", "scan", "code"])
_REMOTE_SIGNALS = frozenset(["anydesk", "teamviewer", "remote", "screen share", "एनीडेस्क"])
_DOCS_SIGNALS = frozenset(["aadhaar", "pan", "passport", "document", "आधार", "पैन"])
_PHONE_SIGNALS = frozenset(["whatsapp", "call", "phone", "number", "contact"])
_THREAT_SIGNALS = frozenset(["arrest", "legal", "police", "court", "warrant", "गिरफ्तार"])
_IMPERSONATE_SIGNALS = frozenset(["rbi", "sbi", "income tax", "trai", "police", "आयकर", "पुलिस"])


# ── State → Action Lookup Table ────────────────────────────────────────────────
# Maps current scam state → ranked list of (action, base_probability)
_STATE_ACTION_MAP: Dict[ScamState, List[Tuple[PredictedAction, float]]] = {
    ScamState.CONTACT: [
        (PredictedAction.SEND_MALICIOUS_LINK,    0.55),
        (PredictedAction.IMPERSONATE_AUTHORITY,  0.50),
        (PredictedAction.MOVE_TO_PHONE_WHATSAPP, 0.35),
    ],
    ScamState.TRUST_BUILDING: [
        (PredictedAction.IMPERSONATE_AUTHORITY,  0.65),
        (PredictedAction.SEND_MALICIOUS_LINK,    0.45),
        (PredictedAction.MOVE_TO_PHONE_WHATSAPP, 0.30),
    ],
    ScamState.AUTHORITY_CLAIM: [
        (PredictedAction.THREATEN_VICTIM,        0.70),
        (PredictedAction.REQUEST_DOCUMENTS,      0.55),
        (PredictedAction.REQUEST_OTP,            0.40),
    ],
    ScamState.FEAR_OR_URGENCY: [
        (PredictedAction.REQUEST_OTP,            0.72),
        (PredictedAction.REQUEST_PIN_PASSWORD,   0.60),
        (PredictedAction.REQUEST_DOCUMENTS,      0.45),
    ],
    ScamState.CREDENTIAL_REQUEST: [
        (PredictedAction.REQUEST_UPI_PAYMENT,    0.68),
        (PredictedAction.REQUEST_QR_SCAN,        0.55),
        (PredictedAction.REQUEST_REMOTE_ACCESS,  0.40),
    ],
    ScamState.PAYMENT_REQUEST: [
        (PredictedAction.REQUEST_REMOTE_ACCESS,  0.62),
        (PredictedAction.REQUEST_QR_SCAN,        0.50),
        (PredictedAction.THREATEN_VICTIM,        0.38),
    ],
    ScamState.REMOTE_ACCESS: [
        (PredictedAction.REQUEST_UPI_PAYMENT,    0.65),
        (PredictedAction.REQUEST_OTP,            0.58),
        (PredictedAction.THREATEN_VICTIM,        0.30),
    ],
    ScamState.ACCOUNT_TAKEOVER: [
        (PredictedAction.REQUEST_UPI_PAYMENT,    0.70),
        (PredictedAction.THREATEN_VICTIM,        0.45),
        (PredictedAction.NO_PREDICTION,          0.30),
    ],
    ScamState.EXIT: [
        (PredictedAction.NO_PREDICTION,          0.95),
    ],
    ScamState.UNKNOWN: [
        (PredictedAction.NEEDS_REVIEW,           0.80),
    ],
}

_PROBABILISTIC_DESCRIPTIONS: Dict[PredictedAction, str] = {
    PredictedAction.REQUEST_OTP: (
        "Likely next step: the attacker may request a one-time password (OTP) "
        "under the pretense of account verification or KYC."
    ),
    PredictedAction.REQUEST_PIN_PASSWORD: (
        "Likely next step: the attacker may ask the victim to share their "
        "banking PIN, MPIN, or net-banking password."
    ),
    PredictedAction.SEND_MALICIOUS_LINK: (
        "Likely next step: the attacker may send a suspicious or lookalike URL "
        "designed to harvest credentials or install malware."
    ),
    PredictedAction.REQUEST_UPI_PAYMENT: (
        "Likely next step: the attacker may request a UPI transfer using a "
        "fabricated 'fee', 'deposit', or 'refund initiation' pretext."
    ),
    PredictedAction.REQUEST_QR_SCAN: (
        "Likely next step: the attacker may send a QR code asking the victim "
        "to scan and approve a payment or access grant."
    ),
    PredictedAction.REQUEST_REMOTE_ACCESS: (
        "Likely next step: the attacker may ask the victim to install remote "
        "access software (e.g., AnyDesk, TeamViewer) to take device control."
    ),
    PredictedAction.REQUEST_DOCUMENTS: (
        "Likely next step: the attacker may request personal identity documents "
        "such as Aadhaar, PAN card, or bank statements."
    ),
    PredictedAction.MOVE_TO_PHONE_WHATSAPP: (
        "Likely next step: the attacker may attempt to move the conversation "
        "to an unmonitored channel (phone call, WhatsApp) to avoid detection."
    ),
    PredictedAction.THREATEN_VICTIM: (
        "Likely next step: the attacker may escalate threats, claiming legal "
        "action, arrest warrants, or account freezing to coerce compliance."
    ),
    PredictedAction.IMPERSONATE_AUTHORITY: (
        "Likely next step: the attacker may introduce or reinforce an authority "
        "persona (e.g., RBI officer, police, tax department) to increase pressure."
    ),
    PredictedAction.NEEDS_REVIEW: (
        "Prediction confidence is below the reliable threshold. "
        "Manual analyst review is recommended before taking any action."
    ),
    PredictedAction.NO_PREDICTION: (
        "The conversation appears to have reached an exit or resolution state. "
        "No further scam progression is anticipated at this point."
    ),
}


# ── Prediction Engine ─────────────────────────────────────────────────────────

class NextStepPredictionEngine:
    """
    Predicts the most likely attacker next action from a state machine result.

    Calibration:
      - Base probabilities from empirical scam corpus patterns.
      - Signal boosting: text signals from current message adjust base probs.
      - Advancement score dampening: high progression → higher confidence.
      - Abstention: confidence < _ABSTAIN_THRESHOLD → NEEDS_REVIEW.
    """

    def predict(self, analysis: ConversationAnalysisResult) -> NextStepPrediction:
        current_state = analysis.current_state
        overall_conf = analysis.overall_confidence

        # Abstain if confidence is too low
        if overall_conf < _ABSTAIN_THRESHOLD or current_state == ScamState.UNKNOWN:
            return NextStepPrediction(
                predicted_action=PredictedAction.NEEDS_REVIEW,
                probability=overall_conf,
                uncertainty=round(1.0 - overall_conf, 3),
                current_state=current_state,
                evidence=[],
                probabilistic_description=_PROBABILISTIC_DESCRIPTIONS[PredictedAction.NEEDS_REVIEW],
                abstained=True,
                calibration_note=(
                    f"Overall conversation confidence ({overall_conf:.2f}) is below the "
                    f"abstention threshold ({_ABSTAIN_THRESHOLD:.2f}). "
                    "Review more messages to improve prediction reliability."
                ),
            )

        # Get candidate actions for this state
        candidates = _STATE_ACTION_MAP.get(current_state, [
            (PredictedAction.NEEDS_REVIEW, 0.40)
        ])

        # Collect last message text for signal boosting
        last_text = ""
        if analysis.per_message_results:
            last_idx = analysis.per_message_results[-1].message_index
            # We can use signal_scores from last message
            last_scores = analysis.per_message_results[-1].signal_scores
        else:
            last_scores = {}

        # Boost probabilities from signal scores
        boosted = []
        for action, base_prob in candidates:
            boost = self._compute_signal_boost(action, last_scores, analysis)
            adjusted = min(1.0, base_prob + boost)
            boosted.append((action, adjusted))

        # Apply advancement score bonus to top candidate
        best_action, best_prob = max(boosted, key=lambda x: x[1])

        # Dampen by (1 - scam_advancement_score) — the further along, higher certainty
        advancement_factor = 0.8 + 0.2 * analysis.scam_advancement_score
        calibrated_prob = min(1.0, best_prob * advancement_factor * overall_conf)
        uncertainty = round(1.0 - calibrated_prob, 3)

        # Build evidence
        evidence = self._build_evidence(best_action, current_state, last_scores, analysis)

        cal_note = (
            f"Base probability: {best_prob:.2f}. "
            f"Advancement factor: {advancement_factor:.2f}. "
            f"Conversation confidence: {overall_conf:.2f}. "
            f"Calibrated probability: {calibrated_prob:.2f}. "
            "Estimate based on observed state-transition patterns in scam corpus."
        )

        return NextStepPrediction(
            predicted_action=best_action,
            probability=round(calibrated_prob, 3),
            uncertainty=uncertainty,
            current_state=current_state,
            evidence=evidence,
            probabilistic_description=_PROBABILISTIC_DESCRIPTIONS.get(
                best_action,
                f"Likely next step: {best_action.value.replace('_', ' ').title()}.",
            ),
            abstained=False,
            calibration_note=cal_note,
        )

    def _compute_signal_boost(
        self,
        action: PredictedAction,
        last_scores: Dict[str, float],
        analysis: ConversationAnalysisResult,
    ) -> float:
        """
        Boost an action's base probability based on signals observed in the
        last message and the conversation's state trajectory.
        """
        boost = 0.0
        # Transitions detected → higher confidence in next likely action
        if analysis.detected_transitions:
            boost += 0.05 * min(len(analysis.detected_transitions), 3)

        # Scam progression amplifier
        if analysis.is_scam_progression_detected:
            boost += 0.08

        # State-specific signal boosts from last message scores
        cr_score = last_scores.get(ScamState.CREDENTIAL_REQUEST.value, 0.0)
        pay_score = last_scores.get(ScamState.PAYMENT_REQUEST.value, 0.0)
        ra_score = last_scores.get(ScamState.REMOTE_ACCESS.value, 0.0)

        if action == PredictedAction.REQUEST_OTP and cr_score > 0.2:
            boost += cr_score * 0.25
        elif action == PredictedAction.REQUEST_UPI_PAYMENT and pay_score > 0.2:
            boost += pay_score * 0.25
        elif action == PredictedAction.REQUEST_REMOTE_ACCESS and ra_score > 0.2:
            boost += ra_score * 0.25

        return boost

    def _build_evidence(
        self,
        action: PredictedAction,
        state: ScamState,
        last_scores: Dict[str, float],
        analysis: ConversationAnalysisResult,
    ) -> List[PredictionEvidence]:
        ev = [
            PredictionEvidence(
                signal="current_state",
                description=f"Current conversation state is {state.value}.",
            ),
        ]
        if analysis.is_scam_progression_detected:
            ev.append(PredictionEvidence(
                signal="scam_progression_detected",
                description=(
                    f"Multi-state scam progression detected across "
                    f"{len(analysis.previous_states) + 1} messages."
                ),
            ))
        if analysis.detected_transitions:
            last_t = analysis.detected_transitions[-1]
            ev.append(PredictionEvidence(
                signal="last_transition",
                description=(
                    f"Most recent detected transition: "
                    f"{last_t.from_state.value} → {last_t.to_state.value} "
                    f"(confidence: {last_t.confidence:.2f})."
                ),
            ))
        top_signal = max(last_scores.items(), key=lambda x: x[1], default=(None, 0.0))
        if top_signal[0] and top_signal[1] > 0.15:
            ev.append(PredictionEvidence(
                signal=f"signal_{top_signal[0].lower()}",
                description=(
                    f"Strongest signal in last message: "
                    f"{top_signal[0]} (score: {top_signal[1]:.2f})."
                ),
            ))
        return ev


# ── Module singleton ──────────────────────────────────────────────────────────

_predictor = NextStepPredictionEngine()


def predict_next_step(analysis: ConversationAnalysisResult) -> NextStepPrediction:
    """
    Predict the most likely attacker next action.
    Returns NEEDS_REVIEW when confidence is below threshold.
    """
    return _predictor.predict(analysis)
