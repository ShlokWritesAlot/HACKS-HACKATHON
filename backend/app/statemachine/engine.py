"""
Scam Conversation State Machine — Core Engine.

Processes an ordered list of messages and produces a structured
state-machine analysis: current state, transitions, likely next state,
and per-message evidence.

SECURITY CONTRACT:
  - Messages are treated as fully UNTRUSTED DATA.
  - Text is HTML-escaped in schema validation layer.
  - Signal scoring is deterministic regex — not LLM-driven.
  - Prompt injection cannot alter state transitions (no LLM path).
  - Conversation length is capped at 100 messages (schema-enforced).
  - Timestamp ordering is validated; reversed/malformed timestamps produce a warning.
  - Duplicate messages are detected and collapsed with a warning.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from app.statemachine.schemas import (
    ConversationAnalysisRequest,
    ConversationAnalysisResult,
    ConversationMessage,
    DetectedTransition,
    MessageStateResult,
    ScamState,
    STATE_ORDER,
    StateEvidence,
)
from app.statemachine.signals import compute_signal_scores

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

# Minimum confidence to assign a non-UNKNOWN state
_MIN_STATE_CONFIDENCE = 0.20

# Minimum score delta from UNKNOWN → named state
_UNKNOWN_THRESHOLD = 0.15

# Adjacent-state transition bonus (scam progression is sequential)
_ADJACENCY_BONUS = 0.10

# Benign dampening — high benign score reduces overall scam confidence
_BENIGN_DAMPEN_FACTOR = 0.35

# Progression: 2+ ordered scam states = scam progression detected
_MIN_STATES_FOR_PROGRESSION = 2

# Likely-next thresholds
_ABSTAIN_NEXT_THRESHOLD = 0.30


# ── Transition Model ──────────────────────────────────────────────────────────
# Valid forward and short-skip transitions (state machine graph)
_VALID_TRANSITIONS = {
    ScamState.UNKNOWN:            {ScamState.CONTACT, ScamState.AUTHORITY_CLAIM, ScamState.FEAR_OR_URGENCY},
    ScamState.CONTACT:            {ScamState.TRUST_BUILDING, ScamState.AUTHORITY_CLAIM, ScamState.FEAR_OR_URGENCY},
    ScamState.TRUST_BUILDING:     {ScamState.AUTHORITY_CLAIM, ScamState.FEAR_OR_URGENCY, ScamState.CREDENTIAL_REQUEST},
    ScamState.AUTHORITY_CLAIM:    {ScamState.FEAR_OR_URGENCY, ScamState.CREDENTIAL_REQUEST, ScamState.PAYMENT_REQUEST},
    ScamState.FEAR_OR_URGENCY:    {ScamState.CREDENTIAL_REQUEST, ScamState.PAYMENT_REQUEST, ScamState.REMOTE_ACCESS},
    ScamState.CREDENTIAL_REQUEST: {ScamState.PAYMENT_REQUEST, ScamState.REMOTE_ACCESS, ScamState.ACCOUNT_TAKEOVER},
    ScamState.PAYMENT_REQUEST:    {ScamState.REMOTE_ACCESS, ScamState.ACCOUNT_TAKEOVER, ScamState.EXIT},
    ScamState.REMOTE_ACCESS:      {ScamState.ACCOUNT_TAKEOVER, ScamState.EXIT},
    ScamState.ACCOUNT_TAKEOVER:   {ScamState.EXIT},
    ScamState.EXIT:               set(),
}

# Likely next state predictions (probabilistic only)
_LIKELY_NEXT = {
    ScamState.CONTACT:            ScamState.TRUST_BUILDING,
    ScamState.TRUST_BUILDING:     ScamState.AUTHORITY_CLAIM,
    ScamState.AUTHORITY_CLAIM:    ScamState.FEAR_OR_URGENCY,
    ScamState.FEAR_OR_URGENCY:    ScamState.CREDENTIAL_REQUEST,
    ScamState.CREDENTIAL_REQUEST: ScamState.PAYMENT_REQUEST,
    ScamState.PAYMENT_REQUEST:    ScamState.REMOTE_ACCESS,
    ScamState.REMOTE_ACCESS:      ScamState.ACCOUNT_TAKEOVER,
    ScamState.ACCOUNT_TAKEOVER:   ScamState.EXIT,
    ScamState.EXIT:               None,
    ScamState.UNKNOWN:            ScamState.CONTACT,
}


class ScamStateMachine:
    """
    Probabilistic scam conversation state machine.

    Assigns a scam lifecycle state to each message, detects transitions,
    and estimates the likely next attacker action using deterministic signals.
    """

    def analyze(self, request: ConversationAnalysisRequest) -> ConversationAnalysisResult:
        warnings: List[str] = []

        # 1. Sort by timestamp if available; warn on reversed timestamps
        messages = self._sort_and_validate_timestamps(request.messages, warnings)

        # 2. Detect and warn on duplicate messages
        messages = self._deduplicate(messages, warnings)

        # 3. Per-message state assignment
        per_message: List[MessageStateResult] = []
        for idx, msg in enumerate(messages):
            result = self._assign_state(idx, msg)
            per_message.append(result)

        # 4. Compute conversation-level state trajectory
        states = [r.assigned_state for r in per_message]
        current_state = states[-1] if states else ScamState.UNKNOWN
        previous_states = states[:-1] if len(states) > 1 else []

        # 5. Detect transitions
        transitions = self._detect_transitions(per_message)

        # 6. Overall confidence = weighted mean of per-message confidences,
        #    dampened by benign signal
        raw_confidences = [r.state_confidence for r in per_message]
        overall_conf = sum(raw_confidences) / len(raw_confidences) if raw_confidences else 0.0

        # 7. Scam advancement score
        named_states = [s for s in states if s not in (ScamState.UNKNOWN, ScamState.EXIT)]
        if named_states:
            max_order = max(STATE_ORDER.get(s, 0) for s in named_states)
            advancement = max_order / (len(STATE_ORDER) - 2)  # exclude UNKNOWN & EXIT
        else:
            advancement = 0.0

        # 8. Progression detection
        ordered_scam_states = [
            s for s, conf in zip(states, [r.state_confidence for r in per_message])
            if s not in (ScamState.UNKNOWN,)
            and STATE_ORDER.get(s, -1) >= 0
            and conf >= 0.30  # Require meaningful confidence for progression
        ]
        is_progression = len(set(ordered_scam_states)) >= _MIN_STATES_FOR_PROGRESSION

        # 9. Likely next state prediction
        likely_next, next_reasoning = self._predict_next(current_state, overall_conf)

        return ConversationAnalysisResult(
            conversation_id=request.conversation_id,
            message_count=len(messages),
            current_state=current_state,
            previous_states=previous_states,
            overall_confidence=round(overall_conf, 3),
            detected_transitions=transitions,
            likely_next_state=likely_next,
            likely_next_state_reasoning=next_reasoning,
            per_message_results=per_message,
            is_scam_progression_detected=is_progression,
            scam_advancement_score=round(advancement, 3),
            warnings=warnings,
        )

    # ── Internal Methods ──────────────────────────────────────────────────────

    def _assign_state(self, idx: int, msg: ConversationMessage) -> MessageStateResult:
        raw = msg.text
        scores = compute_signal_scores(raw)
        benign_score = scores.pop("_benign", 0.0)

        # Find best matching scam state
        best_state = ScamState.UNKNOWN
        best_score = _UNKNOWN_THRESHOLD

        for state_name, score in scores.items():
            try:
                state = ScamState(state_name)
            except ValueError:
                continue
            if score > best_score:
                best_state = state
                best_score = score

        # Apply benign dampening
        confidence = best_score * (1.0 - benign_score * _BENIGN_DAMPEN_FACTOR)
        confidence = round(min(1.0, max(0.0, confidence)), 3)

        # Build evidence list
        evidence: List[StateEvidence] = []
        for state_name, score in scores.items():
            if score > 0.10:
                try:
                    s = ScamState(state_name)
                except ValueError:
                    continue
                evidence.append(StateEvidence(
                    signal=f"signal_{state_name.lower()}",
                    description=f"Pattern match for {state_name} state (score={score:.2f}).",
                    confidence_contribution=round(score, 3),
                ))
        if benign_score > 0.2:
            evidence.append(StateEvidence(
                signal="signal_benign_context",
                description=f"Benign customer-service context detected (dampening scam confidence by {benign_score:.2f}).",
                confidence_contribution=round(benign_score, 3),
            ))

        return MessageStateResult(
            message_index=idx,
            message_id=msg.message_id,
            assigned_state=best_state,
            state_confidence=confidence,
            supporting_evidence=evidence,
            signal_scores={k: round(v, 3) for k, v in scores.items()},
        )

    def _detect_transitions(
        self, per_message: List[MessageStateResult]
    ) -> List[DetectedTransition]:
        transitions: List[DetectedTransition] = []
        for i in range(1, len(per_message)):
            prev = per_message[i - 1]
            curr = per_message[i]
            if prev.assigned_state == curr.assigned_state:
                continue  # no transition
            if prev.assigned_state == ScamState.UNKNOWN or curr.assigned_state == ScamState.UNKNOWN:
                continue  # ignore UNKNOWN transitions

            # Assess if this is a valid forward transition
            valid = curr.assigned_state in _VALID_TRANSITIONS.get(prev.assigned_state, set())
            conf = (prev.state_confidence + curr.state_confidence) / 2.0
            if valid:
                conf = min(1.0, conf + _ADJACENCY_BONUS)

            trigger = (
                curr.supporting_evidence[0].signal
                if curr.supporting_evidence
                else "unknown_signal"
            )
            transitions.append(DetectedTransition(
                from_state=prev.assigned_state,
                to_state=curr.assigned_state,
                confidence=round(conf, 3),
                trigger_signal=trigger,
            ))
        return transitions

    def _predict_next(
        self, current_state: ScamState, overall_conf: float
    ) -> Tuple[Optional[ScamState], str]:
        if overall_conf < _ABSTAIN_NEXT_THRESHOLD or current_state == ScamState.UNKNOWN:
            return None, (
                "Insufficient confidence to predict next step. "
                "Manual review recommended."
            )

        next_state = _LIKELY_NEXT.get(current_state)
        if next_state is None:
            return None, "Conversation appears to have reached an exit state."

        reasoning_map = {
            ScamState.CONTACT: (
                "Likely next step: attacker will attempt to build trust by posing as an official entity."
            ),
            ScamState.TRUST_BUILDING: (
                "Likely next step: attacker may escalate to an authority claim (e.g., bank, government)."
            ),
            ScamState.AUTHORITY_CLAIM: (
                "Likely next step: attacker will likely introduce fear or urgency (e.g., account suspension threat)."
            ),
            ScamState.FEAR_OR_URGENCY: (
                "Likely next step: attacker may request sensitive credentials (OTP, PIN, KYC details)."
            ),
            ScamState.CREDENTIAL_REQUEST: (
                "Likely next step: after obtaining credentials, attacker may demand a payment or fee."
            ),
            ScamState.PAYMENT_REQUEST: (
                "Likely next step: if payment fails, attacker may attempt to gain remote access to victim's device."
            ),
            ScamState.REMOTE_ACCESS: (
                "Likely next step: attacker may attempt full account takeover using remote access."
            ),
            ScamState.ACCOUNT_TAKEOVER: (
                "Likely next step: attacker may attempt to exit conversation after completing account compromise."
            ),
        }
        reasoning = reasoning_map.get(
            current_state,
            f"Likely next step: progression toward {next_state.value} based on observed pattern.",
        )
        return next_state, reasoning

    def _sort_and_validate_timestamps(
        self, messages: List[ConversationMessage], warnings: List[str]
    ) -> List[ConversationMessage]:
        timestamped = [m for m in messages if m.timestamp is not None]
        if not timestamped:
            return messages  # preserve input order

        # Sort by timestamp
        sorted_msgs = sorted(messages, key=lambda m: (m.timestamp or datetime.min.replace(tzinfo=timezone.utc)))

        # Detect if input order differs from sorted order (i.e., timestamps were out-of-order)
        input_ts = [m.timestamp for m in messages if m.timestamp]
        for i in range(1, len(input_ts)):
            if input_ts[i] < input_ts[i - 1]:
                warnings.append(
                    "Reversed or inconsistent timestamps detected. "
                    "Messages were sorted by timestamp for analysis."
                )
                break

        return sorted_msgs

    def _deduplicate(
        self, messages: List[ConversationMessage], warnings: List[str]
    ) -> List[ConversationMessage]:
        seen: set = set()
        deduped: List[ConversationMessage] = []
        dup_count = 0
        for msg in messages:
            h = hashlib.sha256(msg.text.encode("utf-8")).hexdigest()
            if h in seen:
                dup_count += 1
            else:
                seen.add(h)
                deduped.append(msg)
        if dup_count > 0:
            warnings.append(
                f"{dup_count} duplicate message(s) detected and removed before analysis."
            )
        return deduped


# ── Module singleton ──────────────────────────────────────────────────────────

_engine = ScamStateMachine()


def analyze_conversation(request: ConversationAnalysisRequest) -> ConversationAnalysisResult:
    """Analyze a scam conversation using the state machine engine."""
    return _engine.analyze(request)
