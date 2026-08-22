"""
Verified Evidence Detectors for BhashaRakshak.

ALL evidence items originate from Python rule/pattern/intel detectors or verified ML signals.
The LLM is NOT permitted to invent evidence items.
"""

from __future__ import annotations

import re
import uuid
from typing import List, Optional

from app.evidence.schemas import EvidenceCategoryEnum, StructuredEvidenceItem


def _make_ev_id() -> str:
    return f"ev_{uuid.uuid4().hex[:8]}"


# ── 1. OTP Request Detector ───────────────────────────────────────────────────

_OTP_PATTERN = re.compile(
    r"\b(otp|one\s*time\s*pass(?:word)?|pin|verification\s*code|auth\s*code|security\s*code)\b",
    re.IGNORECASE,
)

def detect_otp_request(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    m = _OTP_PATTERN.search(cleaned_text) or _OTP_PATTERN.search(raw_text)
    if m:
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.OTP_REQUEST,
            detector="detector_otp_pattern",
            description="Detected request or reference to One-Time Password (OTP) or security PIN.",
            severity_contribution=45.0,
            confidence=0.95,
            source_span=m.group(0),
            normalized_value=m.group(0).upper(),
            is_deterministic=True,
        )
    return None


# ── 2. Urgency Language Detector ──────────────────────────────────────────────

_URGENCY_PATTERN = re.compile(
    r"\b(urgent(?:ly)?|immediately|today|tonight|24\s*hours?|12\s*hours?|within\s*\d+\s*min(?:ute)?s?|expire[sd]?|last\s*notice|final\s*warning)\b",
    re.IGNORECASE,
)

def detect_urgency_language(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    m = _URGENCY_PATTERN.search(cleaned_text) or _URGENCY_PATTERN.search(raw_text)
    if m:
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.URGENCY_LANGUAGE,
            detector="detector_urgency_language",
            description="High psychological time-pressure language detected.",
            severity_contribution=25.0,
            confidence=0.90,
            source_span=m.group(0),
            normalized_value=m.group(0).lower(),
            is_deterministic=True,
        )
    return None


from app.impersonation.engine import BrandImpersonationEngine

_brand_engine = BrandImpersonationEngine()

def detect_bank_impersonation(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    res = _brand_engine.analyze(raw_text=raw_text, cleaned_text=cleaned_text)
    if not res.claimed_brand:
        return None
    ev_msg = res.supporting_evidence[0] if res.supporting_evidence else f"Brand claim detected: '{res.claimed_brand}'"
    # Scale severity contribution: higher if impersonation confirmed, lower for neutral mention
    severity_contribution = 40.0 if res.impersonation_detected else 18.0
    confidence = res.confidence if res.impersonation_detected else 0.70
    return StructuredEvidenceItem(
        evidence_id=_make_ev_id(),
        category=EvidenceCategoryEnum.BANK_IMPERSONATION,
        detector="detector_brand_impersonation_engine",
        description=ev_msg,
        severity_contribution=severity_contribution,
        confidence=confidence,
        source_span=res.claimed_brand,
        normalized_value=res.claimed_brand.upper(),
        is_deterministic=True,
    )


# ── 4. Suspicious Domain Detector ─────────────────────────────────────────────

_DOMAIN_PATTERN = re.compile(
    r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|www\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|([a-zA-Z0-9.-]+\.(?:xyz|click|top|live|info|online|site|club|work|link))",
    re.IGNORECASE,
)

def detect_suspicious_domain(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    m = _DOMAIN_PATTERN.search(cleaned_text) or _DOMAIN_PATTERN.search(raw_text)
    if m:
        domain = m.group(0)
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.SUSPICIOUS_DOMAIN,
            detector="detector_url_threat_intel",
            description=f"Unverified or suspicious domain detected in text: {domain}",
            severity_contribution=40.0,
            confidence=0.94,
            source_span=domain,
            normalized_value=domain.lower(),
            is_deterministic=True,
        )
    return None


# ── 5. UPI / Payment Request Detector ─────────────────────────────────────────

_UPI_PATTERN = re.compile(
    r"[\w.-]+@(okaxis|paytm|ybl|oksbi|ibl|axl|upi|barodampay|mahb|postbank)",
    re.IGNORECASE,
)

def detect_upi_request(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    m = _UPI_PATTERN.search(cleaned_text) or _UPI_PATTERN.search(raw_text)
    if m:
        vpa = m.group(0)
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.UPI_REQUEST,
            detector="detector_upi_vpa_extractor",
            description=f"Direct UPI payment handle (VPA) detected: {vpa}",
            severity_contribution=30.0,
            confidence=0.96,
            source_span=vpa,
            normalized_value=vpa.lower(),
            is_deterministic=True,
        )
    return None


# ── 6. Remote Access Software Detector ────────────────────────────────────────

_REMOTE_PATTERN = re.compile(
    r"\b(anydesk|teamviewer|quicksupport|rustdesk|any\s*desk|team\s*viewer)\b",
    re.IGNORECASE,
)

def detect_remote_access(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    m = _REMOTE_PATTERN.search(cleaned_text) or _REMOTE_PATTERN.search(raw_text)
    if m:
        app_name = m.group(0)
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.REMOTE_ACCESS,
            detector="detector_remote_access_software",
            description=f"High-risk remote desktop control software requested: {app_name}",
            severity_contribution=50.0,
            confidence=0.98,
            source_span=app_name,
            normalized_value=app_name.lower(),
            is_deterministic=True,
        )
    return None


# ── 7. Account Block Threat Detector ──────────────────────────────────────────

_BLOCK_PATTERN = re.compile(
    r"\b(block(?:ed)?|suspend(?:ed)?|deactivat(?:ed|ion)?|close[sd]?|cut|terminated?)\b",
    re.IGNORECASE,
)

def detect_account_block_threat(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    m = _BLOCK_PATTERN.search(cleaned_text) or _BLOCK_PATTERN.search(raw_text)
    if m:
        word = m.group(0)
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.ACCOUNT_BLOCK_THREAT,
            detector="detector_account_suspension_threat",
            description="Coercive threat of account or service disconnection detected.",
            severity_contribution=35.0,
            confidence=0.91,
            source_span=word,
            normalized_value=word.lower(),
            is_deterministic=True,
        )
    return None


# ── 8. Credential Request Detector ────────────────────────────────────────────

_CREDENTIAL_PATTERN = re.compile(
    r"\b(pass(?:word)?|cvv|card\s*number|netbanking|login\s*details|user(?:id|name)?)\b",
    re.IGNORECASE,
)

def detect_credential_request(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    m = _CREDENTIAL_PATTERN.search(cleaned_text) or _CREDENTIAL_PATTERN.search(raw_text)
    if m:
        word = m.group(0)
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.CREDENTIAL_REQUEST,
            detector="detector_credential_harvesting",
            description="Attempt to harvest confidential banking or account credentials.",
            severity_contribution=45.0,
            confidence=0.93,
            source_span=word,
            normalized_value=word.lower(),
            is_deterministic=True,
        )
    return None


# ── 9. Homoglyph / Spoofed Domain Detector ────────────────────────────────────

_HOMOGLYPH_PATTERN = re.compile(
    r"\b(sbi-kyc|hdfc-verify|icici-update|paytm-kyc|ybl-update|fedex-customs|bijli-pay)\b",
    re.IGNORECASE,
)

def detect_homoglyph_domain(raw_text: str, cleaned_text: str) -> Optional[StructuredEvidenceItem]:
    m = _HOMOGLYPH_PATTERN.search(cleaned_text) or _HOMOGLYPH_PATTERN.search(raw_text)
    if m:
        spoofed = m.group(0)
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.HOMOGLYPH_DOMAIN,
            detector="detector_homoglyph_spoofing",
            description=f"Brand impersonation domain keyword detected: {spoofed}",
            severity_contribution=40.0,
            confidence=0.95,
            source_span=spoofed,
            normalized_value=spoofed.lower(),
            is_deterministic=True,
        )
    return None


# ── 10. Obfuscation Detected Detector ──────────────────────────────────────────

def detect_obfuscation(transformations: List) -> Optional[StructuredEvidenceItem]:
    if transformations and len(transformations) > 0:
        names = [str(getattr(t, "type", t)) for t in transformations[:3]]
        return StructuredEvidenceItem(
            evidence_id=_make_ev_id(),
            category=EvidenceCategoryEnum.OBFUSCATION_DETECTED,
            detector="detector_text_deobfuscator",
            description=f"Detected {len(transformations)} text obfuscation technique(s) (e.g. {', '.join(names)}).",
            severity_contribution=20.0,
            confidence=0.89,
            source_span=None,
            normalized_value=f"count={len(transformations)}",
            is_deterministic=True,
        )
    return None


def run_all_detectors(raw_text: str, cleaned_text: str, transformations: List = None) -> List[StructuredEvidenceItem]:
    """Run all verified deterministic detectors against text."""
    evidence_list: List[StructuredEvidenceItem] = []

    detectors = [
        detect_otp_request(raw_text, cleaned_text),
        detect_urgency_language(raw_text, cleaned_text),
        detect_bank_impersonation(raw_text, cleaned_text),
        detect_suspicious_domain(raw_text, cleaned_text),
        detect_upi_request(raw_text, cleaned_text),
        detect_remote_access(raw_text, cleaned_text),
        detect_account_block_threat(raw_text, cleaned_text),
        detect_credential_request(raw_text, cleaned_text),
        detect_homoglyph_domain(raw_text, cleaned_text),
        detect_obfuscation(transformations or []),
    ]

    for item in detectors:
        if item is not None:
            evidence_list.append(item)

    return evidence_list
