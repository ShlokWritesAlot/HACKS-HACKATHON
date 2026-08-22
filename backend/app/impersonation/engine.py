"""
Brand & Government Impersonation Detection Engine for BhashaRakshak.

SECURITY INVARIANTS:
  - 100% static domain validation against TrustedOrgRegistry.
  - ZERO network, HTTP, or DNS resolution requests are made.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from app.impersonation.registry import TrustedOrgRegistry, get_trusted_registry
from app.impersonation.schemas import BrandImpersonationResult, LegitimateReferenceInformation

logger = logging.getLogger(__name__)


class BrandImpersonationEngine:
    """
    Detects brand, banking, telecom, tax, and government impersonation.
    """

    def __init__(self, registry: Optional[TrustedOrgRegistry] = None):
        self._registry = registry or get_trusted_registry()

    def analyze(
        self,
        raw_text: str,
        cleaned_text: str,
        sender_id: Optional[str] = None,
        extracted_urls: Optional[List[str]] = None,
    ) -> BrandImpersonationResult:
        lower_raw = raw_text.lower()
        lower_clean = cleaned_text.lower()

        # 1. Extract URLs & Domains statically
        urls = extracted_urls or re.findall(
            r"https?://\S+|www\.\S+|bit\.ly/\S+|t\.co/\S+|\S+\.(?:xyz|click|top|live|info|site|com|org|net|in|sbi)",
            raw_text,
            re.IGNORECASE,
        )

        extracted_domains: List[str] = []
        for u in urls:
            d = u.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0].split("?")[0].strip().lower()
            if d:
                extracted_domains.append(d)

        # 2. Detect Claimed Organizations
        claimed_orgs = []
        for org in self._registry.get_all_orgs():
            # Check text aliases
            matched_alias = None
            for alias in org.aliases:
                if re.search(r"\b" + re.escape(alias.lower()) + r"\b", lower_clean) or alias.lower() in lower_raw:
                    matched_alias = alias
                    break
            # Check sender ID
            matched_sender = False
            if sender_id:
                clean_sender = sender_id.upper().replace("-", "")
                if any(sid in clean_sender for sid in org.legitimate_sender_ids):
                    matched_sender = True

            if matched_alias or matched_sender:
                claimed_orgs.append(org)

        if not claimed_orgs:
            return BrandImpersonationResult(
                claimed_brand=None,
                impersonation_detected=False,
                confidence=0.95,
                supporting_evidence=["No registered brand or government organization claims detected in text."],
                legitimate_reference_information=None,
            )

        # Analyze primary claimed org
        primary_org = claimed_orgs[0]
        evidence: List[str] = []
        impersonation_detected = False
        confidence = 0.85

        evidence.append(f"Detected brand claim representing '{primary_org.canonical_name}' ({primary_org.category.value}).")

        # 3. Domain Whitelist vs. Lookalike / Homoglyph Inspection
        has_phishing_link = False
        has_verified_link = False

        for domain in extracted_domains:
            is_legit = any(domain == leg or domain.endswith("." + leg) for leg in primary_org.legitimate_domains)

            if is_legit:
                has_verified_link = True
                evidence.append(f"Verified official domain present: '{domain}' (matches {primary_org.canonical_name}).")
            else:
                # Check if domain contains brand name or homoglyph or lookalike
                contains_brand = any(alias.lower() in domain for alias in primary_org.aliases if len(alias) >= 3)
                is_punycode = domain.startswith("xn--") or "ın" in domain or "gòog" in domain

                if contains_brand or is_punycode or any(tld in domain for tld in [".xyz", ".click", ".top", ".live", ".info"]):
                    impersonation_detected = True
                    has_phishing_link = True
                    confidence = 0.96
                    evidence.append(f"Malicious lookalike or spoofed domain detected: '{domain}' (impersonating {primary_org.canonical_name}).")

        # 4. Check DLT Sender ID Mismatch
        if sender_id:
            clean_sender = sender_id.upper().replace("-", "")
            matches_claimed_sender = any(sid in clean_sender for sid in primary_org.legitimate_sender_ids)

            if not matches_claimed_sender and len(claimed_orgs) >= 1:
                # Check if sender ID belongs to a DIFFERENT org
                other_org = None
                for org in self._registry.get_all_orgs():
                    if org.org_id != primary_org.org_id and any(sid in clean_sender for sid in org.legitimate_sender_ids):
                        other_org = org
                        break

                if other_org:
                    impersonation_detected = True
                    confidence = 0.98
                    evidence.append(f"Sender ID Mismatch: Header '{sender_id}' belongs to '{other_org.canonical_name}', but text claims '{primary_org.canonical_name}'.")

        # 5. Phishing Pressure Context
        has_urgency_or_threat = bool(re.search(r"\b(block|suspend|deactivate|expire|kyc|pan|aadhaar|immediately|cut)\b", lower_clean))

        if has_phishing_link or (has_urgency_or_threat and not has_verified_link):
            impersonation_detected = True
            if not has_phishing_link:
                evidence.append(f"Coercive urgency threat issued under '{primary_org.canonical_name}' brand without verified official domain.")
        elif not has_phishing_link and not has_urgency_or_threat:
            # Coincidental brand mention without phishing CTA or threat language
            impersonation_detected = False
            confidence = 0.90
            evidence.append(f"Coincidental or neutral mention of '{primary_org.canonical_name}' without phishing links or coercive pressure.")

        # Reference Information
        ref_info = LegitimateReferenceInformation(
            canonical_name=primary_org.canonical_name,
            category=primary_org.category.value,
            legitimate_domains=primary_org.legitimate_domains,
            verified_sender_ids=primary_org.legitimate_sender_ids,
            official_support_url=primary_org.official_support_url,
        )

        return BrandImpersonationResult(
            claimed_brand=primary_org.canonical_name,
            impersonation_detected=impersonation_detected,
            confidence=confidence,
            supporting_evidence=evidence,
            legitimate_reference_information=ref_info,
        )
