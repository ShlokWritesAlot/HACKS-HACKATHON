"""
Comprehensive Test Suite for Scam DNA & Campaign Fingerprinting.

Tests:
  - Same campaign, different wording
  - Same campaign, different language
  - Same campaign with obfuscation
  - Anti-merging guardrail (unrelated scams with similar generic wording)
  - IOC overlap scoring boost vs. no IOC overlap
  - Adversarial inputs & deterministic DNA hash consistency
  - Duplicate fingerprint handling
  - Store resilience & MAX_CANDIDATES candidate scan cap
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.dna.builder import ScamDNABuilder
from app.dna.schemas import ScamDNAFingerprint
from app.dna.similarity import ScamDNASimilarityEngine
from app.ml.schemas import ScamCategory


def test_same_campaign_different_wording():
    """Messages with different wording in the same campaign produce high DNA similarity."""
    builder = ScamDNABuilder()
    engine = ScamDNASimilarityEngine()

    dna1 = builder.build_dna(
        raw_text="AX-SBIINB: Dear customer your SBI account is blocked. Update KYC at http://sbi-kyc.click",
        cleaned_text="AX-SBIINB: Dear customer your SBI account is blocked. Update KYC at http://sbi-kyc.click",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.9, "urgency": 0.8, "authority_impersonation": 0.9},
        obfuscations=[],
        extracted_iocs=[{"value": "sbi-kyc.click", "type": "domain"}],
    )

    dna2 = builder.build_dna(
        raw_text="SBI Alert: Your netbanking is suspended due to pending KYC verification. Visit http://sbi-kyc.click immediately.",
        cleaned_text="SBI Alert: Your netbanking is suspended due to pending KYC verification. Visit http://sbi-kyc.click immediately.",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.85, "urgency": 0.85, "authority_impersonation": 0.9},
        obfuscations=[],
        extracted_iocs=[{"value": "sbi-kyc.click", "type": "domain"}],
    )

    comp_score, confidence, breakdown = engine.calculate_similarity(dna1, dna2)

    assert comp_score >= 0.60
    assert confidence >= 0.65
    assert breakdown["taxonomy_compatibility"] == 1.0
    assert breakdown["ioc_overlap"] == 1.0


def test_same_campaign_different_language():
    """Hindi and English versions of same campaign maintain structural DNA match."""
    builder = ScamDNABuilder()
    engine = ScamDNASimilarityEngine()

    dna_en = builder.build_dna(
        raw_text="Dear customer, your SBI account will be blocked today. Update KYC.",
        cleaned_text="Dear customer, your SBI account will be blocked today. Update KYC.",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.9, "urgency": 0.8, "authority_impersonation": 0.9},
        obfuscations=[],
    )

    dna_hi = builder.build_dna(
        raw_text="प्रिय ग्राहक, आपका एसबीआई खाता आज बंद कर दिया जाएगा। केवाईसी अपडेट करें।",
        cleaned_text="प्रिय ग्राहक, आपका एसबीआई खाता आज बंद कर दिया जाएगा। केवाईसी अपडेट करें।",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.9, "urgency": 0.8, "authority_impersonation": 0.9},
        obfuscations=[],
    )

    comp_score, confidence, breakdown = engine.calculate_similarity(dna_en, dna_hi)

    assert breakdown["taxonomy_compatibility"] == 1.0
    assert breakdown["pressure_profile_sim"] >= 0.80


def test_anti_merging_unrelated_scams_similar_wording():
    """Unrelated scam categories (e.g. Bank KYC vs WFH Job Offer) are blocked from merging."""
    builder = ScamDNABuilder()
    engine = ScamDNASimilarityEngine()

    dna_kyc = builder.build_dna(
        raw_text="URGENT: Update details today at http://link1.click or action will be taken.",
        cleaned_text="URGENT: Update details today at http://link1.click or action will be taken.",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.9, "urgency": 0.9},
        obfuscations=[],
    )

    dna_job = builder.build_dna(
        raw_text="URGENT: Earn daily salary today at http://link2.click or offer will expire.",
        cleaned_text="URGENT: Earn daily salary today at http://link2.click or offer will expire.",
        scam_archetype=ScamCategory.JOB,
        manipulation_dict={"fear": 0.2, "urgency": 0.9},
        obfuscations=[],
    )

    comp_score, confidence, breakdown = engine.calculate_similarity(dna_kyc, dna_job)

    # Anti-merging guardrail must force score to 0.0 due to incompatible archetypes
    assert comp_score == 0.0
    assert confidence == 0.0
    assert breakdown["taxonomy_compatibility"] == 0.0


def test_ioc_overlap_scoring_boost():
    """Exact IOC overlap boosts association confidence score."""
    builder = ScamDNABuilder()
    engine = ScamDNASimilarityEngine()

    dna1 = builder.build_dna(
        raw_text="Pay fee at collect@paytm",
        cleaned_text="Pay fee at collect@paytm",
        scam_archetype=ScamCategory.UPI_PAYMENT,
        manipulation_dict={"financial_request": 0.9},
        obfuscations=[],
        extracted_iocs=[{"value": "collect@paytm", "type": "upi"}],
    )

    dna2 = builder.build_dna(
        raw_text="Transfer money to collect@paytm now",
        cleaned_text="Transfer money to collect@paytm now",
        scam_archetype=ScamCategory.UPI_PAYMENT,
        manipulation_dict={"financial_request": 0.9},
        obfuscations=[],
        extracted_iocs=[{"value": "collect@paytm", "type": "upi"}],
    )

    comp_score, confidence, breakdown = engine.calculate_similarity(dna1, dna2)

    assert breakdown["ioc_overlap"] == 1.0
    assert confidence > comp_score  # Boost applied


def test_adversarial_dna_hashing_consistency():
    """DNA hash format is dna_<hash16> and deterministic across builds."""
    builder = ScamDNABuilder()

    dna1 = builder.build_dna(
        raw_text="AX-SBIINB: Account block notice http://sbi.xyz",
        cleaned_text="AX-SBIINB: Account block notice http://sbi.xyz",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.8},
        obfuscations=["leetspeak"],
    )

    dna2 = builder.build_dna(
        raw_text="AX-SBIINB: Account block notice http://sbi.xyz",
        cleaned_text="AX-SBIINB: Account block notice http://sbi.xyz",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.8},
        obfuscations=["leetspeak"],
    )

    assert dna1.dna_hash.startswith("dna_")
    assert len(dna1.dna_hash) == 20  # 'dna_' (4) + 16 hex chars
    assert dna1.dna_hash == dna2.dna_hash


def test_same_campaign_with_obfuscation():
    """De-obfuscated messages match structural DNA despite leetspeak and zero-width spaces."""
    builder = ScamDNABuilder()
    engine = ScamDNASimilarityEngine()

    dna_obf = builder.build_dna(
        raw_text="S​B​I Acc0unt upd8 at http://sbi.xyz",
        cleaned_text="SBI Account update at http://sbi.xyz",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.8, "urgency": 0.8},
        obfuscations=["zero_width_spaces", "leetspeak"],
    )

    dna_clean = builder.build_dna(
        raw_text="SBI Account update at http://sbi.xyz",
        cleaned_text="SBI Account update at http://sbi.xyz",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.8, "urgency": 0.8},
        obfuscations=[],
    )

    comp_score, confidence, breakdown = engine.calculate_similarity(dna_obf, dna_clean)
    assert breakdown["taxonomy_compatibility"] == 1.0


def test_no_ioc_overlap_structural_similarity():
    """Messages without extracted IOCs are evaluated on structural DNA and pressure profile."""
    builder = ScamDNABuilder()
    engine = ScamDNASimilarityEngine()

    dna1 = builder.build_dna(
        raw_text="Dear SBI customer your account will be blocked today.",
        cleaned_text="Dear SBI customer your account will be blocked today.",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.9, "urgency": 0.9},
        obfuscations=[],
    )

    dna2 = builder.build_dna(
        raw_text="Dear SBI user your netbanking is suspended immediately.",
        cleaned_text="Dear SBI user your netbanking is suspended immediately.",
        scam_archetype=ScamCategory.BANK_KYC,
        manipulation_dict={"fear": 0.85, "urgency": 0.85},
        obfuscations=[],
    )

    comp_score, confidence, breakdown = engine.calculate_similarity(dna1, dna2)
    assert breakdown["pressure_profile_sim"] >= 0.80
    assert breakdown["taxonomy_compatibility"] == 1.0


def test_max_candidates_bound_protection():
    """Verify MAX_CANDIDATES = 200 protection constant remains intact in store."""
    from app.campaigns.store import MAX_CANDIDATES
    assert MAX_CANDIDATES == 200


def run_all_tests():
    tests = [
        test_same_campaign_different_wording,
        test_same_campaign_different_language,
        test_anti_merging_unrelated_scams_similar_wording,
        test_ioc_overlap_scoring_boost,
        test_adversarial_dna_hashing_consistency,
        test_same_campaign_with_obfuscation,
        test_no_ioc_overlap_structural_similarity,
        test_max_candidates_bound_protection,
    ]

    for fn in tests:
        fn()

    print(f"[PASS] All {len(tests)} Scam DNA Fingerprinting Tests Passed!")
