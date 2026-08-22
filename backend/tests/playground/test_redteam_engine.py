"""
Comprehensive Test Suite for Adaptive Red-Team Evaluation Engine & 19 Perturbations.

Tests:
  - Generation of all 19 perturbation categories
  - Unicode confusables, zero-width chars, normalization attacks
  - Multilingual switching, nested obfuscation, OCR corruption
  - Realistic QWERTY typos, domain obfuscation, sender ID mutation
  - Iterative multi-depth red-team evaluation loop
  - Robustness score & confusion matrix calculation
  - HTML sanitization of failure examples
  - Regression testing (previously fixed vulnerabilities remain detected)
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.playground.generator import AdversarialVariantGenerator
from app.playground.redteam_engine import AdaptiveRedTeamEngine
from app.playground.schemas import PerturbationType, RedTeamRequest


def test_all_19_transformations_generation():
    """Generator must successfully generate variants across all 19 perturbation categories."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "Your SBI bank account is blocked. Update KYC at http://sbi.co.in immediately."

    results = gen.generate_all_variants(sample, intensity="medium")
    assert len(results) == 19

    types_generated = {r[0] for r in results}
    assert len(types_generated) == 19


def test_unicode_confusables():
    """Unicode confusable transformation replaces Latin chars with Cyrillic lookalikes."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "bank account update"
    variant = gen.unicode_confusables(sample, intensity="high")

    assert variant != sample
    assert any(ord(c) > 127 for c in variant)


def test_zero_width_chars():
    """Zero-width character transformation injects non-printable Unicode separators."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "SBIINB"
    variant = gen.zero_width_chars(sample, intensity="high")

    assert any(c in variant for c in ["\u200B", "\u200C", "\u200D", "\uFEFF"])


def test_unicode_normalization():
    """Unicode normalization attack injects combining diacritics."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "urgent update"
    variant = gen.unicode_normalization(sample, intensity="high")

    assert "\u0301" in variant or len(variant) > len(sample)


def test_multilingual_switching():
    """Multilingual switching combines English, Hindi Devanagari, and Hinglish."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "Your bank account will be blocked."
    variant = gen.multilingual_switching(sample, intensity="medium")

    assert "SBI" in variant or "KYC" in variant
    assert any("\u0900" <= c <= "\u097F" for c in variant)  # Devanagari range


def test_nested_obfuscation():
    """Nested obfuscation applies multi-layered recursive transformations."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "SBI bank account blocked"
    variant = gen.nested_obfuscation(sample, intensity="medium")

    assert variant != sample


def test_ocr_corruption():
    """OCR corruption replaces character pairs with visual OCR misrecognitions."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "learn clean account"
    variant = gen.ocr_corruption(sample)

    assert "m" in variant or "1" in variant or "d" in variant


def test_realistic_typos():
    """Realistic typos swap letters with QWERTY adjacent keys."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "urgent verification required"
    variant = gen.realistic_typos(sample, intensity="high")

    assert variant != sample


def test_domain_obfuscation():
    """Domain obfuscation obfuscates URLs with bracketed dots or hyphens."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "Visit http://sbi.co.in/update now"
    variant = gen.domain_obfuscation(sample)

    assert "[.]" in variant or "h**p" in variant


def test_sender_id_mutation():
    """Sender ID mutation prepends mutated DLT header representations."""
    gen = AdversarialVariantGenerator(seed=42)
    sample = "Your SBI account is blocked."
    variant = gen.sender_id_mutation(sample)

    assert "[Sender:" in variant


def test_adaptive_redteam_iterative_loop():
    """Red-team engine executes iterative mutation loop and returns comprehensive report metrics."""
    engine = AdaptiveRedTeamEngine()
    req = RedTeamRequest(
        message="Dear customer, your SBI account is blocked. Update KYC at http://sbi-kyc-update.xyz immediately.",
        max_depth=2,
        seed=42,
    )

    report = engine.evaluate(req)

    assert report.total_mutations_tested > 0
    assert 0.0 <= report.robustness_score <= 100.0
    assert isinstance(report.per_transformation_score, dict)
    assert isinstance(report.per_language_score, dict)
    assert report.confusion_matrix.true_positive >= 0
    assert len(report.iteration_history) == report.total_mutations_tested


def test_failure_examples_sanitization():
    """All stored failure examples are HTML-escaped to prevent script execution."""
    engine = AdaptiveRedTeamEngine()
    req = RedTeamRequest(
        message="<script>alert(1)</script> SBI account update",
        max_depth=1,
        seed=42,
    )

    report = engine.evaluate(req)

    for example in report.failure_examples:
        assert "<script>" not in example
        assert "&lt;script&gt;" in example or "<" not in example


def test_regression_fixed_vulnerabilities_remain_fixed():
    """Regression test: previously fixed obfuscated variants remain correctly detected as threats."""
    from app.xray.engine import ScamXRayEngine

    xray = ScamXRayEngine()
    vulnerable_variants = [
        "S.B.I Acc0unt upd8 at http://sbi-kyc.xyz",
        "SВI bаnk ассount block. Click http://sbi-unblock.top",
        "S\u200BB\u200BI\u200B account blocked. Visit http://sbiinb.xyz",
    ]

    for variant in vulnerable_variants:
        res = xray.analyze(variant)
        assert res.risk_score >= 40, f"Regression failure: Variant '{variant}' was not detected as threat!"


def run_all_tests():
    tests = [
        test_all_19_transformations_generation,
        test_unicode_confusables,
        test_zero_width_chars,
        test_unicode_normalization,
        test_multilingual_switching,
        test_nested_obfuscation,
        test_ocr_corruption,
        test_realistic_typos,
        test_domain_obfuscation,
        test_sender_id_mutation,
        test_adaptive_redteam_iterative_loop,
        test_failure_examples_sanitization,
        test_regression_fixed_vulnerabilities_remain_fixed,
    ]

    for fn in tests:
        fn()

    print(f"[PASS] All {len(tests)} Adaptive Red-Team Evaluation Tests Passed!")
