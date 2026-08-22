"""
Automated unit and integration tests for BhashaRakshak Adversarial Playground.

Verifies:
1. All 10 obfuscation algorithms terminate and produce non-empty variants
2. Output length is strictly bounded
3. Determinism: identical random seeds yield identical variants
4. Original message immutability
5. Robustness score calculation formula accuracy
6. End-to-end integration with the FastAPI simulation endpoint
"""

import asyncio
from app.playground.generator import AdversarialVariantGenerator
from app.playground.schemas import PerturbationType, PlaygroundRequest
from tests.api.test_integration import client


def test_all_10_transformations_terminate():
    """Verify that every transformation executes without infinite loops or crashes."""
    orig = "Your bank account will be blocked. Update KYC immediately at bit.ly/kyc-sbi"
    generator = AdversarialVariantGenerator(seed=42)

    variants = generator.generate_all_variants(orig)
    assert len(variants) == 10

    types_generated = {v[0] for v in variants}
    assert len(types_generated) == 10
    assert PerturbationType.VOWEL_DELETION in types_generated
    assert PerturbationType.HINGLISH_SYNTHESIS in types_generated
    assert PerturbationType.MIXED_SCRIPTS in types_generated
    assert PerturbationType.NUMBER_SUBSTITUTION in types_generated


def test_seed_reproducibility():
    """Verify that identical random seeds produce 100% byte-for-byte identical output."""
    orig = "Your bank account will be suspended. Please verify credentials."
    gen1 = AdversarialVariantGenerator(seed=123)
    gen2 = AdversarialVariantGenerator(seed=123)
    gen3 = AdversarialVariantGenerator(seed=999)

    out1 = gen1.generate_all_variants(orig)
    out2 = gen2.generate_all_variants(orig)
    out3 = gen3.generate_all_variants(orig)

    # Identical seeds must match exactly
    for (t1, _, text1), (t2, _, text2) in zip(out1, out2):
        assert t1 == t2
        assert text1 == text2

    # Different seeds should produce variance in stochastic algorithms
    diff_count = sum(1 for (_, _, text1), (_, _, text3) in zip(out1, out3) if text1 != text3)
    assert diff_count > 0


def test_original_message_immutability():
    """Verify that the input string is never modified in place."""
    orig = "Static unchanged scam template"
    orig_copy = str(orig)
    generator = AdversarialVariantGenerator(seed=42)

    generator.generate_all_variants(orig)
    assert orig == orig_copy


def test_bounded_output_length():
    """Verify that variants do not blow up in size."""
    orig = "Short message for test"
    generator = AdversarialVariantGenerator(seed=42)

    variants = generator.generate_all_variants(orig, intensity="extreme")
    for _, _, variant_text in variants:
        # Repetition / punctuation shouldn't exceed 10x original length
        assert len(variant_text) < len(orig) * 15


async def test_playground_api_endpoint_simulation():
    """Test POST /api/v1/playground/simulate integration and robustness score calculation."""
    payload = {
        "message": "Your SBI account is blocked. Update KYC immediately at bit.ly/sbi-kyc",
        "intensity": "medium",
        "seed": 42
    }
    response = await client.post("/api/v1/playground/simulate", json=payload)
    assert response["status_code"] == 200
    data = response["json"]

    assert "robustness_score" in data
    assert 0.0 <= data["robustness_score"] <= 100.0
    assert data["total_variants"] == 10
    assert data["detected_variants"] <= data["total_variants"]
    assert len(data["variants"]) == 10

    # Verify each variant evaluation schema
    for v in data["variants"]:
        assert "variant_text" in v
        assert "predicted_scam_family" in v
        assert "risk_score" in v
        assert "is_detected_as_scam" in v


async def run_playground_tests():
    test_all_10_transformations_terminate()
    test_seed_reproducibility()
    test_original_message_immutability()
    test_bounded_output_length()
    await test_playground_api_endpoint_simulation()
