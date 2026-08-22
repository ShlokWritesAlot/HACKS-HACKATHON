from __future__ import annotations

import asyncio
import uuid
from typing import List

from fastapi import APIRouter, Depends, status

from app.api.v1.analyze import get_xray_engine
from app.playground.generator import AdversarialVariantGenerator
from app.playground.schemas import (
    PlaygroundRequest,
    PlaygroundResponse,
    RedTeamEvaluationReport,
    RedTeamRequest,
    VariantEvaluation,
)
from app.xray.engine import ScamXRayEngine

router = APIRouter()


@router.post(
    "/simulate",
    response_model=PlaygroundResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate Adversarial Scam Variants & Compute Robustness",
    description="Generates controlled, meaning-preserving adversarial variants of a scam template and evaluates detector resilience.",
)
async def simulate_adversarial_playground(
    request: PlaygroundRequest,
    engine: ScamXRayEngine = Depends(get_xray_engine),
) -> PlaygroundResponse:
    # 1. Baseline analysis on the original message
    baseline_result = await asyncio.to_thread(engine.analyze, request.message)
    baseline_family = (
        baseline_result.scam_family.value
        if hasattr(baseline_result.scam_family, "value")
        else str(baseline_result.scam_family)
    )
    baseline_score = baseline_result.risk_score

    # 2. Instantiate generator with reproducible seed
    generator = AdversarialVariantGenerator(seed=request.seed if request.seed is not None else 42)
    generated_variants = generator.generate_all_variants(
        text=request.message,
        perturbations=request.perturbations,
        intensity=request.intensity,
    )

    # 3. Concurrently evaluate each variant through the Scam X-Ray engine
    evaluations: List[VariantEvaluation] = []
    detected_count = 0

    semaphore = asyncio.Semaphore(10)

    async def _evaluate_variant(p_type, p_name, variant_text) -> VariantEvaluation:
        async with semaphore:
            xray = await asyncio.to_thread(engine.analyze, variant_text)
            predicted_family = (
                xray.scam_family.value
                if hasattr(xray.scam_family, "value")
                else str(xray.scam_family)
            )
            # A variant is considered correctly detected if it remains flagged as a threat (risk_score >= 40)
            is_detected = xray.risk_score >= 40

            return VariantEvaluation(
                variant_id=str(uuid.uuid4()),
                variant_text=variant_text,
                perturbation_type=p_type,
                perturbation_name=p_name,
                predicted_scam_family=predicted_family,
                risk_score=xray.risk_score,
                risk_level=xray.risk_level.value if hasattr(xray.risk_level, "value") else str(xray.risk_level),
                confidence=round(xray.risk_score / 100.0, 2),
                is_detected_as_scam=is_detected,
                cleaned_text=xray.cleaned_text,
            )

    tasks = [
        _evaluate_variant(p_type, p_name, var_text)
        for p_type, p_name, var_text in generated_variants
    ]
    evaluations = await asyncio.gather(*tasks)

    detected_count = sum(1 for e in evaluations if e.is_detected_as_scam)
    total_count = len(evaluations)
    robustness_score = round((detected_count / total_count * 100.0), 1) if total_count > 0 else 100.0

    return PlaygroundResponse(
        original_message=request.message,
        baseline_scam_family=baseline_family,
        baseline_risk_score=baseline_score,
        total_variants=total_count,
        detected_variants=detected_count,
        robustness_score=robustness_score,
        variants=evaluations,
    )


@router.post(
    "/redteam",
    response_model=RedTeamEvaluationReport,
    status_code=status.HTTP_200_OK,
    summary="Adaptive Red-Team Iterative Stress-Test Evaluation",
    description="Executes an adaptive multi-depth mutation loop to profile detector robustness and failure modes.",
)
async def evaluate_redteam_playground(
    request: RedTeamRequest,
    engine: ScamXRayEngine = Depends(get_xray_engine),
) -> RedTeamEvaluationReport:
    from app.playground.redteam_engine import AdaptiveRedTeamEngine

    redteam = AdaptiveRedTeamEngine(xray_engine=engine)
    return await asyncio.to_thread(redteam.evaluate, request)
