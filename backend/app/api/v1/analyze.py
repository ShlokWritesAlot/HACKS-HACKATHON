from __future__ import annotations

import asyncio
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, status

from app.api.v1.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
)
from app.core.text.pipeline import detect_language_and_script
from app.db.repository import AnalysisRepository, get_repository
from app.xray.engine import ScamXRayEngine

router = APIRouter()

# Singleton engine instance
_xray_engine = ScamXRayEngine()

def get_xray_engine() -> ScamXRayEngine:
    return _xray_engine


def _convert_xray_to_response(xray_result, analysis_id: str | None = None) -> AnalyzeResponse:
    """Helper to convert ScamXRayResponse to full AnalyzeResponse schema with enriched subsystem intelligence."""
    lang, _ = detect_language_and_script(xray_result.cleaned_text)

    # 1. Threat Intelligence Extractor (IOCs & Static SSRF)
    extracted_iocs = []
    try:
        from app.intel.extractor import ThreatIntelligenceExtractor
        extractor = ThreatIntelligenceExtractor()
        extracted_iocs = [
            ioc.model_dump() if hasattr(ioc, "model_dump") else ioc.__dict__
            for ioc in extractor.extract_indicators(xray_result.original_text)
        ]
    except Exception:
        pass

    # 2. Brand & Government Impersonation Engine
    brand_info = None
    try:
        from app.impersonation.engine import BrandImpersonationEngine
        brand_engine = BrandImpersonationEngine()
        res = brand_engine.analyze(raw_text=xray_result.original_text, cleaned_text=xray_result.cleaned_text)
        brand_info = res.model_dump() if hasattr(res, "model_dump") else res.__dict__
    except Exception:
        pass

    # 3. Scam Conversation State Machine & Next-Step Prediction Engine
    conv_info = None
    try:
        from app.statemachine.engine import analyze_conversation
        from app.statemachine.prediction import predict_next_step
        from app.statemachine.schemas import ConversationAnalysisRequest, ConversationMessage

        req = ConversationAnalysisRequest(messages=[ConversationMessage(text=xray_result.original_text)])
        analysis_state = analyze_conversation(req)
        prediction = predict_next_step(analysis_state)
        conv_info = {
            "analysis": analysis_state.model_dump() if hasattr(analysis_state, "model_dump") else analysis_state.__dict__,
            "prediction": prediction.model_dump() if hasattr(prediction, "model_dump") else prediction.__dict__,
        }
    except Exception:
        pass

    # 4. 16-Dimensional Scam DNA Engine
    scam_dna = None
    try:
        from app.dna.builder import ScamDNABuilder
        from app.ml.schemas import ScamCategory
        dna_builder = ScamDNABuilder()
        # Resolve scam archetype — ScamDNABuilder uses ScamCategory not ScamFamily
        try:
            scam_cat_value = xray_result.scam_family.value if hasattr(xray_result.scam_family, 'value') else str(xray_result.scam_family)
            archetype = ScamCategory(scam_cat_value)
        except Exception:
            archetype = ScamCategory.SAFE
        manip = xray_result.manipulation
        manip_dict = manip.model_dump() if hasattr(manip, "model_dump") else (manip if isinstance(manip, dict) else {})
        obfus = xray_result.obfuscation if isinstance(xray_result.obfuscation, list) else []
        dna_obj = dna_builder.build_dna(
            raw_text=xray_result.original_text,
            cleaned_text=xray_result.cleaned_text,
            scam_archetype=archetype,
            manipulation_dict=manip_dict,
            obfuscations=obfus,
        )
        scam_dna = dna_obj.model_dump() if hasattr(dna_obj, "model_dump") else dna_obj.__dict__
    except Exception:
        pass

    kwargs = {
        "risk_score": xray_result.risk_score,
        "risk_level": xray_result.risk_level.value if hasattr(xray_result.risk_level, "value") else str(xray_result.risk_level),
        "scam_family": xray_result.scam_family.value if hasattr(xray_result.scam_family, "value") else str(xray_result.scam_family),
        "language": lang,
        "original_text": xray_result.original_text,
        "normalized_text": xray_result.cleaned_text,
        "decoded_meaning": xray_result.decoded_meaning,
        "manipulation_fingerprint": xray_result.manipulation,
        "obfuscation_fingerprint": xray_result.obfuscation,
        "evidence": xray_result.evidence,
        "structured_evidence": getattr(xray_result, "structured_evidence", []),
        "uncertainty": getattr(xray_result, "uncertainty", 0.05),
        "safe_action": xray_result.recommended_action,
        "model_version": "v1.0.0-xray",
        "extracted_iocs": extracted_iocs,
        "brand_impersonation": brand_info,
        "conversation_state": conv_info,
        "scam_dna": scam_dna,
    }
    if analysis_id:
        kwargs["analysis_id"] = analysis_id

    return AnalyzeResponse(**kwargs)


@router.post(
    "",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze suspicious SMS",
    description="Analyzes an SMS message for scam family, psychological manipulation, obfuscation, evidence, and safe actions.",
)
async def analyze_single_sms(
    request: AnalyzeRequest,
    engine: ScamXRayEngine = Depends(get_xray_engine),
    repo: AnalysisRepository = Depends(get_repository),
) -> AnalyzeResponse:
    try:
        xray_result = await asyncio.wait_for(
            asyncio.to_thread(engine.analyze, request.message),
            timeout=5.0
        )
        response = _convert_xray_to_response(xray_result)
        await repo.save_analysis(response)
        return response
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Inference analysis timed out after 5.0 seconds.",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal analysis error: {str(e)}",
        )


@router.post(
    "/batch",
    response_model=BatchAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch analyze multiple SMS messages",
    description="Processes up to 50 SMS messages concurrently with safety bounds.",
)
async def analyze_batch_sms(
    request: BatchAnalyzeRequest,
    engine: ScamXRayEngine = Depends(get_xray_engine),
    repo: AnalysisRepository = Depends(get_repository),
) -> BatchAnalyzeResponse:
    semaphore = asyncio.Semaphore(10)  # Max 10 concurrent processing threads

    async def _process_item(msg: str) -> AnalyzeResponse:
        async with semaphore:
            xray_result = await asyncio.wait_for(
                asyncio.to_thread(engine.analyze, msg),
                timeout=5.0
            )
            resp = _convert_xray_to_response(xray_result)
            await repo.save_analysis(resp)
            return resp

    try:
        tasks = [_process_item(m) for m in request.messages]
        results = await asyncio.gather(*tasks)
        return BatchAnalyzeResponse(
            results=results,
            total_processed=len(results),
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Batch analysis timed out.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch processing error: {str(e)}",
        )


@router.get(
    "/{analysis_id}",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Get past analysis by ID",
    description="Retrieves a historical analysis record by its unique UUID.",
)
async def get_analysis_by_id(
    analysis_id: str = Path(..., description="UUID of the analysis record"),
    repo: AnalysisRepository = Depends(get_repository),
) -> AnalyzeResponse:
    analysis = await repo.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis with ID '{analysis_id}' not found.",
        )
    return analysis
