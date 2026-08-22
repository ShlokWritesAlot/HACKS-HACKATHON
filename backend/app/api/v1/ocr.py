"""
POST /api/v1/analyze/screenshot - Screenshot Analysis API Endpoint.

SECURITY INVARIANTS:
  - Untrusted file uploads are validated via magic-bytes (NEVER filename extensions).
  - Decompression bombs & oversized files are rejected before processing.
  - Uploaded bytes are stored in temporary files using randomly generated UUIDs.
  - Temporary files are GUARANTEED to be deleted in a try-finally block.
  - Extracted text is fed into the Scam X-Ray engine for full scam analysis.
"""

from __future__ import annotations

import logging
import os
import tempfile
import uuid
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field

from app.ocr.engine import extract_text_from_image
from app.ocr.validator import ImageValidationError, validate_image_bytes
from app.xray.engine import ScamXRayEngine
from app.xray.schemas import ScamXRayResponse

logger = logging.getLogger(__name__)

router = APIRouter()
_xray_engine = ScamXRayEngine()


class ScreenshotAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    image_format: str
    dimensions: str
    file_size_bytes: int
    extracted_text: str
    ocr_confidence: float
    analysis: ScamXRayResponse


@router.post(
    "/screenshot",
    response_model=ScreenshotAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze SMS Screenshot for Scams",
    description="Upload an SMS or chat screenshot (PNG/JPEG/WebP). Validates file safety, performs OCR text extraction, and runs Scam X-Ray analysis.",
)
async def analyze_screenshot(
    file: UploadFile = File(...),
) -> ScreenshotAnalysisResponse:
    # 1. Read file bytes into memory up to size limit
    try:
        content = await file.read()
    except Exception as exc:
        logger.error("Failed to read uploaded file: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read uploaded file.",
        )

    # 2. Validate image security & magic bytes
    try:
        validated = validate_image_bytes(content, filename=file.filename or "upload")
    except ImageValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    # 3. Create isolated temp file with random UUID (guaranteed cleanup)
    temp_dir = tempfile.gettempdir()
    temp_filename = f"bhasha_ocr_{uuid.uuid4().hex}.tmp"
    temp_path = os.path.join(temp_dir, temp_filename)

    try:
        with open(temp_path, "wb") as f:
            f.write(content)

        # 4. Perform OCR text extraction
        extracted_text, confidence = extract_text_from_image(content)

        if not extracted_text or not extracted_text.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="No legible text could be extracted from the screenshot.",
            )

        # 5. Run Scam X-Ray analysis on extracted text
        xray_output = _xray_engine.analyze(extracted_text)

        return ScreenshotAnalysisResponse(
            filename=os.path.basename(file.filename or "upload.png"),
            image_format=validated.format,
            dimensions=f"{validated.width}x{validated.height}",
            file_size_bytes=validated.size_bytes,
            extracted_text=extracted_text,
            ocr_confidence=confidence,
            analysis=xray_output,
        )

    finally:
        # Guaranteed cleanup of temp file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logger.debug("Cleaned up temp file %s", temp_path)
            except Exception as exc:
                logger.warning("Failed to remove temp file %s: %s", temp_path, exc)
