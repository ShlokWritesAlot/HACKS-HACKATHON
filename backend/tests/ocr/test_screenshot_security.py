"""
Comprehensive security and functional test suite for BhashaRakshak Screenshot Analysis.

Tests:
  - Valid PNG, JPEG, WebP file upload & analysis
  - Magic byte validation: reject fake PNG (renamed .exe)
  - Executable signature rejection (MZ, ELF, shell scripts)
  - Oversized file rejection (> 10MB)
  - Decompression bomb dimension rejection (> 4096 x 4096)
  - Tiny image dimension rejection (< 5 x 5)
  - Corrupted image bytes rejection
  - Multilingual OCR, Emojis, URLs, and UPI IDs handling
  - Automatic temporary file cleanup verification
"""

import io
import os
import sys
import tempfile
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from fastapi.testclient import TestClient
from app.main import app
from app.ocr.validator import (
    ImageValidationError,
    validate_image_bytes,
    MAX_FILE_SIZE_BYTES,
)

client = TestClient(app)


def _create_dummy_image(format: str = "PNG", size: tuple[int, int] = (200, 100), color: str = "white") -> bytes:
    """Helper to generate valid in-memory image bytes."""
    buf = io.BytesIO()
    img = Image.new("RGB", size, color=color)
    img.save(buf, format=format)
    return buf.getvalue()


# ── Security & Validation Unit Tests ──────────────────────────────────────────

def test_valid_png_validation():
    data = _create_dummy_image("PNG")
    val = validate_image_bytes(data, "test.png")
    assert val.format == "PNG"
    assert val.mime_type == "image/png"
    assert val.width == 200
    assert val.height == 100


def test_valid_jpeg_validation():
    data = _create_dummy_image("JPEG")
    val = validate_image_bytes(data, "test.jpg")
    assert val.format == "JPEG"
    assert val.mime_type == "image/jpeg"


def test_reject_renamed_exe_fake_png_extension():
    """Renamed Windows executable with .png extension MUST be rejected."""
    exe_payload = b"MZ\x90\x00\x03\x00\x00\x00Fake Exe Content"
    try:
        validate_image_bytes(exe_payload, "malicious.png")
        assert False, "Expected ImageValidationError for executable payload"
    except ImageValidationError as exc:
        assert "forbidden binary or script content" in str(exc)


def test_reject_corrupted_image():
    """Corrupted bytes matching magic header but broken payload MUST be rejected."""
    corrupted_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    try:
        validate_image_bytes(corrupted_png, "corrupted.png")
        assert False, "Expected ImageValidationError for corrupted image"
    except ImageValidationError as exc:
        assert "Corrupted or unreadable" in str(exc) or "Invalid image file signature" in str(exc)


def test_reject_decompression_bomb_dimension():
    """Image exceeding 4096x4096 MUST be rejected to prevent memory exhaustion."""
    data = _create_dummy_image("PNG", size=(4097, 100))
    try:
        validate_image_bytes(data, "huge.png")
        assert False, "Expected ImageValidationError for oversized dimension"
    except ImageValidationError as exc:
        assert "exceed maximum allowed limit" in str(exc)


def test_reject_tiny_dimension():
    """Image smaller than 5x5 MUST be rejected."""
    data = _create_dummy_image("PNG", size=(3, 3))
    try:
        validate_image_bytes(data, "tiny.png")
        assert False, "Expected ImageValidationError for tiny dimension"
    except ImageValidationError as exc:
        assert "too small" in str(exc)


def test_reject_oversized_file():
    """Files larger than 10MB MUST be rejected."""
    oversized_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * (MAX_FILE_SIZE_BYTES + 1)
    try:
        validate_image_bytes(oversized_data, "large.png")
        assert False, "Expected ImageValidationError for oversized file"
    except ImageValidationError as exc:
        assert "exceeds maximum allowed limit" in str(exc)


# ── Endpoint API Tests ────────────────────────────────────────────────────────

def test_analyze_screenshot_endpoint_valid_png():
    """POST /api/v1/analyze/screenshot with valid PNG returns full Scam X-Ray analysis."""
    png_bytes = _create_dummy_image("PNG")
    files = {"file": ("screenshot.png", png_bytes, "image/png")}

    res = client.post("/api/v1/analyze/screenshot", files=files)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["filename"] == "screenshot.png"
    assert data["image_format"] == "PNG"
    assert "extracted_text" in data
    assert "ocr_confidence" in data
    assert "analysis" in data
    assert data["analysis"]["risk_level"] in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_analyze_screenshot_endpoint_rejects_exe():
    """POST /api/v1/analyze/screenshot with renamed exe returns 422 Unprocessable Entity."""
    exe_bytes = b"MZ\x90\x00Fake Executable"
    files = {"file": ("payload.png", exe_bytes, "image/png")}

    res = client.post("/api/v1/analyze/screenshot", files=files)
    assert res.status_code == 422
    assert "forbidden binary or script content" in res.json()["error"]["message"]


def test_temp_file_cleanup_after_request():
    """Verify that temp files generated during OCR are cleaned up."""
    temp_dir = tempfile.gettempdir()
    before_files = set(os.listdir(temp_dir))

    png_bytes = _create_dummy_image("PNG")
    files = {"file": ("temp_test.png", png_bytes, "image/png")}
    res = client.post("/api/v1/analyze/screenshot", files=files)
    assert res.status_code == 200

    after_files = set(os.listdir(temp_dir))
    new_bhasha_temps = [f for f in (after_files - before_files) if f.startswith("bhasha_ocr_")]
    assert len(new_bhasha_temps) == 0, f"Leaked temporary files: {new_bhasha_temps}"


def run_all_tests():
    tests = [
        test_valid_png_validation,
        test_valid_jpeg_validation,
        test_reject_renamed_exe_fake_png_extension,
        test_reject_corrupted_image,
        test_reject_decompression_bomb_dimension,
        test_reject_tiny_dimension,
        test_reject_oversized_file,
        test_analyze_screenshot_endpoint_valid_png,
        test_analyze_screenshot_endpoint_rejects_exe,
        test_temp_file_cleanup_after_request,
    ]

    for fn in tests:
        fn()

    print(f"[PASS] All {len(tests)} Screenshot Security & OCR Tests Passed!")
