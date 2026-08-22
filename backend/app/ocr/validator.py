"""
Image File Security Validator for BhashaRakshak Screenshot Analysis.

SECURITY CONTROLS:
  - Magic-byte verification (NEVER trust filename extension or MIME header).
  - Maximum upload size: 10 MB.
  - Maximum dimensions: 4096 x 4096 pixels (Decompression Bomb protection).
  - File signature enforcement (PNG, JPEG, WebP).
  - Executable/script payload detection (blocks ELF, PE .exe, shell scripts disguised as images).
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass
from typing import Tuple

from PIL import Image

logger = logging.getLogger(__name__)

# Max upload size: 10 MB
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
# Max dimension (protect against decompression bombs)
MAX_IMAGE_DIMENSION = 4096
# Limit max pixels to 16 Megapixels in PIL
Image.MAX_IMAGE_PIXELS = 16_777_216

# Magic byte signatures
_MAGIC_PNG = b"\x89PNG\r\n\x1a\n"
_MAGIC_JPEG = b"\xff\xd8\xff"
_MAGIC_WEBP_PREFIX = b"RIFF"
_MAGIC_WEBP_SUFFIX = b"WEBP"

# Executable / dangerous headers to explicitly reject
_DANGEROUS_SIGNATURES = (
    b"MZ",          # Windows PE Executable / DLL
    b"\x7fELF",     # Linux ELF Executable
    b"<!DOCTYPE",   # HTML / SVG XSS payload
    b"<svg",        # SVG vector payload
    b"<?xml",       # XML payload
    b"#!/bin/",     # Unix Shell script
    b"PK\x03\x04",  # Zip / Jar / APK file
)


class ImageValidationError(ValueError):
    """Raised when an uploaded file fails security validation."""
    pass


@dataclass
class ValidatedImage:
    format: str
    width: int
    height: int
    size_bytes: int
    mime_type: str


def validate_image_bytes(data: bytes, filename: str = "upload") -> ValidatedImage:
    """
    Validate untrusted image file bytes.

    Raises ImageValidationError if validation fails.
    """
    if not data or len(data) == 0:
        raise ImageValidationError("File is empty (0 bytes).")

    size_bytes = len(data)

    if size_bytes > MAX_FILE_SIZE_BYTES:
        raise ImageValidationError(
            f"File size ({size_bytes / (1024*1024):.1f} MB) exceeds maximum allowed limit of 10 MB."
        )

    # 1. Reject dangerous signatures immediately
    for sig in _DANGEROUS_SIGNATURES:
        if data.startswith(sig):
            logger.warning("Rejected upload with executable/script signature: %s", filename)
            raise ImageValidationError("Uploaded file contains forbidden binary or script content.")

    # 2. Magic byte check
    is_png = data.startswith(_MAGIC_PNG)
    is_jpeg = data.startswith(_MAGIC_JPEG)
    is_webp = data.startswith(_MAGIC_WEBP_PREFIX) and _MAGIC_WEBP_SUFFIX in data[:16]

    if not (is_png or is_jpeg or is_webp):
        raise ImageValidationError(
            "Invalid image file signature. Allowed formats: PNG, JPEG, WebP."
        )

    # Determine MIME type
    if is_png:
        mime_type = "image/png"
    elif is_jpeg:
        mime_type = "image/jpeg"
    else:
        mime_type = "image/webp"

    # 3. Parse dimensions with Pillow & check for decompression bombs
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()  # Verify header integrity without decoding entire raster

        # Re-open for dimension inspection after verify()
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
            img_format = img.format or "UNKNOWN"

            if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
                raise ImageValidationError(
                    f"Image dimensions ({width}x{height}) exceed maximum allowed limit of {MAX_IMAGE_DIMENSION}x{MAX_IMAGE_DIMENSION} pixels."
                )

            if width < 5 or height < 5:
                raise ImageValidationError(
                    f"Image dimensions ({width}x{height}) are too small to contain legible text."
                )

            return ValidatedImage(
                format=img_format.upper(),
                width=width,
                height=height,
                size_bytes=size_bytes,
                mime_type=mime_type,
            )

    except ImageValidationError:
        raise
    except Exception as exc:
        logger.warning("Image verification failed for %s: %s", filename, exc)
        raise ImageValidationError(f"Corrupted or unreadable image file: {exc}")
