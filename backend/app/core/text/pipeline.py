"""
Text Analysis & Normalization Pipeline for BhashaRakshak.

Multi-pass normalization pipeline hardened against all 19 adversarial
perturbation categories produced by the red-team generator.

Pass order (designed so each pass enables the next):
  1. Strip zero-width / invisible chars
  2. NFKC + Unicode confusable mapping
  3. Punctuation camouflage removal (b.l.o.c.k.e.d → blocked)
  4. Domain bracket obfuscation restoration
  5. Collapse repeated characters (blooocked → blocked)
  6. OCR corruption correction (bl0cked → blocked)
  7. Leetspeak / number substitution
  8. Vowel-deleted keyword reconstruction
  9. QWERTY typo correction
  10. Informal abbreviation expansion
  11. Whitespace normalization

SECURITY:
  - Input length strictly capped before processing.
  - No network access. No external calls. Pure text transforms.
  - All transforms are idempotent and bounded.
"""

import logging
from collections import defaultdict

from app.core.text.schemas import TextAnalysisResult, Transformation
from app.core.text.filters import (
    strip_zero_width_chars,
    normalize_unicode,
    strip_punctuation_camouflage,
    fix_domain_obfuscation,
    collapse_whitespace,
    fix_repeated_chars,
    fix_ocr_corruption,
    fix_number_substitutions,
    fix_vowel_deleted_words,
    fix_qwerty_typos,
    fix_abbreviations,
)

logger = logging.getLogger(__name__)

# Security: Max length to prevent resource exhaustion attacks
MAX_TEXT_LENGTH = 5000


def detect_language_and_script(text: str) -> tuple[str, list[str]]:
    """
    Heuristic-based language and script detection.
    (ML-based detection deferred due to dependency constraints).
    """
    scripts = set()

    for char in text:
        code = ord(char)
        if 0x0900 <= code <= 0x097F:
            scripts.add("Deva")
        elif (0x0041 <= code <= 0x005A) or (0x0061 <= code <= 0x007A):
            scripts.add("Latn")

    if "Deva" in scripts:
        primary_lang = "hi"
    elif "Latn" in scripts:
        lower_text = text.lower()
        hinglish_markers = {
            "kro", "karo", "hai", "bhi", "nahi", "kya", "apka", "apna", "jaldi", "jayega",
            "kare", "karein", "hoga", "raha", "sakte", "kripya", "turant", "paisa", "rupaye",
            "bijli", "bijali", "abhi", "aaj", "paiso", "khata", "khatta",
        }
        words = set(lower_text.split())
        if words.intersection(hinglish_markers):
            primary_lang = "hinglish"
        else:
            primary_lang = "en"
    else:
        primary_lang = "unknown"

    return primary_lang, list(scripts)


def analyze_and_normalize(raw_text: str) -> TextAnalysisResult:
    """
    Process SMS text through the full multi-pass normalization pipeline.

    Security:
    - Input length is strictly capped.
    - Transformations never mutate the original string in place.
    - Output strictly conforms to TextAnalysisResult schema.
    """
    if len(raw_text) > MAX_TEXT_LENGTH:
        logger.warning(
            "Input text exceeded maximum length. Truncating for analysis.",
            extra={"original_length": len(raw_text), "max_length": MAX_TEXT_LENGTH}
        )
        working_text = raw_text[:MAX_TEXT_LENGTH]
    else:
        working_text = raw_text

    all_transformations: list[Transformation] = []

    # ── Pass 1: Strip zero-width & invisible chars ──────────────
    working_text, t = strip_zero_width_chars(working_text)
    all_transformations.extend(t)

    # ── Pass 2: NFKC + Unicode confusable map ───────────────────
    working_text, t = normalize_unicode(working_text)
    all_transformations.extend(t)

    # ── Pass 3: Remove punctuation-as-spacer camouflage ─────────
    # Must come before repeated-char collapse so 'b.l.o.c.k.e.d' → 'blocked'
    working_text, t = strip_punctuation_camouflage(working_text)
    all_transformations.extend(t)

    # ── Pass 4: Restore domain obfuscation brackets ──────────────
    working_text, t = fix_domain_obfuscation(working_text)
    all_transformations.extend(t)

    # ── Pass 5: Collapse 3+ repeated characters ──────────────────
    working_text, t = fix_repeated_chars(working_text)
    all_transformations.extend(t)

    # ── Pass 6: OCR corruption correction ───────────────────────
    # After leet so 'acc0unt' → 'account' but real phone numbers survive
    working_text, t = fix_ocr_corruption(working_text)
    all_transformations.extend(t)

    # ── Pass 7: Leet / number substitution ──────────────────────
    working_text, t = fix_number_substitutions(working_text)
    all_transformations.extend(t)

    # ── Pass 8: Vowel-deleted keyword reconstruction ─────────────
    working_text, t = fix_vowel_deleted_words(working_text)
    all_transformations.extend(t)

    # ── Pass 9: QWERTY typo correction ──────────────────────────
    working_text, t = fix_qwerty_typos(working_text)
    all_transformations.extend(t)

    # ── Pass 10: Informal abbreviation expansion ─────────────────
    working_text, t = fix_abbreviations(working_text)
    all_transformations.extend(t)

    # ── Pass 11: Whitespace normalization ────────────────────────
    working_text, t = collapse_whitespace(working_text)
    all_transformations.extend(t)

    lang, scripts = detect_language_and_script(working_text)

    # Confidence decreases slightly with more transforms detected
    confidence = max(0.1, 1.0 - (len(all_transformations) * 0.03))

    return TextAnalysisResult(
        original_text=raw_text,
        normalized_text=working_text,
        detected_language=lang,
        detected_scripts=scripts,
        transformations=all_transformations,
        confidence=confidence,
    )
