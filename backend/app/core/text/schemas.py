from __future__ import annotations

import enum

from pydantic import BaseModel, Field


class ObfuscationType(str, enum.Enum):
    """Taxonomy of text obfuscation techniques."""

    VOWEL_DELETION = "vowel_deletion"
    NUMBER_SUBSTITUTION = "number_substitution"
    CHARACTER_REPETITION = "character_repetition"
    PUNCTUATION_INSERTION = "punctuation_insertion"
    WHITESPACE_REMOVAL = "whitespace_removal"
    INFORMAL_ABBREVIATION = "informal_abbreviation"
    TRANSLITERATION = "transliteration"
    MIXED_SCRIPT_CONSTRUCTION = "mixed_script_construction"


class Transformation(BaseModel):
    """
    A single tracked transformation applied to the text.
    
    Maintains auditability by linking the normalized output back
    to the original span of text.
    """

    original_text: str = Field(description="The exact text before transformation")
    transformed_text: str = Field(description="The text after transformation")
    type: ObfuscationType | str = Field(description="Type of transformation applied")
    
    # Optional character positions mapping back to the original full string
    start_index: int | None = Field(default=None, description="Starting character index in original string")
    end_index: int | None = Field(default=None, description="Ending character index in original string")
    
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in this transformation (0.0 to 1.0)")


class TextAnalysisResult(BaseModel):
    """
    Final structured output of the text normalization pipeline.
    
    The original text is strictly preserved.
    """

    original_text: str = Field(description="The pristine original text")
    normalized_text: str = Field(description="The fully normalized text")
    
    detected_language: str = Field(description="Primary detected language (e.g., 'en', 'hi', 'hinglish')")
    detected_scripts: list[str] = Field(description="List of scripts found (e.g., ['Latn', 'Deva'])")
    
    transformations: list[Transformation] = Field(
        default_factory=list,
        description="Chronological log of all transformations applied to reach normalized_text",
    )
    
    confidence: float = Field(default=1.0, description="Overall confidence of the normalization")
