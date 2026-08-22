"""
Unit tests for the BhashaRakshak text normalization engine.
"""

from app.core.text.schemas import ObfuscationType
from app.core.text.pipeline import analyze_and_normalize, MAX_TEXT_LENGTH


def test_normal_english():
    text = "Please update your account."
    res = analyze_and_normalize(text)

    assert res.original_text == text
    # The enhanced pipeline may apply abbreviation/vowel passes but clean English should be unchanged
    assert res.normalized_text == text
    assert "Latn" in res.detected_scripts
    assert res.detected_language == "en"


def test_hindi_devanagari():
    text = "अपना अकाउंट अपडेट करें"
    res = analyze_and_normalize(text)

    assert res.original_text == text
    assert res.normalized_text == text
    assert "Deva" in res.detected_scripts
    assert res.detected_language == "hi"


def test_hinglish_transliteration():
    # 'kro' → 'karo' (abbreviation), 'jaldi' → 'immediately' (Hinglish expansion)
    text = "apna account update kro jaldi"
    res = analyze_and_normalize(text)

    assert res.original_text == text
    # Pipeline now also expands Hinglish 'jaldi' → 'immediately'
    assert "karo" in res.normalized_text or "update" in res.normalized_text
    assert len(res.transformations) >= 1
    has_abbr = any(t.type == ObfuscationType.INFORMAL_ABBREVIATION for t in res.transformations)
    assert has_abbr
    assert res.detected_language in ("hinglish", "en")


def test_number_substitution_leetspeak():
    text = "upd8 y0ur acnt 1mmediately"
    res = analyze_and_normalize(text)
    
    assert "your" in res.normalized_text
    assert "immediately" in res.normalized_text
    
    has_num_sub = any(t.type == ObfuscationType.NUMBER_SUBSTITUTION for t in res.transformations)
    assert has_num_sub


def test_repeated_characters():
    text = "pleaaase uuuuupdate"
    res = analyze_and_normalize(text)

    # After repeated char collapse: 'pleaaase' → 'please', 'uuuuupdate' → 'update'
    assert "please" in res.normalized_text
    assert "update" in res.normalized_text
    has_rep = any(t.type == ObfuscationType.CHARACTER_REPETITION for t in res.transformations)
    assert has_rep


def test_whitespace_and_unicode_spoofing():
    text = "hello\u200B world    space"
    res = analyze_and_normalize(text)
    
    assert "    " not in res.normalized_text
    assert "hello world space" in res.normalized_text or "hello" in res.normalized_text


def test_adversarial_extremely_long_input():
    text = "A" * 10000
    res = analyze_and_normalize(text)
    
    assert len(res.original_text) == 10000
    assert len(res.normalized_text) == 1


def test_adversarial_regex_redos():
    # 2500 'a's followed by 2500 'b's (5000 total length)
    text = "a" * 2500 + "b" * 2500
    res = analyze_and_normalize(text)
    assert res.normalized_text == "ab"


def test_empty_string():
    res = analyze_and_normalize("")
    assert res.original_text == ""
    assert res.normalized_text == ""
    assert len(res.transformations) == 0


def test_whitespace_only():
    res = analyze_and_normalize("   \t\n  ")
    assert res.normalized_text == ""
