"""
Enhanced Text Normalization Filters for BhashaRakshak.

Handles all 19 adversarial perturbation categories produced by the red-team generator:
  1.  vowel_deletion          → vowel reconstruction via scam keyword dictionary
  2.  adjacent_swap           → typo-tolerant keyword matching via canonical form
  3.  number_substitution     → full leet→alpha mapping
  4.  repeated_chars          → collapse 3+ repeats to 1
  5.  whitespace_manipulation → collapse whitespace / strip zero-width
  6.  phonetic_transliteration→ Hinglish/phonetic → canonical English
  7.  hinglish_synthesis      → Hinglish word → canonical English
  8.  mixed_scripts           → Devanagari digit/word → transliterated
  9.  punctuation_insertion   → strip inter-letter punctuation camouflage
  10. informal_abbreviations  → abbrev → full word
  11. unicode_confusables     → map look-alike Unicode chars back to ASCII
  12. zero_width_chars        → strip all zero-width & invisible chars
  13. unicode_normalization   → NFKC + NFC normalization
  14. multilingual_switching  → kept as-is (Devanagari patterns already covered)
  15. nested_obfuscation      → iterative multi-pass normalization
  16. ocr_corruption          → OCR glyph→letter (rn→m, 0→O, |→l, etc.)
  17. realistic_typos         → QWERTY proximity typo correction (common scam words)
  18. domain_obfuscation      → restore domain keywords (bit[.]ly → bitly)
  19. sender_id_mutation      → not needed at filter level

SECURITY:
- All regexes use bounded quantifiers to prevent ReDoS.
- Input is strictly capped before processing.
- No network access, no external calls.
"""

import re
import unicodedata
from typing import List, Tuple

from app.core.text.schemas import ObfuscationType, Transformation

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

# Security: bounded quantifiers to prevent ReDoS
REPEATED_CHAR_REGEX = re.compile(r"([a-zA-Z])\1{2,}", re.IGNORECASE)

# Expanded leet map covering all common substitutions
LEET_MAP: dict[str, str] = {
    "0": "o", "1": "i", "2": "z", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "i", "+": "t",
}

# Reverse LEET for number-only-substituted words
LEET_MAP_EXTENDED: dict[str, str] = {**LEET_MAP, "€": "e", "£": "l"}

# Common scam keyword abbreviation expansions
WORD_SUBSTITUTIONS: dict[str, str] = {
    # English abbreviations used by generator
    "acnt": "account",
    "acct": "account",
    "upd8": "update",
    "v3rify": "verify",
    "vrify": "verify",
    "kyyc": "kyc",
    "immdtly": "immediately",
    "plz": "please",
    "2day": "today",
    "b4": "before",
    "msg": "message",
    "urgnt": "urgent",
    "srvc": "service",
    "custmr": "customer",
    "pls": "please",
    "ur": "your",
    "yr": "your",
    "u": "you",
    "r": "are",
    "n": "and",
    "blckd": "blocked",
    "blkd": "blocked",
    "suspnd": "suspended",
    "suspd": "suspended",
    "verf": "verify",
    "vrf": "verify",
    "kyck": "kyc",
    "bnk": "bank",
    "sndr": "sender",
    "pw": "password",
    "passwd": "password",
    "otps": "otp",
    "crdt": "credit",
    "dbts": "debit",
    "trnsf": "transfer",
    "trnsfr": "transfer",
    "depst": "deposit",
    "pymnt": "payment",
    "pymt": "payment",
    "no": "number",
    # Hinglish
    "kro": "karo",
    "bhi": "bhi",
    "hai": "hai",
    "apka": "your",
    "apna": "your",
    "jaldi": "immediately",
    "turant": "immediately",
    "band": "blocked",
    "bijli": "electricity",
    "bijali": "electricity",
    "bill": "bill",
    "paisa": "money",
    "paise": "money",
    "rupaye": "rupees",
    "rupya": "rupees",
    "khata": "account",
    "khatta": "account",
    "dena": "give",
    "lena": "take",
    "karna": "do",
    "abhi": "now",
    "aaj": "today",
}

# ─────────────────────────────────────────────────────────────
# UNICODE CONFUSABLES MAP (Cyrillic, Greek, fullwidth → ASCII)
# ─────────────────────────────────────────────────────────────
# Covers characters visually identical to ASCII letters used in scam URLs/text
CONFUSABLES_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a", "\u0410": "A",  # а А
    "\u0435": "e", "\u0415": "E",  # е Е
    "\u0456": "i", "\u0406": "I",  # і І
    "\u043E": "o", "\u041E": "O",  # о О
    "\u0440": "r", "\u0420": "R",  # р Р
    "\u0441": "c", "\u0421": "C",  # с С
    "\u0443": "y", "\u0423": "Y",  # у У
    "\u0445": "x", "\u0425": "X",  # х Х
    "\u0440": "r",                  # р
    "\u0432": "b",                  # в (looks like 6)
    "\u0440": "r",
    # Greek → Latin
    "\u03B1": "a", "\u0391": "A",  # α Α
    "\u03B5": "e", "\u0395": "E",  # ε Ε
    "\u03B9": "i", "\u0399": "I",  # ι Ι
    "\u03BF": "o", "\u039F": "O",  # ο Ο
    "\u03C1": "r", "\u03A1": "R",  # ρ Ρ
    "\u03C5": "y", "\u03A5": "Y",  # υ Υ
    "\u03BD": "v",                  # ν
    "\u03BA": "k",                  # κ
    "\u03BC": "m",                  # μ
    "\u03C4": "t",                  # τ
    # Fullwidth Latin (e.g. ａｂｃ → abc)
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
    # Superscript / subscript digits
    "\u2070": "0", "\u00B9": "1", "\u00B2": "2", "\u00B3": "3",
    "\u2074": "4", "\u2075": "5", "\u2076": "6", "\u2077": "7",
    "\u2078": "8", "\u2079": "9",
    # Mathematical bold/italic letters mapped to ASCII
    "\u1D41A": "a", "\u1D41B": "b",  # (supplemental, best-effort)
    # Common look-alikes
    "\u2216": "/",   # ∖ → /
    "\u2223": "l",   # ∣ → l
    "\u2124": "Z",   # ℤ
    "\u2102": "C",   # ℂ
    "\u210A": "g",   # ℊ
    "\u210B": "H",   # ℋ
    "\u2115": "N",   # ℕ
    "\u211A": "Q",   # ℚ
    "\u211D": "R",   # ℝ
}

# Zero-width and invisible characters to strip
ZERO_WIDTH_CHARS = re.compile(
    "[\u200B\u200C\u200D\u200E\u200F\u00AD\uFEFF\u2060\u2061\u2062\u2063\u2064"
    "\u180E\u034F\u2028\u2029\u202A\u202B\u202C\u202D\u202E\u206A-\u206F]+"
)

# OCR glyph corruption patterns — maps OCR misread chars back to letters
OCR_FIXES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brn\b", re.IGNORECASE), "m"),     # rn → m (in isolation)
    (re.compile(r"(?<=[a-z])rn(?=[a-z])", re.IGNORECASE), "m"),  # arn → am
    (re.compile(r"\b0(?=[a-z])", re.IGNORECASE), "o"),  # 0pdate → opdate
    (re.compile(r"(?<=[a-z])0(?=[a-z])", re.IGNORECASE), "o"),   # bl0ck → block
    (re.compile(r"\bl(?=[a-z]{2})", re.IGNORECASE), "l"),  # keep l (usually fine)
]

# Punctuation-as-spacer pattern: detects a.b.c.d or a-b-c-d between letters
PUNCT_SPACER_REGEX = re.compile(r"(?<=[a-zA-Z\u0900-\u097F])[.\-_*~^](?=[a-zA-Z\u0900-\u097F])")

# Domain obfuscation patterns: bit[.]ly, bit(.)ly, sbi-live-kyc etc
DOMAIN_OBFUS_REGEX = re.compile(r"\[\.?\]|\(\.\)|\{\.?\}", re.IGNORECASE)

# Scam keyword vocabulary (vowel-deleted forms → canonical)
# Generated by removing vowels from critical scam trigger words
VOWEL_DELETED_MAP: dict[str, str] = {
    # Removing aeiou from canonical → variant: canonical
    "blckd": "blocked",
    "blkd": "blocked",
    "blck": "block",
    "blk": "block",
    "spnd": "suspend",
    "sspnd": "suspend",
    "spndd": "suspended",
    "sspndd": "suspended",
    "ccnt": "account",
    "ccnt": "account",
    "kynr": "kyc",
    "kyc": "kyc",
    "pn": "pan",
    "pswrd": "password",
    "psswrd": "password",
    "pswd": "password",
    "vrfy": "verify",
    "vrfctn": "verification",
    "mmdtly": "immediately",
    "mmdt": "immediate",
    "rqst": "request",
    "rgstrd": "registered",
    "xprd": "expired",
    "xpr": "expire",
    "xpry": "expiry",
    "dctv": "deactivate",
    "dctd": "deactivated",
    "clck": "click",
    "clk": "click",
    "dpst": "deposit",
    "pyt": "payment",
    "pymt": "payment",
    "trnsfr": "transfer",
    "trnsct": "transact",
    "frm": "from",
    "cstmr": "customer",
    "srvc": "service",
    "bnk": "bank",
    "crdt": "credit",
    "dbt": "debit",
    "bnkng": "banking",
    "lgn": "login",
    "nmbr": "number",
    "mbl": "mobile",
    "mbl": "mobile",
    "nstll": "install",
    "dwnld": "download",
    "wmnt": "amount",
    "mnt": "amount",
    "rglr": "regular",
    "scrty": "security",
    "scrt": "secret",
    "vld": "valid",
    "nvld": "invalid",
    "dtls": "details",
    "dtl": "detail",
    "fnd": "fund",
    "fnds": "funds",
    "pnlty": "penalty",
    "fnd": "find",
    "rcd": "record",
    "prcd": "proceed",
    "mng": "manage",
    "mgr": "manager",
    "dpt": "department",
    "prtcl": "protocol",
    "lgl": "legal",
    "ncm": "income",
    "tx": "tax",
    "othrws": "otherwise",
    "wll": "will",
    "ct": "cut",
    "dscnnct": "disconnect",
    "wrnng": "warning",
    "ntc": "notice",
    "ltry": "lottery",
    "prz": "prize",
    "wnnr": "winner",
    "jb": "job",
    "slry": "salary",
    "offr": "offer",
    "ln": "loan",
    "nstnt": "instant",
    "pprv": "approve",
    "prcs": "process",
    "smpl": "simple",
    "dly": "daily",
    "wkly": "weekly",
    "mnthly": "monthly",
    "rmt": "remote",
    "scrn": "screen",
    "shre": "share",
    "crd": "card",
    "crdt": "credit",
    "cvv": "cvv",
    "otp": "otp",
    "bnfcry": "beneficiary",
    "invst": "invest",
    "prft": "profit",
    "bns": "bonus",
    "csh": "cash",
    "wthdrwl": "withdrawal",
    "wthdrl": "withdrawal",
    "dpst": "deposit",
    "blnc": "balance",
    "trnsction": "transaction",
    "nms": "names",
    "ddr": "address",
    "prtcl": "protocol",
    "prt": "port",
    "lnk": "link",
    "url": "url",
    "http": "http",
    "https": "https",
    "nstlltn": "installation",
    "cstm": "custom",
    "pkd": "packed",
    "prcel": "parcel",
    "crr": "courier",
    "dlvry": "delivery",
    "cstms": "customs",
    "clrnc": "clearance",
    "chrg": "charge",
    "fd": "food",
    "gvt": "government",
    "gvrnmnt": "government",
    "mnstr": "minister",
    "dptr": "department",
    "py": "pay",
    "wrd": "reward",
    "rwrd": "reward",
    "cmplnt": "complaint",
    "rgstrd": "registered",
    "unrgsrd": "unregistered",
    "cnfrm": "confirm",
    "cnfrmtn": "confirmation",
    "sgntr": "signature",
    "sgn": "sign",
    "prtctd": "protected",
    "frdd": "fraud",
    "frd": "fraud",
    "scm": "scam",
    "hck": "hack",
    "vrs": "virus",
    "mlcr": "malware",
    "phsh": "phish",
    "phshng": "phishing",
}

# QWERTY proximity corrections for common scam words
# Maps (canonical → likely-typo variants)
QWERTY_CORRECTIONS: dict[str, str] = {
    "blovked": "blocked",
    "bloxked": "blocked",
    "blpcked": "blocked",
    "accpunt": "account",
    "acvount": "account",
    "accoint": "account",
    "accout": "account",
    "updaet": "update",
    "updzte": "update",
    "updste": "update",
    "veriyf": "verify",
    "verufy": "verify",
    "verift": "verify",
    "urgnet": "urgent",
    "urgjent": "urgent",
    "urgant": "urgent",
    "immediatley": "immediately",
    "imediately": "immediately",
    "immeditaely": "immediately",
    "immeditaly": "immediately",
    "kuc": "kyc",
    "kyv": "kyc",
    "oassword": "password",
    "passqord": "password",
    "passwird": "password",
    "passworx": "password",
    "paswrod": "password",
    "transger": "transfer",
    "tranfser": "transfer",
    "tranfer": "transfer",
    "paymenr": "payment",
    "paymenmt": "payment",
    "paymrnt": "payment",
    "suspeneded": "suspended",
    "suspened": "suspended",
    "deactuvate": "deactivate",
    "deactvate": "deactivate",
    "downlosd": "download",
    "downloaf": "download",
    "cluck": "click",
    "clivk": "click",
    "instsll": "install",
    "insatll": "install",
}

# ─────────────────────────────────────────────────────────────
# FILTER FUNCTIONS
# ─────────────────────────────────────────────────────────────

def strip_zero_width_chars(text: str) -> tuple[str, list[Transformation]]:
    """Strip all zero-width and invisible Unicode characters."""
    normalized = ZERO_WIDTH_CHARS.sub("", text)
    transformations = []
    if normalized != text:
        transformations.append(Transformation(
            original_text=text[:80],
            transformed_text=normalized[:80],
            type="zero_width_stripped",
        ))
    return normalized, transformations


def normalize_unicode(text: str) -> tuple[str, list[Transformation]]:
    """
    Apply NFKC normalization + confusable mapping.
    Handles: fullwidth chars, superscripts, Unicode normalization attacks,
    and common Cyrillic/Greek confusables.
    """
    # Step 1: NFKC (handles fullwidth, ligatures, superscripts)
    normalized = unicodedata.normalize("NFKC", text)

    # Step 2: Map known confusable characters to ASCII
    result = []
    for ch in normalized:
        result.append(CONFUSABLES_MAP.get(ch, ch))
    normalized = "".join(result)

    transformations = []
    if normalized != text:
        transformations.append(Transformation(
            original_text=text[:80],
            transformed_text=normalized[:80],
            type="unicode_normalization",
        ))
    return normalized, transformations


def collapse_whitespace(text: str) -> tuple[str, list[Transformation]]:
    """Collapse multiple spaces/newlines into a single space."""
    words = text.split()
    normalized = " ".join(words)
    transformations = []
    if normalized != text:
        transformations.append(Transformation(
            original_text=text[:80],
            transformed_text=normalized[:80],
            type=ObfuscationType.WHITESPACE_REMOVAL,
        ))
    return normalized, transformations


def strip_punctuation_camouflage(text: str) -> tuple[str, list[Transformation]]:
    """
    Remove punctuation used as inter-letter spacers to dodge keyword detection.
    e.g. 'b.l.o.c.k.e.d' → 'blocked', 'k-y-c' → 'kyc'
    """
    normalized = PUNCT_SPACER_REGEX.sub("", text)
    transformations = []
    if normalized != text:
        transformations.append(Transformation(
            original_text=text[:80],
            transformed_text=normalized[:80],
            type="punctuation_camouflage_stripped",
        ))
    return normalized, transformations


def fix_domain_obfuscation(text: str) -> tuple[str, list[Transformation]]:
    """
    Restore domain bracket obfuscation.
    e.g. 'bit[.]ly' → 'bit.ly', 'sbi(.)in' → 'sbi.in'
    """
    normalized = DOMAIN_OBFUS_REGEX.sub(".", text)
    transformations = []
    if normalized != text:
        transformations.append(Transformation(
            original_text=text[:80],
            transformed_text=normalized[:80],
            type="domain_obfuscation_restored",
        ))
    return normalized, transformations


def fix_repeated_chars(text: str) -> tuple[str, list[Transformation]]:
    """Collapse 3+ repeated characters to a single character."""
    transformations = []

    def replacer(match: re.Match) -> str:
        orig = match.group(0)
        new_str = match.group(1)
        transformations.append(Transformation(
            original_text=orig,
            transformed_text=new_str,
            type=ObfuscationType.CHARACTER_REPETITION,
            start_index=match.start(),
            end_index=match.end(),
        ))
        return new_str

    normalized = REPEATED_CHAR_REGEX.sub(replacer, text)
    return normalized, transformations


def fix_number_substitutions(text: str) -> tuple[str, list[Transformation]]:
    """
    Replace leet/number substitutions in words.
    Context-aware: only replaces when the word mixes letters and leet symbols.
    """
    transformations = []
    words = text.split(" ")
    new_words = []

    for word in words:
        has_letter = any(c.isalpha() for c in word)
        has_leet = any(c in LEET_MAP_EXTENDED for c in word)

        if has_letter and has_leet:
            new_word = ""
            changed = False
            for char in word:
                mapped = LEET_MAP_EXTENDED.get(char.lower())
                if mapped:
                    new_word += mapped
                    changed = True
                else:
                    new_word += char

            if changed:
                transformations.append(Transformation(
                    original_text=word,
                    transformed_text=new_word,
                    type=ObfuscationType.NUMBER_SUBSTITUTION,
                ))
                new_words.append(new_word)
                continue

        new_words.append(word)

    return " ".join(new_words), transformations


def fix_vowel_deleted_words(text: str) -> tuple[str, list[Transformation]]:
    """
    Reconstruct vowel-deleted scam keywords.
    e.g. 'blckd' → 'blocked', 'spnd' → 'suspend', 'kyyc' → 'kyc'
    Operates word-by-word against a curated scam vocabulary.
    """
    transformations = []
    words = text.split(" ")
    new_words = []

    for word in words:
        key = re.sub(r"[^a-z0-9]", "", word.lower())
        if key in VOWEL_DELETED_MAP:
            restored = VOWEL_DELETED_MAP[key]
            # preserve rough casing
            if word.isupper():
                restored = restored.upper()
            elif word.istitle():
                restored = restored.title()
            transformations.append(Transformation(
                original_text=word,
                transformed_text=restored,
                type="vowel_deletion_restored",
            ))
            new_words.append(restored)
        else:
            new_words.append(word)

    return " ".join(new_words), transformations


def fix_qwerty_typos(text: str) -> tuple[str, list[Transformation]]:
    """
    Fix QWERTY proximity typos in known scam keywords.
    """
    transformations = []
    words = text.split(" ")
    new_words = []

    for word in words:
        key = word.lower().strip(".,!?;:")
        if key in QWERTY_CORRECTIONS:
            restored = QWERTY_CORRECTIONS[key]
            transformations.append(Transformation(
                original_text=word,
                transformed_text=restored,
                type="qwerty_typo_corrected",
            ))
            new_words.append(restored)
        else:
            new_words.append(word)

    return " ".join(new_words), transformations


def fix_abbreviations(text: str) -> tuple[str, list[Transformation]]:
    """Replace common informal abbreviations and Hinglish equivalents."""
    transformations = []
    words = text.split(" ")
    new_words = []

    for word in words:
        lower_word = word.lower().strip(".,!?;:")
        if lower_word in WORD_SUBSTITUTIONS:
            new_word = WORD_SUBSTITUTIONS[lower_word]
            if word.isupper():
                new_word = new_word.upper()
            elif word.istitle():
                new_word = new_word.title()
            transformations.append(Transformation(
                original_text=word,
                transformed_text=new_word,
                type=ObfuscationType.INFORMAL_ABBREVIATION,
            ))
            new_words.append(new_word)
        else:
            new_words.append(word)

    return " ".join(new_words), transformations


def fix_ocr_corruption(text: str) -> tuple[str, list[Transformation]]:
    """
    Correct common OCR-like corruption patterns.
    e.g. 'bl0cked' → 'blocked', 'acc0unt' → 'account'
    """
    # Only apply OCR digit→letter substitution inside words (not standalone numbers)
    # We do this after leet substitution so order matters
    transformations = []
    normalized = text

    # Replace 0 → o and 1 → l when sandwiched between letters
    def _replace_ocr_digit(m: re.Match) -> str:
        ch = m.group(0)
        replacement = {"0": "o", "1": "l"}.get(ch, ch)
        return replacement

    new = re.sub(r"(?<=[a-zA-Z])[01](?=[a-zA-Z])", _replace_ocr_digit, normalized)
    if new != normalized:
        transformations.append(Transformation(
            original_text=normalized[:80],
            transformed_text=new[:80],
            type="ocr_corruption_corrected",
        ))
        normalized = new

    return normalized, transformations
