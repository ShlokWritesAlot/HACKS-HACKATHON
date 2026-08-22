"""
Scam Conversation State Machine — Signal Detectors.

Each signal function takes raw/cleaned text and returns a score 0.0–1.0.
All text is treated as UNTRUSTED. Prompt injection cannot influence scores
because these are deterministic regex/pattern functions — no LLM calls.

SECURITY:
  - Input is HTML-escaped upstream in the schema layer.
  - All patterns are bounded to prevent ReDoS.
  - Scores are float math only — no dynamic execution.
"""

from __future__ import annotations

import re
from typing import Dict

# ── Compiled patterns — all bounded ───────────────────────────────────────────

_CONTACT_PATTERNS = re.compile(
    r"\b(dear\s+(?:customer|sir|madam|user|valued)|congratulations|you\s+have\s+been\s+selected"
    r"|we\s+(?:are\s+)?(?:contacting|reaching)|kindly\s+(?:note|be\s+informed)"
    r"|नमस्ते|नमस्कार|priya|pyaare|dear\s+friend)\b",
    re.IGNORECASE,
)

_TRUST_BUILDING_PATTERNS = re.compile(
    r"\b(we\s+are\s+from|calling\s+from|official\s+(?:team|department|bank|helpline)"
    r"|government\s+(?:of\s+india|department|scheme)|rbi\s+(?:approved|certified|official)"
    r"|pm\s+(?:scheme|yojana)|pradhan\s+mantri|आरबीआई|सरकारी|official\s+notice"
    r"|this\s+is\s+(?:an?\s+)?(?:official|authorized)|verified\s+partner"
    r"|हम\s+(?:बैंक|सरकार|विभाग)\s+से)\b",
    re.IGNORECASE,
)

_AUTHORITY_CLAIM_PATTERNS = re.compile(
    r"\b(sbi|hdfc|icici|axis|rbi|reserve\s+bank|income\s+tax|it\s+department"
    r"|trai|cyber\s+cell|police|cbi|enforcement\s+directorate|ed\s+india"
    r"|court\s+(?:notice|order|summons)|legal\s+action|fir|arrest\s+warrant"
    r"|आयकर|प्रवर्तन\s+निदेशालय|पुलिस|अदालत|गिरफ्तारी"
    r"|fedex|india\s+post|customs|narcotic|narcotics|drug\s+(?:enforcement|control))\b",
    re.IGNORECASE,
)

_FEAR_URGENCY_PATTERNS = re.compile(
    r"\b(urgent|immediately|within\s+\d+\s+(?:hours?|minutes?|days?)|last\s+(?:warning|chance|notice)"
    r"|account\s+(?:will\s+be\s+)?(?:blocked|suspended|closed|frozen|deactivated)"
    r"|service\s+(?:will\s+be\s+)?(?:disconnected|terminated|cut)"
    r"|legal\s+(?:action|consequences|proceedings)|warrant|arrested|penalty|fine"
    r"|तुरंत|जल्दी|अंतिम\s+(?:सूचना|चेतावनी)|खाता\s+(?:बंद|ब्लॉक)"
    r"|abhi|jaldi|turant|block\s+ho\s+jayega|band\s+ho\s+jayega)\b",
    re.IGNORECASE,
)

_CREDENTIAL_REQUEST_PATTERNS = re.compile(
    r"\b(otp|one[\s-]time[\s-]password|pin|password|credentials|login\s+(?:id|details)"
    r"|net\s+banking\s+(?:id|password)|cvv|expiry\s+date|card\s+(?:number|details)"
    r"|aadhaar\s+(?:number|otp)|pan\s+(?:number|card)|kyc\s+(?:update|verification|complete)"
    r"|verify\s+your\s+(?:account|identity)|share\s+(?:the\s+)?otp"
    r"|ओटीपी|पासवर्ड|पिन|आधार|पैन|केवाईसी"
    r"|apna\s+otp|otp\s+batao|otp\s+share)\b",
    re.IGNORECASE,
)

_PAYMENT_REQUEST_PATTERNS = re.compile(
    r"\b(pay|transfer|send\s+(?:money|amount|rs|rupees|₹)"
    r"|upi|gpay|phonepe|paytm|bhim|neft|rtgs|imps"
    r"|₹\s*\d|rs\.?\s*\d|\d\s*(?:rs|rupees|₹)"
    r"|processing\s+fee|registration\s+fee|refund\s+(?:initiate|process)"
    r"|scan\s+(?:qr|the\s+code)|qr\s+(?:code|scan)"
    r"|पैसे\s+(?:भेजो|ट्रांसफर)|यूपीआई|भुगतान"
    r"|paise\s+bhejo|payment\s+karo|fee\s+bhejo)\b",
    re.IGNORECASE,
)

_REMOTE_ACCESS_PATTERNS = re.compile(
    r"\b(anydesk|teamviewer|quick\s+support|remote\s+(?:access|control|desktop|support)"
    r"|screen\s+(?:share|sharing)|install\s+(?:the\s+)?app|download\s+(?:and\s+)?install"
    r"|allow\s+(?:access|permission)|grant\s+permission|enable\s+(?:screen|access)"
    r"|anydesk\s+id|teamviewer\s+id|control\s+your\s+(?:phone|device|screen)"
    r"|स्क्रीन\s+शेयर|रिमोट\s+एक्सेस|एनीडेस्क)\b",
    re.IGNORECASE,
)

_ACCOUNT_TAKEOVER_PATTERNS = re.compile(
    r"\b(account\s+(?:compromised|hacked|accessed|takeover)"
    r"|unauthorized\s+(?:access|transaction|login)"
    r"|change\s+(?:your\s+)?(?:password|pin|mpin)"
    r"|reset\s+(?:your\s+)?(?:password|pin)|new\s+device\s+(?:login|registered)"
    r"|sim\s+(?:swap|port|transfer)|number\s+(?:port|transfer)"
    r"|खाता\s+(?:हैक|समझौता)|अनधिकृत\s+लेनदेन)\b",
    re.IGNORECASE,
)

_EXIT_PATTERNS = re.compile(
    r"\b(thank\s+you\s+for\s+(?:your\s+)?(?:cooperation|patience|time)"
    r"|transaction\s+(?:completed|successful|processed)"
    r"|issue\s+(?:resolved|fixed|sorted)|problem\s+(?:solved|fixed)"
    r"|your\s+(?:refund|amount|money)\s+(?:will\s+be\s+)?(?:credited|transferred|sent)"
    r"|case\s+(?:closed|resolved)|ticket\s+(?:closed|resolved)"
    r"|धन्यवाद|समस्या\s+(?:हल|सुलझाई)\s+गई)\b",
    re.IGNORECASE,
)

# Benign customer-service indicators (reduces false positive scam signals)
_BENIGN_PATTERNS = re.compile(
    r"\b(your\s+(?:order|booking|ticket|reservation)\s+(?:is|has\s+been)"
    r"|tracking\s+(?:id|number)|delivery\s+(?:scheduled|expected|confirmed)"
    r"|account\s+statement|transaction\s+(?:alert|notification)"
    r"|welcome\s+to|thank\s+you\s+for\s+(?:choosing|using|shopping)"
    r"|our\s+(?:customer\s+service|support\s+team)\s+is\s+available)\b",
    re.IGNORECASE,
)


def compute_signal_scores(text: str) -> Dict[str, float]:
    """
    Compute normalized signal scores for each scam state from raw text.

    Returns a dict of {signal_name: score_0_to_1}.
    PURELY DETERMINISTIC — no LLM, no network, no dynamic execution.
    """
    from app.statemachine.schemas import ScamState

    def _score(pattern: re.Pattern, t: str) -> float:
        matches = pattern.findall(t)
        return min(1.0, len(matches) * 0.35) if matches else 0.0

    scores = {
        ScamState.CONTACT.value:              _score(_CONTACT_PATTERNS, text),
        ScamState.TRUST_BUILDING.value:       _score(_TRUST_BUILDING_PATTERNS, text),
        ScamState.AUTHORITY_CLAIM.value:      _score(_AUTHORITY_CLAIM_PATTERNS, text),
        ScamState.FEAR_OR_URGENCY.value:      _score(_FEAR_URGENCY_PATTERNS, text),
        ScamState.CREDENTIAL_REQUEST.value:   _score(_CREDENTIAL_REQUEST_PATTERNS, text),
        ScamState.PAYMENT_REQUEST.value:      _score(_PAYMENT_REQUEST_PATTERNS, text),
        ScamState.REMOTE_ACCESS.value:        _score(_REMOTE_ACCESS_PATTERNS, text),
        ScamState.ACCOUNT_TAKEOVER.value:     _score(_ACCOUNT_TAKEOVER_PATTERNS, text),
        ScamState.EXIT.value:                 _score(_EXIT_PATTERNS, text),
        "_benign":                             _score(_BENIGN_PATTERNS, text),
    }
    return scores
