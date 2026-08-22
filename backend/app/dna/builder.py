"""
Scam DNA Builder & Fingerprint Generator.

Constructs 16-dimensional ScamDNAFingerprint and SHA-256 dna_hash from text & threat analysis.
Zero raw text is included in dna_hash or fingerprint metadata.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional

from app.campaigns.embedder import embed_text
from app.dna.schemas import ScamDNAFingerprint
from app.ml.schemas import ScamCategory


class ScamDNABuilder:
    """
    Deterministically builds structured ScamDNAFingerprint objects.
    """

    def build_dna(
        self,
        raw_text: str,
        cleaned_text: str,
        scam_archetype: ScamCategory,
        manipulation_dict: Dict[str, float],
        obfuscations: List[str],
        extracted_iocs: Optional[List[Dict[str, str]]] = None,
        sender_id: Optional[str] = None,
        embedding: Optional[List[float]] = None,
    ) -> ScamDNAFingerprint:
        lower_clean = cleaned_text.lower()
        lower_raw = raw_text.lower()

        # 1. Linguistic Structure
        words = lower_clean.split()
        word_count = len(words)
        sentence_count = len(re.split(r"[.!?]+", raw_text))
        has_imperatives = bool(
            re.search(r"\b(click|update|pay|call|download|install|verify|submit|claim)\b", lower_clean)
        )
        linguistic_structure = {
            "word_count": word_count,
            "sentence_count": sentence_count,
            "has_imperatives": has_imperatives,
        }

        # 2. Impersonated Organization
        org_match = re.search(r"\b(sbi|hdfc|icici|axis|pnb|canara|rbi|fedex|dhl|india\s*post|electricity|paytm|gpay)\b", lower_clean)
        impersonated_org = org_match.group(0).upper() if org_match else "NONE"

        # 3. URL Characteristics
        urls = re.findall(r"https?://\S+|www\.\S+|bit\.ly/\S+|t\.co/\S+|\S+\.(?:xyz|click|top|live|info|site)", lower_raw)
        has_url = len(urls) > 0
        tlds = list({u.split(".")[-1].split("/")[0].lower() for u in urls if "." in u})
        is_shortener = any(x in lower_raw for x in ["bit.ly", "t.co", "tinyurl.com", "is.gd"])
        has_homoglyph = any("-" in u or "kyc" in u or "verify" in u for u in urls)
        url_characteristics = {
            "has_url": has_url,
            "url_count": len(urls),
            "tlds": sorted(tlds),
            "is_shortener": is_shortener,
            "has_homoglyph": has_homoglyph,
        }

        # 4. Phone Indicators
        phones = re.findall(r"\b(?:\+91|0)?[6-9]\d{9}\b", raw_text)
        phone_indicators = {
            "has_phone": len(phones) > 0,
            "phone_count": len(phones),
            "country_codes": ["+91"] if any("+91" in p for p in phones) else [],
        }

        # 5. UPI Characteristics
        vpas = re.findall(r"[\w.-]+@(okaxis|paytm|ybl|oksbi|ibl|axl|upi|barodampay)", lower_raw)
        upi_characteristics = {
            "has_vpa": len(vpas) > 0,
            "vpa_count": len(vpas),
            "psp_handles": sorted(list(set(vpas))),
        }

        # 6. Monetary Request Characteristics
        has_amount = bool(re.search(r"\b(rs\.?|inr|₹|\$)\s*\d+", lower_clean)) or bool(re.search(r"\d+\s*(rupees|rs)", lower_clean))
        currency_symbols = []
        if "₹" in raw_text or "rs" in lower_clean:
            currency_symbols.append("INR")
        if "$" in raw_text:
            currency_symbols.append("USD")
        monetary_characteristics = {
            "has_amount": has_amount,
            "currency_symbols": sorted(currency_symbols),
        }

        # 7. Obfuscation Techniques
        obfuscation_list = sorted(list(set(obfuscations or [])))

        # 8. Message Structure Signature
        struct_parts = []
        if sender_id:
            struct_parts.append("HEADER")
        if impersonated_org != "NONE":
            struct_parts.append(f"ORG_{impersonated_org}")
        if manipulation_dict.get("fear", 0) > 0.5:
            struct_parts.append("FEAR")
        if manipulation_dict.get("urgency", 0) > 0.5:
            struct_parts.append("URGENCY")
        if has_url:
            struct_parts.append("LINK")
        if has_imperatives:
            struct_parts.append("CTA")
        message_structure = "+".join(struct_parts) if struct_parts else "GENERIC_MESSAGE"

        # 9. Extracted Entities (Sorted list of IOC values/hashes)
        entities = []
        if extracted_iocs:
            for ioc in extracted_iocs:
                val = ioc.get("value", "").strip().lower()
                if val:
                    entities.append(val)
        entities = sorted(list(set(entities)))

        # 10. Semantic Embedding (384-d)
        if embedding is None:
            embedding = embed_text(cleaned_text).tolist()
        elif hasattr(embedding, "tolist"):
            embedding = embedding.tolist()

        # 11. Temporal Characteristics
        temporal_characteristics = {
            "time_window_hour": int(time.time() // 3600),
            "creation_bucket": "v1_current",
        }

        # 12. Deterministic DNA Hash (SHA-256 of canonical structural traits)
        hash_payload = (
            f"archetype={scam_archetype.value}|org={impersonated_org}|"
            f"obf={','.join(obfuscation_list)}|ent={','.join(entities)}|"
            f"struct={message_structure}|has_url={has_url}|has_vpa={upi_characteristics['has_vpa']}"
        )
        dna_hash = f"dna_{hashlib.sha256(hash_payload.encode('utf-8')).hexdigest()[:16]}"

        return ScamDNAFingerprint(
            version="1.0.0-dna",
            dna_hash=dna_hash,
            scam_archetype=scam_archetype,
            pressure_profile=manipulation_dict,
            language="hi" if "hindi" in lower_raw or re.search(r"[\u0900-\u097F]", raw_text) else "en",
            script="devanagari" if re.search(r"[\u0900-\u097F]", raw_text) else "latin",
            linguistic_structure=linguistic_structure,
            impersonated_organization=impersonated_org,
            url_characteristics=url_characteristics,
            phone_indicators=phone_indicators,
            upi_characteristics=upi_characteristics,
            sender_id=sender_id,
            monetary_request_characteristics=monetary_characteristics,
            obfuscation_techniques=obfuscation_list,
            message_structure=message_structure,
            extracted_entities=entities,
            semantic_embedding=embedding,
            temporal_characteristics=temporal_characteristics,
        )
