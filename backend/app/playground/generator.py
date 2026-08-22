from __future__ import annotations

import random
import re
from typing import Dict, List, Tuple

from app.playground.schemas import PerturbationType

# Leetspeak substitution map
LEET_DICT = {
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8",
    "A": "4", "E": "3", "I": "1", "O": "0", "S": "5", "T": "7", "B": "8",
}

# Common SMS abbreviations
ABBREV_DICT = {
    "account": "acnt",
    "update": "upd8",
    "verify": "v3rify",
    "immediately": "immdtly",
    "please": "plz",
    "today": "2day",
    "before": "b4",
    "message": "msg",
    "number": "no",
    "customer": "custmr",
    "urgent": "urgnt",
    "service": "srvc",
    "kyc": "kyyc",
}

# Phonetic & Hinglish word mappings
HINGLISH_DICT = {
    "your": "apka",
    "account": "acnt",
    "bank": "bank",
    "will be": "hoga",
    "blocked": "band",
    "suspended": "block",
    "update": "upd8 kro",
    "immediately": "jaldi",
    "call": "call kro",
    "click": "click kro",
    "pay": "pay kro",
    "bill": "bijli bill",
    "is": "hai",
    "unpaid": "baki hai",
}

# Devanagari script equivalents for mixed-script construction
DEVA_MIX_DICT = {
    "bank": "बैंक",
    "account": "खाता",
    "update": "अपडेट",
    "kyc": "केवाईसी",
    "pan": "पैन",
    "blocked": "ब्लॉक",
    "immediately": "तुरंत",
    "urgent": "अति आवश्यक",
    "call": "कॉल",
    "click": "क्लिक",
    "today": "आज",
}


class AdversarialVariantGenerator:
    """
    Generates meaning-preserving, controlled adversarial variations 
    of scam messages for defensive robustness profiling.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_all_variants(
        self,
        text: str,
        perturbations: List[PerturbationType] | None = None,
        intensity: str = "medium",
    ) -> List[Tuple[PerturbationType, str, str]]:
        """
        Generates variants across requested perturbation categories.
        
        Returns:
            List of (PerturbationType, Display Name, Variant Text)
        """
        targets = perturbations or list(PerturbationType)
        results: List[Tuple[PerturbationType, str, str]] = []

        mapping = {
            # Original 10
            PerturbationType.VOWEL_DELETION: ("Vowel Deletion", self.vowel_deletion),
            PerturbationType.ADJACENT_SWAP: ("Adjacent Character Swap", self.adjacent_swap),
            PerturbationType.NUMBER_SUBSTITUTION: ("Leetspeak Substitution", self.number_substitution),
            PerturbationType.REPEATED_CHARS: ("Repeated Characters", self.repeated_characters),
            PerturbationType.WHITESPACE_MANIPULATION: ("Whitespace Manipulation", self.whitespace_manipulation),
            PerturbationType.PHONETIC_TRANSLITERATION: ("Phonetic Transliteration", self.phonetic_transliteration),
            PerturbationType.HINGLISH_SYNTHESIS: ("Hinglish Code-Mixing", self.hinglish_synthesis),
            PerturbationType.MIXED_SCRIPTS: ("Mixed Devanagari Script", self.mixed_scripts),
            PerturbationType.PUNCTUATION_INSERTION: ("Punctuation Camouflage", self.punctuation_insertion),
            PerturbationType.INFORMAL_ABBREVIATIONS: ("Informal SMS Abbreviations", self.informal_abbreviations),

            # New 9
            PerturbationType.UNICODE_CONFUSABLES: ("Unicode Homoglyphs", self.unicode_confusables),
            PerturbationType.ZERO_WIDTH_CHARS: ("Zero-Width Characters", self.zero_width_chars),
            PerturbationType.UNICODE_NORMALIZATION: ("Unicode Normalization Attack", self.unicode_normalization),
            PerturbationType.MULTILINGUAL_SWITCHING: ("Multilingual Code-Switching", self.multilingual_switching),
            PerturbationType.NESTED_OBFUSCATION: ("Nested Multi-Layer Obfuscation", self.nested_obfuscation),
            PerturbationType.OCR_CORRUPTION: ("OCR-Like Typo Corruption", self.ocr_corruption),
            PerturbationType.REALISTIC_TYPOS: ("Realistic QWERTY Typos", self.realistic_typos),
            PerturbationType.DOMAIN_OBFUSCATION: ("Domain Link Obfuscation", self.domain_obfuscation),
            PerturbationType.SENDER_ID_MUTATION: ("Sender ID Header Mutation", self.sender_id_mutation),
        }

        for p_type in targets:
            if p_type in mapping:
                name, fn = mapping[p_type]
                variant = fn(text, intensity=intensity)
                results.append((p_type, name, variant))

        return results

    def vowel_deletion(self, text: str, intensity: str = "medium") -> str:
        """Deletes vowels from middle/end of words while preserving meaning."""
        prob = 0.4 if intensity == "low" else 0.7 if intensity == "medium" else 0.95
        words = text.split()
        new_words = []
        for word in words:
            if len(word) <= 3 or "http" in word or "bit.ly" in word:
                new_words.append(word)
                continue
            first, rest = word[0], word[1:]
            new_rest = "".join(
                c for c in rest if c.lower() not in "aeiou" or self.rng.random() > prob
            )
            new_words.append(first + new_rest)
        return " ".join(new_words)

    def adjacent_swap(self, text: str, intensity: str = "medium") -> str:
        """Swaps adjacent letters within words (typographical camouflage)."""
        prob = 0.3 if intensity == "low" else 0.5 if intensity == "medium" else 0.8
        words = text.split()
        new_words = []
        for word in words:
            if len(word) <= 3 or "http" in word or "bit.ly" in word or self.rng.random() > prob:
                new_words.append(word)
                continue
            chars = list(word)
            idx = self.rng.randint(1, len(chars) - 2)
            chars[idx], chars[idx + 1] = chars[idx + 1], chars[idx]
            new_words.append("".join(chars))
        return " ".join(new_words)

    def number_substitution(self, text: str, intensity: str = "medium") -> str:
        """Substitutes letters with leetspeak numbers."""
        prob = 0.4 if intensity == "low" else 0.7 if intensity == "medium" else 0.9
        out = []
        for char in text:
            if char in LEET_DICT and self.rng.random() < prob:
                out.append(LEET_DICT[char])
            else:
                out.append(char)
        return "".join(out)

    def repeated_characters(self, text: str, intensity: str = "medium") -> str:
        """Repeats characters to evade exact regex matching."""
        repeat_count = 3 if intensity == "low" else 4 if intensity == "medium" else 6
        words = text.split()
        new_words = []
        for word in words:
            if len(word) <= 3 or "http" in word:
                new_words.append(word)
                continue
            # Pick a random vowel or consonant to repeat
            idx = self.rng.randint(0, len(word) - 1)
            char = word[idx]
            new_word = word[:idx] + (char * repeat_count) + word[idx + 1:]
            new_words.append(new_word)
        return " ".join(new_words)

    def whitespace_manipulation(self, text: str, intensity: str = "medium") -> str:
        """Removes spaces or injects zero-width/micro spaces."""
        words = text.split()
        if intensity == "low":
            return " ".join(words).replace(". ", ".")
        elif intensity == "medium":
            # Strip spaces between pairs of words
            out = []
            for i, w in enumerate(words):
                out.append(w)
                if i % 2 == 0:
                    out.append(" ")
            return "".join(out)
        else:
            # Extreme: collapse almost all spaces into CamelCase
            return "".join(w.capitalize() for w in words)

    def phonetic_transliteration(self, text: str, intensity: str = "medium") -> str:
        """Replaces common English scam tokens with phonetic romanized Hindi."""
        words = text.split()
        new_words = []
        for word in words:
            clean = re.sub(r"[^\w\s]", "", word.lower())
            if clean in HINGLISH_DICT:
                punct = word[len(clean):] if len(word) > len(clean) else ""
                new_words.append(HINGLISH_DICT[clean] + punct)
            else:
                new_words.append(word)
        return " ".join(new_words)

    def hinglish_synthesis(self, text: str, intensity: str = "medium") -> str:
        """Synthesizes structured conversational Hinglish message."""
        # Baseline semantic synthesis
        hinglish_template = (
            "Apka bank acnt band hoga. KYC upd8 kro jaldi. Click bit.ly/kyc-unblock"
        )
        if "electricity" in text.lower() or "bijli" in text.lower() or "power" in text.lower():
            return "Apka bijli connection rat ko cut hoga bill baki hai. Turant call kro 9876543210"
        elif "parcel" in text.lower() or "courier" in text.lower() or "fedex" in text.lower():
            return "Apka courier parcel customs me roka hai. Rs 50 charge pay kro link pe"
        elif "job" in text.lower() or "salary" in text.lower():
            return "Ghar baithe kamaye daily 5000 rupaye. HR se WhatsApp pe contact kro"
        return hinglish_template

    def mixed_scripts(self, text: str, intensity: str = "medium") -> str:
        """Injects native Devanagari script words inside Latin text."""
        words = text.split()
        new_words = []
        for word in words:
            clean = re.sub(r"[^\w\s]", "", word.lower())
            if clean in DEVA_MIX_DICT:
                new_words.append(DEVA_MIX_DICT[clean])
            else:
                new_words.append(word)
        return " ".join(new_words)

    def punctuation_insertion(self, text: str, intensity: str = "medium") -> str:
        """Camouflages tokens with periods, underscores, or hyphens."""
        sep = "." if intensity == "low" else "_" if intensity == "medium" else "-"
        words = text.split()
        new_words = []
        for word in words:
            if len(word) >= 3 and "http" not in word:
                new_words.append(sep.join(list(word)))
            else:
                new_words.append(word)
        return " ".join(new_words)

    # ── New 9 Red-Team Transformations ────────────────────────────────────────

    def unicode_confusables(self, text: str, intensity: str = "medium") -> str:
        """Replaces Latin characters with lookalike Cyrillic/Greek confusables."""
        confusable_map = {
            "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "y": "у", "x": "х",
            "A": "А", "B": "В", "E": "Е", "K": "К", "M": "М", "H": "Н", "O": "О",
            "P": "Р", "C": "С", "T": "Т", "X": "Х", "i": "і",
        }
        prob = 0.4 if intensity == "low" else 0.7 if intensity == "medium" else 0.95
        out = []
        for char in text:
            if char in confusable_map and self.rng.random() < prob:
                out.append(confusable_map[char])
            else:
                out.append(char)
        return "".join(out)

    def zero_width_chars(self, text: str, intensity: str = "medium") -> str:
        """Inserts zero-width spaces (\u200B), non-joiners (\u200C), and joiners (\u200D)."""
        zw_chars = ["\u200B", "\u200C", "\u200D", "\uFEFF"]
        words = text.split()
        new_words = []
        for word in words:
            if len(word) >= 3:
                chars = list(word)
                idx = self.rng.randint(1, len(chars) - 1)
                chars.insert(idx, self.rng.choice(zw_chars))
                new_words.append("".join(chars))
            else:
                new_words.append(word)
        return " ".join(new_words)

    def unicode_normalization(self, text: str, intensity: str = "medium") -> str:
        """Decomposes characters into NFD form with combining diacritics."""
        import unicodedata
        nfd = unicodedata.normalize("NFD", text)
        # Inject explicit combining acute accent \u0301
        out = []
        for char in nfd:
            out.append(char)
            if char.lower() in "aeiou" and self.rng.random() < 0.5:
                out.append("\u0301")
        return "".join(out)

    def multilingual_switching(self, text: str, intensity: str = "medium") -> str:
        """Switches languages mid-sentence (English, Hindi Devanagari, Hinglish)."""
        return (
            "Dear customer, apka SBI bank account block ho jayega. "
            "कृपया तुरंत KYC अपडेट करें at http://sbi-kyc-update.xyz"
        )

    def nested_obfuscation(self, text: str, intensity: str = "medium") -> str:
        """Applies multi-layered recursive transformations (Leetspeak -> Homoglyph -> Zero-width)."""
        step1 = self.number_substitution(text, intensity="high")
        step2 = self.unicode_confusables(step1, intensity="medium")
        step3 = self.zero_width_chars(step2, intensity="low")
        return step3

    def ocr_corruption(self, text: str, intensity: str = "medium") -> str:
        """Simulates common OCR misrecognitions (rn -> m, l -> 1, O -> 0, cl -> d)."""
        t = text
        t = t.replace("rn", "m").replace("cl", "d").replace("vv", "w")
        t = t.replace("l", "1").replace("O", "0")
        return t

    def realistic_typos(self, text: str, intensity: str = "medium") -> str:
        """Swaps letters with adjacent QWERTY keyboard keys."""
        qwerty_adj = {
            "a": "sqwz", "b": "vghn", "c": "xdfv", "d": "ersfcx", "e": "wsdr",
            "f": "rtgvcd", "g": "tyhbvf", "h": "yujnbg", "i": "ujko", "k": "ijlm",
            "l": "okp", "m": "njk", "n": "bhjm", "o": "iklp", "p": "ol",
            "r": "edft", "s": "wedxza", "t": "rfgy", "u": "yhji", "v": "cfgb",
            "w": "qase", "y": "tghu", "z": "asx",
        }
        words = text.split()
        new_words = []
        for word in words:
            if len(word) > 3 and "http" not in word and self.rng.random() < 0.6:
                idx = self.rng.randint(0, len(word) - 1)
                c = word[idx].lower()
                if c in qwerty_adj:
                    rep = self.rng.choice(list(qwerty_adj[c]))
                    word = word[:idx] + rep + word[idx + 1:]
            new_words.append(word)
        return " ".join(new_words)

    def domain_obfuscation(self, text: str, intensity: str = "medium") -> str:
        """Obfuscates URLs and domains using bracketed dots, hyphenation, or homoglyphs."""
        t = text.replace("sbi.co.in", "sbi[.]co[.]in").replace(".com", "[.]com").replace("http://", "h**p://")
        return t

    def sender_id_mutation(self, text: str, intensity: str = "medium") -> str:
        """Mutates DLT sender headers to evade exact string matches."""
        # Prepend mutated sender header representation
        return f"[Sender: S-B-I-I-N-B] {text}"


    def informal_abbreviations(self, text: str, intensity: str = "medium") -> str:
        """Substitutes tokens with informal SMS shortcodes and abbreviations."""
        words = text.split()
        new_words = []
        for word in words:
            clean = re.sub(r"[^\w\s]", "", word.lower())
            if clean in ABBREV_DICT:
                punct = word[len(clean):] if len(word) > len(clean) else ""
                new_words.append(ABBREV_DICT[clean] + punct)
            else:
                new_words.append(word)
        return " ".join(new_words)
