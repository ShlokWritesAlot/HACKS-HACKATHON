"""
Pluggable threat intelligence provider architecture for BhashaRakshak.

Architecture:
    BaseThreatIntelProvider (abstract interface)
        └── LocalThreatIntelProvider (built-in static blocklist, MVP default)
        └── (Future) VirusTotalProvider
        └── (Future) PhishTankProvider
        └── (Future) SpamhausProvider

SECURITY CONTRACT:
    - Providers that make outbound HTTP requests MUST call ssrf.is_safe_for_enrichment()
      before sending ANY network request.
    - Provider initialization MUST NOT accept raw user-supplied URLs as targets.
    - All provider implementations must inherit from BaseThreatIntelProvider.
"""

from __future__ import annotations

import abc
import logging
from typing import List, Optional

from app.intel.schemas import EnrichmentVerdict, ExtractedIndicator, IndicatorType

logger = logging.getLogger(__name__)


class BaseThreatIntelProvider(abc.ABC):
    """
    Abstract base class for all threat intelligence enrichment adapters.

    New providers must implement `enrich_indicator()` to return an
    EnrichmentVerdict without performing blind HTTP fetches.
    """

    @property
    @abc.abstractmethod
    def provider_name(self) -> str:
        """Human-readable name of this provider (e.g. 'VirusTotal')."""
        ...

    @abc.abstractmethod
    async def enrich_indicator(self, indicator: ExtractedIndicator) -> Optional[EnrichmentVerdict]:
        """
        Enrich a single indicator with threat intelligence.

        MUST NOT directly fetch user-supplied URLs.
        MUST call ssrf.is_safe_for_enrichment() before any network request.

        Returns EnrichmentVerdict or None if the provider has no data.
        """
        ...

    async def enrich_batch(self, indicators: List[ExtractedIndicator]) -> List[EnrichmentVerdict]:
        """Enrich a batch of indicators, skipping those with no result."""
        verdicts: List[EnrichmentVerdict] = []
        for indicator in indicators:
            result = await self.enrich_indicator(indicator)
            if result is not None:
                verdicts.append(result)
        return verdicts


# ── Static / Built-in Blocklist Provider ──────────────────────────────────────

# Known high-risk dynamic DNS and free-hosting domains frequently abused in scams
_KNOWN_MALICIOUS_DOMAINS: frozenset[str] = frozenset({
    "fedex-customs.live",
    "sbi-kyc-update.xyz",
    "kyc-sbi-unblock.click",
    "airtelpostpaid.tk",
    "hdfc-fastag-recharge.ml",
    "paytm-kyc-verify.ga",
    "bit.ly",          # URL shortener — flagged suspicious, not confirmed malicious
    "cutt.ly",
    "t.co",
    "is.gd",
})

_KNOWN_MALICIOUS_URLS_PREFIX: frozenset[str] = frozenset({
    "http://fedex-customs.live",
    "http://phish.xyz",
    "https://kyc-sbi-unblock",
})

_SUSPICIOUS_UPI_HANDLES: frozenset[str] = frozenset({
    # Known abused collection UPI handles (example set)
    "collect.scam@paytm",
    "fraudmerchant@okaxis",
})


class LocalThreatIntelProvider(BaseThreatIntelProvider):
    """
    Built-in, zero-dependency static threat intelligence provider.

    Uses a curated local blocklist of known-malicious domains, URL prefixes,
    and UPI handles. This is the MVP default — no outbound network requests.
    """

    @property
    def provider_name(self) -> str:
        return "BhashaRakshak-Local"

    async def enrich_indicator(self, indicator: ExtractedIndicator) -> Optional[EnrichmentVerdict]:
        value_lower = indicator.value.lower()

        if indicator.type == IndicatorType.URL:
            is_malicious = any(value_lower.startswith(p) for p in _KNOWN_MALICIOUS_URLS_PREFIX)
            domain = indicator.metadata.get("host", "").lower()
            if domain in _KNOWN_MALICIOUS_DOMAINS:
                is_malicious = True
            if is_malicious:
                return EnrichmentVerdict(
                    provider=self.provider_name,
                    indicator_value=indicator.value,
                    is_known_malicious=True,
                    threat_category="phishing_url",
                    reputation_score=0.02,
                    raw={"source": "local_blocklist"},
                )

        elif indicator.type == IndicatorType.DOMAIN:
            if value_lower in _KNOWN_MALICIOUS_DOMAINS:
                return EnrichmentVerdict(
                    provider=self.provider_name,
                    indicator_value=indicator.value,
                    is_known_malicious=True,
                    threat_category="phishing_domain",
                    reputation_score=0.05,
                    raw={"source": "local_blocklist"},
                )

        elif indicator.type == IndicatorType.UPI_ID:
            if value_lower in _SUSPICIOUS_UPI_HANDLES:
                return EnrichmentVerdict(
                    provider=self.provider_name,
                    indicator_value=indicator.value,
                    is_known_malicious=True,
                    threat_category="fraudulent_upi",
                    reputation_score=0.01,
                    raw={"source": "local_blocklist"},
                )

        return None


# ── Provider Registry ─────────────────────────────────────────────────────────

class ThreatIntelRegistry:
    """
    Registry of active threat intelligence providers.

    Usage:
        registry = ThreatIntelRegistry()
        registry.register(LocalThreatIntelProvider())
        # registry.register(VirusTotalProvider(api_key="..."))

        verdicts = await registry.enrich_all(indicators)
    """

    def __init__(self) -> None:
        self._providers: List[BaseThreatIntelProvider] = []

    def register(self, provider: BaseThreatIntelProvider) -> None:
        logger.info("Registered threat intel provider: %s", provider.provider_name)
        self._providers.append(provider)

    async def enrich_all(self, indicators: List[ExtractedIndicator]) -> List[EnrichmentVerdict]:
        """Run all registered providers across all indicators."""
        verdicts: List[EnrichmentVerdict] = []
        for provider in self._providers:
            try:
                batch = await provider.enrich_batch(indicators)
                verdicts.extend(batch)
            except Exception as exc:
                logger.error(
                    "Threat intel provider %s failed: %s",
                    provider.provider_name,
                    exc,
                )
        return verdicts


def build_default_registry() -> ThreatIntelRegistry:
    """Build and return the default Phase 1 provider registry."""
    registry = ThreatIntelRegistry()
    registry.register(LocalThreatIntelProvider())
    return registry
