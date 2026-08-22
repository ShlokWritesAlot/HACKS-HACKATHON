"""
Versioned Trusted Organization Registry for BhashaRakshak.

Contains structured metadata for major organizations frequently targeted
for brand and government impersonation in Indian scams.

SECURITY:
  - Domain validation is 100% static against these official whitelists.
  - Zero network/DNS fetching is performed.
"""

from __future__ import annotations

import enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class OrgCategoryEnum(str, enum.Enum):
    BANK = "BANK"
    PAYMENT = "PAYMENT"
    TELECOM = "TELECOM"
    GOVERNMENT = "GOVERNMENT"
    TAX = "TAX"
    POSTAL = "POSTAL"


class TrustedOrganization(BaseModel):
    """Structured metadata for a registered trusted organization."""
    model_config = ConfigDict(extra="forbid")

    org_id: str = Field(..., description="Unique org identifier (e.g. 'org_sbi').")
    canonical_name: str = Field(..., description="Official canonical name (e.g. 'State Bank of India').")
    aliases: List[str] = Field(..., description="List of aliases in English, Hindi Devanagari, and Hinglish.")
    legitimate_domains: List[str] = Field(..., description="Official verified domain names.")
    legitimate_sender_ids: List[str] = Field(..., description="Official DLT sender ID headers.")
    category: OrgCategoryEnum = Field(..., description="Organization industry category.")
    base_confidence: float = Field(default=0.95, ge=0.0, le=1.0)
    official_support_url: str = Field(..., description="Official verified support website or portal.")


class TrustedOrgRegistry:
    """
    Versioned registry of trusted Indian financial, government, telecom, and courier entities.
    """
    VERSION: str = "1.0.0-registry"

    def __init__(self):
        self._orgs: Dict[str, TrustedOrganization] = {}
        self._initialize_default_registry()

    def _initialize_default_registry(self):
        # 1. State Bank of India
        self.register(
            TrustedOrganization(
                org_id="org_sbi",
                canonical_name="State Bank of India",
                aliases=["sbi", "sbiinb", "sbipay", "एसबीआई", "स्टेट बैंक", "state bank of india", "onlinesbi"],
                legitimate_domains=["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "bank.sbi"],
                legitimate_sender_ids=["SBIINB", "SBIPAY", "SBICRD", "SBIOTP", "SBIMB"],
                category=OrgCategoryEnum.BANK,
                base_confidence=0.95,
                official_support_url="https://onlinesbi.sbi",
            )
        )

        # 2. HDFC Bank
        self.register(
            TrustedOrganization(
                org_id="org_hdfc",
                canonical_name="HDFC Bank",
                aliases=["hdfc", "hdfcbk", "एचडीएफसी", "hdfc bank", "hdfcbank"],
                legitimate_domains=["hdfcbank.com", "netbanking.hdfcbank.com"],
                legitimate_sender_ids=["HDFCBK", "HDFCTP", "HDFCAL"],
                category=OrgCategoryEnum.BANK,
                base_confidence=0.95,
                official_support_url="https://www.hdfcbank.com",
            )
        )

        # 3. ICICI Bank
        self.register(
            TrustedOrganization(
                org_id="org_icici",
                canonical_name="ICICI Bank",
                aliases=["icici", "icicib", "आईसीआईसीआई", "icici bank"],
                legitimate_domains=["icicibank.com", "icicibank.co.in"],
                legitimate_sender_ids=["ICICIB", "ICICIT", "ICICIP"],
                category=OrgCategoryEnum.BANK,
                base_confidence=0.95,
                official_support_url="https://www.icicibank.com",
            )
        )

        # 4. Axis Bank
        self.register(
            TrustedOrganization(
                org_id="org_axis",
                canonical_name="Axis Bank",
                aliases=["axis", "axisbk", "एक्सिस", "axis bank"],
                legitimate_domains=["axisbank.com"],
                legitimate_sender_ids=["AXISBK", "AXISTP"],
                category=OrgCategoryEnum.BANK,
                base_confidence=0.95,
                official_support_url="https://www.axisbank.com",
            )
        )

        # 5. Income Tax Department
        self.register(
            TrustedOrganization(
                org_id="org_incometax",
                canonical_name="Income Tax Department",
                aliases=["income tax", "incometax", "आयकर विभाग", "tax refund", "itr"],
                legitimate_domains=["incometax.gov.in", "incometaxindia.gov.in"],
                legitimate_sender_ids=["ITAXIN", "ITAXDE", "ITAXGOV"],
                category=OrgCategoryEnum.TAX,
                base_confidence=0.96,
                official_support_url="https://www.incometax.gov.in",
            )
        )

        # 6. Electricity Department
        self.register(
            TrustedOrganization(
                org_id="org_electricity",
                canonical_name="State Electricity Department",
                aliases=["electricity dept", "bijli", "power corp", "बिजली विभाग", "बिजली बिल", "electricity bill"],
                legitimate_domains=["uppcl.org", "bsesdelhi.com", "mahadiscom.in"],
                legitimate_sender_ids=["BIJLI", "UPPCL", "BSESDL"],
                category=OrgCategoryEnum.GOVERNMENT,
                base_confidence=0.94,
                official_support_url="https://uppcl.org",
            )
        )

        # 7. India Post
        self.register(
            TrustedOrganization(
                org_id="org_indiapost",
                canonical_name="India Post",
                aliases=["india post", "post office", "भारतीय डाक", "indiapost"],
                legitimate_domains=["indiapost.gov.in"],
                legitimate_sender_ids=["INDPOST", "POSTIN"],
                category=OrgCategoryEnum.POSTAL,
                base_confidence=0.95,
                official_support_url="https://www.indiapost.gov.in",
            )
        )

        # 8. FedEx Express
        self.register(
            TrustedOrganization(
                org_id="org_fedex",
                canonical_name="FedEx Express",
                aliases=["fedex", "फेडेक्स", "fedex customs"],
                legitimate_domains=["fedex.com"],
                legitimate_sender_ids=["FEDEX", "FDXIND"],
                category=OrgCategoryEnum.POSTAL,
                base_confidence=0.94,
                official_support_url="https://www.fedex.com",
            )
        )

        # 9. Paytm
        self.register(
            TrustedOrganization(
                org_id="org_paytm",
                canonical_name="Paytm",
                aliases=["paytm", "पेटीएम"],
                legitimate_domains=["paytm.com", "paytm.in"],
                legitimate_sender_ids=["PAYTM", "PAYTMS"],
                category=OrgCategoryEnum.PAYMENT,
                base_confidence=0.95,
                official_support_url="https://paytm.com",
            )
        )

        # 10. Reliance Jio
        self.register(
            TrustedOrganization(
                org_id="org_jio",
                canonical_name="Reliance Jio",
                aliases=["jio", "reliance jio", "जिओ"],
                legitimate_domains=["jio.com"],
                legitimate_sender_ids=["JIOSMS", "JIOINF"],
                category=OrgCategoryEnum.TELECOM,
                base_confidence=0.95,
                official_support_url="https://www.jio.com",
            )
        )

    def register(self, org: TrustedOrganization):
        self._orgs[org.org_id] = org

    def get_all_orgs(self) -> List[TrustedOrganization]:
        return list(self._orgs.values())

    def lookup_by_alias(self, text: str) -> Optional[TrustedOrganization]:
        text_lower = text.lower()
        for org in self._orgs.values():
            for alias in org.aliases:
                if alias.lower() in text_lower:
                    return org
        return None

    def lookup_by_domain(self, domain: str) -> Optional[TrustedOrganization]:
        domain_lower = domain.lower().strip()
        for org in self._orgs.values():
            for leg_dom in org.legitimate_domains:
                if leg_dom in domain_lower or domain_lower.endswith("." + leg_dom):
                    return org
        return None


# Global singleton instance
_registry = TrustedOrgRegistry()

def get_trusted_registry() -> TrustedOrgRegistry:
    return _registry
