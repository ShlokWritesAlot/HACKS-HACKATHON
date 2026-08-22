"""
BhashaRakshak database models.

All SQLAlchemy models are registered here for Alembic discovery.
Gracefully handles environments where SQLAlchemy is absent.
"""

from app.db.base import HAS_SQLALCHEMY

if HAS_SQLALCHEMY:
    from .analyses import Analysis
    from .audit import AuditEvent
    from .campaigns import Campaign, CampaignMember
    from .feedback import Feedback
    from .messages import Message
    from .scams import Indicator, ScamFamily
    from .users import User
else:
    class Analysis: pass  # type: ignore
    class AuditEvent: pass  # type: ignore
    class Campaign: pass  # type: ignore
    class CampaignMember: pass  # type: ignore
    class Feedback: pass  # type: ignore
    class Indicator: pass  # type: ignore
    class Message: pass  # type: ignore
    class ScamFamily: pass  # type: ignore
    class User: pass  # type: ignore

__all__ = [
    "Analysis",
    "AuditEvent",
    "Campaign",
    "CampaignMember",
    "Feedback",
    "Indicator",
    "Message",
    "ScamFamily",
    "User",
]
