"""
Tests for SQLAlchemy models.

Since we cannot run these against a live database locally,
these tests focus on model definition sanity checks:
- Verifying __tablename__
- Verifying column definitions and lengths
- Verifying Enum mappings
"""

from app.db.models import (
    Analysis,
    AuditEvent,
    Campaign,
    CampaignMember,
    Feedback,
    Indicator,
    Message,
    ScamFamily,
    User,
)
from app.db.models.analyses import RiskLevel
from app.db.models.messages import MessageSource
from app.db.models.scams import IndicatorType
from app.db.models.users import UserRole


def test_table_names():
    """Verify all models have correct table names."""
    assert User.__tablename__ == "users"
    assert ScamFamily.__tablename__ == "scam_families"
    assert Indicator.__tablename__ == "indicators"
    assert Message.__tablename__ == "messages"
    assert Analysis.__tablename__ == "analyses"
    assert Campaign.__tablename__ == "campaigns"
    assert CampaignMember.__tablename__ == "campaign_members"
    assert Feedback.__tablename__ == "feedback"
    assert AuditEvent.__tablename__ == "audit_events"


def test_enum_definitions():
    """Verify that Enum classes contain the correct values."""
    assert UserRole.ADMIN.value == "admin"
    assert UserRole.ANALYST.value == "analyst"
    
    assert IndicatorType.PHONE_NUMBER.value == "phone_number"
    assert IndicatorType.DOMAIN.value == "domain"
    
    assert MessageSource.USER_SUBMISSION.value == "user_submission"
    assert MessageSource.HONEYPOT.value == "honeypot"
    
    assert RiskLevel.SAFE.value == "safe"
    assert RiskLevel.MALICIOUS.value == "malicious"


def test_model_column_types():
    """Verify that specific columns exist and are of correct types/lengths."""
    
    # Message privacy fields
    assert Message.raw_text.property.columns[0].nullable is True
    assert Message.sender_id.property.columns[0].nullable is True
    assert Message.content_hash.property.columns[0].type.length == 64
    
    # User security fields
    assert User.hashed_password.property.columns[0].nullable is False
    assert User.hashed_password.property.columns[0].type.length == 255
    
    # Analysis structured fields
    assert Analysis.manipulation_signals.property.columns[0].type.__class__.__name__ == "ARRAY"
    assert Analysis.obfuscation_signals.property.columns[0].type.__class__.__name__ == "ARRAY"
