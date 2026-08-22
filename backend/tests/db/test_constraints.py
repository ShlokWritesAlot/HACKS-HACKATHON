"""
Tests for SQLAlchemy model constraints (Foreign Keys, Unique Constraints).
"""

from app.db.models import (
    Analysis,
    CampaignMember,
    Feedback,
    Indicator,
)


def _get_foreign_keys(model):
    """Helper to extract foreign keys from a model's table."""
    return list(model.__table__.foreign_keys)


def test_analysis_foreign_keys():
    """Verify Analysis foreign keys and ON DELETE behaviors."""
    fks = _get_foreign_keys(Analysis)
    assert len(fks) == 2
    
    # message_id -> CASCADE
    msg_fk = next(fk for fk in fks if fk.parent.name == "message_id")
    assert msg_fk.ondelete == "CASCADE"
    assert msg_fk.column.table.name == "messages"
    
    # scam_family_id -> SET NULL
    scam_fk = next(fk for fk in fks if fk.parent.name == "scam_family_id")
    assert scam_fk.ondelete == "SET NULL"
    assert scam_fk.column.table.name == "scam_families"


def test_unique_constraints():
    """Verify unique constraints (composite keys) on tables."""
    # Indicator: type + value must be unique
    indicator_constraints = [c for c in Indicator.__table__.constraints if getattr(c, "name", "") == "uix_indicator_type_value"]
    assert len(indicator_constraints) == 1
    
    # CampaignMember: campaign_id + message_id must be unique
    cm_constraints = [c for c in CampaignMember.__table__.constraints if getattr(c, "name", "") == "uix_campaign_message"]
    assert len(cm_constraints) == 1
    
    # Feedback: analysis_id + user_id must be unique
    feedback_constraints = [c for c in Feedback.__table__.constraints if getattr(c, "name", "") == "uix_analysis_user_feedback"]
    assert len(feedback_constraints) == 1


def test_audit_event_no_cascade():
    """Verify AuditEvent uses SET NULL, never CASCADE, for user deletion."""
    from app.db.models import AuditEvent
    
    fks = _get_foreign_keys(AuditEvent)
    assert len(fks) == 1
    user_fk = next(fk for fk in fks if fk.parent.name == "user_id")
    
    # We must NEVER delete audit events if a user is deleted
    assert user_fk.ondelete == "SET NULL"
