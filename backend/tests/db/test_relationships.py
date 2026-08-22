"""
Tests for SQLAlchemy model relationships.

Verifies that relationships, foreign keys, back_populates, and cascading
delete strategies are correctly defined.
"""

from sqlalchemy import inspect
from sqlalchemy.orm import RelationshipProperty

from app.db.models import (
    Analysis,
    Campaign,
    CampaignMember,
    Feedback,
    Message,
    ScamFamily,
    User,
)


def _get_relationship(model, rel_name):
    """Helper to safely get a relationship property."""
    mapper = inspect(model)
    return mapper.relationships.get(rel_name)


def test_message_analysis_relationship():
    """Verify Message <-> Analysis 1:1 relationship with cascade."""
    rel = _get_relationship(Message, "analysis")
    assert rel is not None
    assert rel.uselist is False
    assert rel.back_populates == "message"
    assert rel.cascade.delete is True
    assert rel.cascade.delete_orphan is True
    
    back_rel = _get_relationship(Analysis, "message")
    assert back_rel is not None
    assert back_rel.back_populates == "analysis"


def test_analysis_feedback_relationship():
    """Verify Analysis <-> Feedback 1:N relationship with cascade."""
    rel = _get_relationship(Analysis, "feedbacks")
    assert rel is not None
    assert rel.uselist is True
    assert rel.cascade.delete is True
    assert rel.cascade.delete_orphan is True


def test_campaign_message_m2m_relationship():
    """Verify Campaign <-> Message M:N via CampaignMember association."""
    # Campaign -> Memberships
    rel1 = _get_relationship(Campaign, "memberships")
    assert rel1.uselist is True
    assert rel1.cascade.delete is True
    assert rel1.cascade.delete_orphan is True
    
    # Message -> Memberships
    rel2 = _get_relationship(Message, "campaign_memberships")
    assert rel2.uselist is True
    assert rel2.cascade.delete is True
    assert rel2.cascade.delete_orphan is True
    
    # CampaignMember -> Campaign/Message
    assert _get_relationship(CampaignMember, "campaign") is not None
    assert _get_relationship(CampaignMember, "message") is not None


def test_scam_family_relationships():
    """Verify ScamFamily -> Analyses and Campaigns (SET NULL on delete)."""
    # Just check relationships exist and back-populate correctly
    # The actual SET NULL behavior is verified in foreign keys in test_constraints
    assert _get_relationship(ScamFamily, "analyses") is not None
    assert _get_relationship(ScamFamily, "campaigns") is not None
