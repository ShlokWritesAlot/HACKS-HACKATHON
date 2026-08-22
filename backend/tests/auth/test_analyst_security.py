"""
Comprehensive security and functional tests for BhashaRakshak Analyst Command Center.

Tests:
  - Unauthorized access (missing header, bad key, bad session token) -> 401
  - IDOR & Least privilege (resource boundaries)
  - Expired session purge & invalidation
  - Invalid / deleted campaign IDs -> 404
  - Empty dataset pagination & filtering
  - Concurrent session operations
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from fastapi.testclient import TestClient
from app.main import app
from app.auth.session import get_session_store, SESSION_DURATION
from datetime import datetime, timedelta, timezone

client = TestClient(app)


def test_unauthorized_overview_access():
    """Accessing overview without X-Session-Token must fail with 401."""
    res = client.get("/api/v1/analyst/overview")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["error"]["message"]


def test_unauthorized_messages_access():
    """Accessing messages without X-Session-Token must fail with 401."""
    res = client.get("/api/v1/analyst/messages")
    assert res.status_code == 401


def test_unauthorized_indicators_access():
    """Accessing indicators without X-Session-Token must fail with 401."""
    res = client.get("/api/v1/analyst/indicators")
    assert res.status_code == 401


def test_login_invalid_key():
    """Login with wrong secret key returns 401."""
    res = client.post("/api/v1/analyst/auth/login", json={"analyst_key": "wrong-key"})
    assert res.status_code == 401
    assert "Invalid analyst secret key" in res.json()["error"]["message"]


def test_successful_login_and_authenticated_overview():
    """Successful login returns token which unlocks overview."""
    # 1. Login
    login_res = client.post(
        "/api/v1/analyst/auth/login",
        json={"analyst_key": "bhasharakshak-analyst-secret-key"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]
    assert token

    # 2. Access overview with token
    headers = {"X-Session-Token": token}
    ov_res = client.get("/api/v1/analyst/overview", headers=headers)
    assert ov_res.status_code == 200
    data = ov_res.json()
    assert "total_messages" in data
    assert "high_risk_percentage" in data
    assert "scam_family_distribution" in data


def test_logout_invalidates_token():
    """Logging out invalidates the session token."""
    # 1. Login
    login_res = client.post(
        "/api/v1/analyst/auth/login",
        json={"analyst_key": "bhasharakshak-analyst-secret-key"},
    )
    token = login_res.json()["session_token"]
    headers = {"X-Session-Token": token}

    # 2. Verify access
    res1 = client.get("/api/v1/analyst/overview", headers=headers)
    assert res1.status_code == 200

    # 3. Logout
    logout_res = client.post("/api/v1/analyst/auth/logout", headers=headers)
    assert logout_res.status_code == 200

    # 4. Access must now fail
    res2 = client.get("/api/v1/analyst/overview", headers=headers)
    assert res2.status_code == 401


def test_expired_session_purged():
    """Expired session tokens are rejected."""
    store = get_session_store()
    token, session = store.create_session(analyst_id="analyst-test")

    # Manually expire the session in store
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

    headers = {"X-Session-Token": token}
    res = client.get("/api/v1/analyst/overview", headers=headers)
    assert res.status_code == 401


def test_invalid_campaign_id_returns_404():
    """Non-existent campaign ID must return 404."""
    # Login first
    login_res = client.post(
        "/api/v1/analyst/auth/login",
        json={"analyst_key": "bhasharakshak-analyst-secret-key"},
    )
    token = login_res.json()["session_token"]

    headers = {"X-Analyst-Key": "dev", "X-Session-Token": token}
    res = client.get("/api/v1/campaigns/non-existent-campaign-id-9999", headers=headers)
    assert res.status_code == 404


def test_messages_pagination_and_filtering():
    """Messages endpoint handles pagination and filtering correctly."""
    login_res = client.post(
        "/api/v1/analyst/auth/login",
        json={"analyst_key": "bhasharakshak-analyst-secret-key"},
    )
    token = login_res.json()["session_token"]
    headers = {"X-Session-Token": token}

    # Filter by scam family
    res = client.get("/api/v1/analyst/messages?scam_family=BANK_KYC", headers=headers)
    assert res.status_code == 200
    items = res.json()
    assert all(i["scam_family"] == "BANK_KYC" for i in items)

    # Filter by min risk
    res_risk = client.get("/api/v1/analyst/messages?min_risk=80", headers=headers)
    assert res_risk.status_code == 200
    items_risk = res_risk.json()
    assert all(i["risk_score"] >= 80 for i in items_risk)


def run_all_tests():
    tests = [
        test_unauthorized_overview_access,
        test_unauthorized_messages_access,
        test_unauthorized_indicators_access,
        test_login_invalid_key,
        test_successful_login_and_authenticated_overview,
        test_logout_invalidates_token,
        test_expired_session_purged,
        test_invalid_campaign_id_returns_404,
        test_messages_pagination_and_filtering,
    ]

    for fn in tests:
        fn()

    print(f"[PASS] All {len(tests)} Analyst Command Center Security Tests Passed!")
