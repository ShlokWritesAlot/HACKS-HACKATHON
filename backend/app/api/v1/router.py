"""
API v1 router — aggregates all v1 sub-routers.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    analyst_auth,
    analyst_dashboard,
    analyze,
    campaigns,
    feedback,
    health,
    intel,
    ocr,
    playground,
    statemachine,
)

router = APIRouter(prefix="/api/v1")

# ── Health ────────────────────────────────────────────────────────────────────
router.include_router(health.router)

# ── Analyze & Analysis by ID ──────────────────────────────────────────────────
router.include_router(analyze.router, prefix="/analyze", tags=["analyze"])
router.include_router(analyze.router, prefix="/analysis", tags=["analysis"])
router.include_router(ocr.router, prefix="/analyze", tags=["screenshot-ocr"])

# ── Feedback ──────────────────────────────────────────────────────────────────
router.include_router(feedback.router, prefix="/feedback", tags=["feedback"])

# ── Adversarial Playground ────────────────────────────────────────────────────
router.include_router(playground.router, prefix="/playground", tags=["playground"])

# ── Threat Intelligence Extraction ────────────────────────────────────────────
router.include_router(intel.router, prefix="/intel", tags=["intel"])

# ── Campaign Clustering ───────────────────────────────────────────────────────
router.include_router(campaigns.router, prefix="/campaigns", tags=["campaigns"])

# ── Analyst Auth & Command Center ─────────────────────────────────────────────
router.include_router(analyst_auth.router, prefix="/analyst/auth", tags=["analyst-auth"])
router.include_router(analyst_dashboard.router, prefix="/analyst", tags=["analyst-dashboard"])

# ── Scam State Machine & Next-Step Prediction ──────────────────────────────────
router.include_router(statemachine.router, prefix="/conversation", tags=["state-machine"])

