"""
Analyst authentication endpoints: Login and Logout.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth.session import (
    AnalystSession,
    get_session_store,
    verify_analyst_key,
)

router = APIRouter()


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analyst_key: str = Field(..., min_length=1, description="Analyst Secret Key")


class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_token: str
    session_id: str
    analyst_id: str
    role: str
    expires_at: datetime


class LogoutResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyst Login",
    description="Authenticate with analyst secret key and retrieve a session token.",
)
def login(request: LoginRequest) -> LoginResponse:
    if not verify_analyst_key(request.analyst_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid analyst secret key.",
        )

    store = get_session_store()
    raw_token, session = store.create_session(analyst_id="analyst-01")

    return LoginResponse(
        session_token=raw_token,
        session_id=session.session_id,
        analyst_id=session.analyst_id,
        role=session.role,
        expires_at=session.expires_at,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyst Logout",
    description="Invalidate current session token.",
)
def logout(x_session_token: Optional[str] = Header(default=None)) -> LogoutResponse:
    if x_session_token:
        store = get_session_store()
        store.invalidate_token(x_session_token)

    return LogoutResponse(message="Successfully logged out.")
