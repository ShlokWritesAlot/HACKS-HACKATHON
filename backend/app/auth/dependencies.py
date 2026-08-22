"""
FastAPI Dependencies for Analyst Authentication and Authorization.
"""

from __future__ import annotations

from typing import Optional

from fastapi import Header, HTTPException, status

from app.auth.session import AnalystSession, get_session_store


def get_current_analyst(
    x_session_token: Optional[str] = Header(default=None),
) -> AnalystSession:
    """
    Dependency requiring a valid analyst session token.
    Raises 401 UNAUTHORIZED if missing or invalid.
    """
    if not x_session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid X-Session-Token header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session_store = get_session_store()
    session = session_store.verify_token(x_session_token)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return session
