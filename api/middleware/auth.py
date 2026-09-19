import os
from fastapi import Header, HTTPException


async def require_api_key(x_api_key: str = Header(default="")):
    expected = os.environ.get("API_KEY", "")
    # When API_KEY env var is not set, auth is disabled (local dev / tests)
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
