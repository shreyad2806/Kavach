import os
from fastapi import Header, HTTPException


async def require_api_key(x_api_key: str = Header(...)):
    if x_api_key != os.environ.get("API_KEY", ""):
        raise HTTPException(status_code=401, detail="Unauthorized")
