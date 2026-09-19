"""
Lambda entry point for the Kavach API (FastAPI via Mangum).
Used when deployed to AWS Lambda — not needed for local uvicorn.
"""
from mangum import Mangum
from api.main import app

handler = Mangum(app, lifespan="off")
