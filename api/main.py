from fastapi import FastAPI

from api.routes.artifacts import router as artifacts_router

app = FastAPI(title="Kavach API", version="1.0.0")


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(artifacts_router, prefix="/artifacts")
