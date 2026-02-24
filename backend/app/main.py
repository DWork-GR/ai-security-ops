from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.assets import router as assets_router
from app.api.chat import router as chat_router
from app.api.errors import router as errors_router
from app.api.incidents import router as incidents_router
from app.api.integrations import router as integrations_router
from app.api.knowledge import router as knowledge_router
from app.api.reports import router as reports_router
from app.config import CORS_ORIGINS
from app.database.db import Base, engine

app = FastAPI(
    title="AI Security Operations Assistant",
    description="Integration-first SOC assistant MVP",
    version="0.3.0",
)

cors_origins = CORS_ORIGINS.split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in cors_origins if origin.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)

app.include_router(chat_router)
app.include_router(integrations_router)
app.include_router(incidents_router)
app.include_router(reports_router)
app.include_router(knowledge_router)
app.include_router(errors_router)
app.include_router(assets_router)


@app.get("/")
def root():
    return {"status": "ok", "service": "ai-security-ops"}


Base.metadata.create_all(bind=engine)
