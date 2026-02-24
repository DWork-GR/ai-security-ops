from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.assets import router as assets_router
from app.api.chat import router as chat_router
from app.api.errors import router as errors_router
from app.api.incidents import router as incidents_router
from app.api.integrations import router as integrations_router
from app.api.knowledge import router as knowledge_router
from app.api.outbound import router as outbound_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.config import CORS_ORIGINS
from app.database.db import Base, engine
from app.services.scan_job_worker import start_scan_worker, stop_scan_worker


@asynccontextmanager
async def lifespan(_: FastAPI):
    start_scan_worker()
    try:
        yield
    finally:
        stop_scan_worker()

app = FastAPI(
    title="AI Security Operations Assistant",
    description="Integration-first SOC assistant MVP",
    version="0.3.0",
    lifespan=lifespan,
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
app.include_router(outbound_router)
app.include_router(scans_router)


@app.get("/")
def root():
    return {"status": "ok", "service": "ai-security-ops"}


Base.metadata.create_all(bind=engine)
