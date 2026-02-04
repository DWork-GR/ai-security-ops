from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.chat import router as chat_router


app = FastAPI(
    title="AI Security Operations Assistant",
    description="MVP інтелектуальної системи аналізу подій ІБ",
    version="0.1.0"
)


# ⚠️ CORS для локального MVP
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # для разработки
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat_router)


@app.get("/")
def root():
    return {"status": "ok"}

from app.database.db import engine
from app.database.models import Base

Base.metadata.create_all(bind=engine)
