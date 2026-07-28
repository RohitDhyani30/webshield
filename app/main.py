"""
FastAPI application entrypoint.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.api.routes import router as api_router

app = FastAPI(
    title="WebShield",
    description="A non-exploitative DAST tool for OWASP Top 10 style vulnerability scanning.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten this before any real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"message": "WebShield API is running", "docs": "/docs"}


app.include_router(api_router, prefix="/api")
