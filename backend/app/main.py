from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.app.config import settings
from backend.app.models.db import init_db
from backend.app.api.endpoints import router as api_router
from backend.app.api.github_endpoints import router as github_router
from backend.app.api.similarity_endpoints import router as similarity_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup DB schema initialization
    init_db()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Forge - AI-Assisted Security Code Review & Vulnerability Analysis Platform",
    lifespan=lifespan
)

# CORS Middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(api_router, prefix=settings.API_PREFIX)
app.include_router(github_router, prefix=settings.API_PREFIX)
app.include_router(similarity_router, prefix=settings.API_PREFIX)
app.include_router(api_router)  # Direct root mounts for /health endpoint


