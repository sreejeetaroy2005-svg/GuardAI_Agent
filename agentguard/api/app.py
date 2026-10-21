"""
FastAPI application factory for AgentGuard.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from agentguard.api.routes import router
from agentguard.config import get_settings


def create_app() -> FastAPI:
    """Instantiate and configure the FastAPI AgentGuard application."""
    settings = get_settings()

    app = FastAPI(
        title="AgentGuard API",
        description=(
            "AI Agent Security and Observability Platform. "
            "Provides synchronous policy enforcement, real-time audit logging, "
            "incident monitoring, kill switch circuit breakers, and adversarial resilience testing."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Basic CORS setup for dashboard / local integrations
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routes
    app.include_router(router)

    return app


app = create_app()
