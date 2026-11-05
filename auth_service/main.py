"""Main FastAPI Application Entrypoint & Factory (Layer 5: API).

Assembles FastAPI instance, lifecycle hooks, middleware pipeline, exception handlers,
and OpenAPI documentation metadata.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from auth_service.config import settings
from auth_service.core.exceptions import AaaSException, to_http_exception
from auth_service.core.logger import logger
from auth_service.storage.postgres.database import init_db, close_db
from auth_service.storage.redis.client import close_redis_client
from auth_service.api.templates.landing import LANDING_PAGE_HTML

# Middleware
from auth_service.api.middleware.request_id import RequestIdMiddleware
from auth_service.api.middleware.security_headers import SecurityHeadersMiddleware
from auth_service.api.middleware.tenant import TenantResolutionMiddleware
from auth_service.api.middleware.request_logger import RequestLoggerMiddleware

# Routers
from auth_service.api.routes.auth import router as auth_router
from auth_service.api.routes.oauth import router as oauth_router
from auth_service.api.routes.users import router as users_router
from auth_service.api.routes.roles import router as roles_router
from auth_service.api.routes.permissions import router as permissions_router
from auth_service.api.routes.api_keys import router as api_keys_router
from auth_service.api.routes.tenants import router as tenants_router
from auth_service.api.routes.admin import router as admin_router
from auth_service.api.routes.health import router as health_router
from auth_service.api.routes.mfa import router as mfa_router
from auth_service.api.routes.sessions import router as sessions_router
from auth_service.api.routes.webhooks import router as webhooks_router
from auth_service.api.routes.well_known import router as well_known_router
from auth_service.api.routes.introspection import router as introspection_router
from auth_service.api.routes.metrics import router as metrics_router
from auth_service.api.routes.compliance import router as compliance_router


OPENAPI_TAGS = [
    {"name": "Authentication", "description": "User registration, password login, token rotation, verification, and logout"},
    {"name": "OAuth & Social Sign-In", "description": "Federated Google & GitHub OAuth2 social logins"},
    {"name": "User Profiles", "description": "Authenticated self-service profile and credential updates"},
    {"name": "Roles & RBAC", "description": "Role-Based Access Control and permission policy management"},
    {"name": "Permissions", "description": "Granular capability discovery and registration"},
    {"name": "API Keys", "description": "Machine-to-Machine credential provisioning and scopes"},
    {"name": "Tenants & Multi-Tenancy", "description": "Organization boundaries and domain isolation"},
    {"name": "Administration & Telemetry", "description": "Administrative user controls, audit log search, and metrics"},
    {"name": "Health & Diagnostics", "description": "Kubernetes liveness, readiness, and performance probes"},
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle event manager orchestrating startup and graceful shutdown."""
    logger.info("Initializing Auth-as-a-Service runtime...")
    # Initialize database schemas and baseline seeds
    await init_db()
    logger.info("AaaS core subsystems ready.")
    yield
    logger.info("Shutting down Auth-as-a-Service...")
    await close_db()
    await close_redis_client()
    logger.info("AaaS cleanup completed.")


def create_app() -> FastAPI:
    """Application factory constructing the configured FastAPI instance."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Enterprise-grade, self-hosted, multi-tenant authentication and authorization platform. "
            "Delivers JWT sessions, OAuth2 social identity, RBAC, API keys, and immutable audit logs."
        ),
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # 1. Register Core Middleware (Executed bottom-to-top)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggerMiddleware)
    app.add_middleware(TenantResolutionMiddleware)
    app.add_middleware(RequestIdMiddleware)

    # 2. Register Global Exception Handlers
    @app.exception_handler(AaaSException)
    async def aaas_exception_handler(request: Request, exc: AaaSException):
        http_exc = to_http_exception(exc)
        return JSONResponse(
            status_code=http_exc.status_code,
            content=http_exc.detail,
            headers=getattr(http_exc, "headers", None),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        detail = exc.detail
        if isinstance(detail, str):
            detail = {"error": "HTTP_ERROR", "message": detail}
        return JSONResponse(
            status_code=exc.status_code,
            content=detail,
            headers=exc.headers,
        )

    # 3. Mount Routers
    api_prefix = settings.API_PREFIX

    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(oauth_router, prefix=api_prefix)
    app.include_router(users_router, prefix=api_prefix)
    app.include_router(roles_router, prefix=api_prefix)
    app.include_router(permissions_router, prefix=api_prefix)
    app.include_router(api_keys_router, prefix=api_prefix)
    app.include_router(tenants_router, prefix=api_prefix)
    app.include_router(admin_router, prefix=api_prefix)
    app.include_router(mfa_router, prefix=api_prefix)
    app.include_router(sessions_router, prefix=api_prefix)
    app.include_router(webhooks_router, prefix=api_prefix)
    app.include_router(introspection_router, prefix=api_prefix)
    app.include_router(compliance_router, prefix=api_prefix)
    app.include_router(well_known_router, prefix="")
    app.include_router(metrics_router, prefix="")

    # Health router accessible at both /health and /api/v1/health
    app.include_router(health_router, prefix="")
    app.include_router(health_router, prefix=api_prefix)

    @app.get("/", include_in_schema=False)
    async def root(request: Request):
        accept = request.headers.get("accept", "")
        if "text/html" in accept or "*/*" in accept:
            return HTMLResponse(content=LANDING_PAGE_HTML)
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "online",
            "docs": "/docs",
            "redoc": "/redoc",
            "health": "/health",
            "openid_configuration": "/.well-known/openid-configuration",
            "jwks": "/.well-known/jwks.json",
        }

    return app


app = create_app()
