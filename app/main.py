from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.database import get_pool, close_pool
from app.routers import admin, driver, tms

@asynccontextmanager
async def lifespan(app: FastAPI):
    await get_pool()
    yield
    await close_pool()

app = FastAPI(
    title="RutaIQ API",
    version="0.1.0",
    lifespan=lifespan,
)

@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    """CORS: wildcard — Railway Hikari proxy modifica el header Origin."""
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Access-Control-Max-Age": "3600",
            },
        )
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

app.include_router(admin.router)
app.include_router(driver.router)
app.include_router(tms.router)

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
