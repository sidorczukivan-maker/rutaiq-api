from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import get_pool, close_pool
from app.routers import admin, driver, tms


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: inicializar pool de conexiones
    await get_pool()
    yield
    # Shutdown: cerrar pool
    await close_pool()


app = FastAPI(
    title="RutaIQ API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin.router)
app.include_router(driver.router)
app.include_router(tms.router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
