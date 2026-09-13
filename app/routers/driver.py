"""
Endpoints para la app movil del chofer.

POST /api/driver/login            -> login con tel + pin
GET  /api/driver/ruta/hoy         -> ruta del dia con paradas
POST /api/driver/paradas/{id}/evento -> reportar entrega/falla/foto
POST /api/driver/gps              -> ping de posicion (cada ~60s)
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

from app.config import settings
from app.database import get_pool

router = APIRouter(prefix="/api/driver", tags=["driver"])


# -- Modelos --

class LoginRequest(BaseModel):
    tel: str
    pin: str

class EventoRequest(BaseModel):
    tipo: str
    lat: Optional[float] = None
    lng: Optional[float] = None
    foto_url: Optional[str] = None
    motivo: Optional[str] = None
    bultos_real: Optional[int] = None

class GpsRequest(BaseModel):
    ruta_id: Optional[str] = None
    lat: float
    lng: float
    precision_m: Optional[float] = None
    velocidad_kmh: Optional[float] = None
    heading: Optional[float] = None


# -- Auth helpers --

def crear_token(chofer_id: str, tenant_id: str) -> str:
    payload = {
        "sub":    chofer_id,
        "tenant": tenant_id,
        "exp":    datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decodificar_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalido")

async def chofer_actual(authorization: str = Header(...)) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header de autorizacion invalido")
    return decodificar_token(authorization[7:])


# -- Endpoints --

@router.post("/login")
async def login(body: LoginRequest):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, tenant_id, nombre, apellido, pin_hash, activo
            FROM choferes
            WHERE tel = $1
            LIMIT 1
            """,
            body.tel,
        )

    if not row:
        raise HTTPException(status_code=401, detail="Telefono o PIN incorrectos")

    if not row["activo"]:
        raise HTTPException(status_code=403, detail="Chofer inactivo")

    from passlib.hash import bcrypt
    if not bcrypt.verify(body.pin, row["pin_hash"]):
        raise HTTPException(status_code=401, detail="Telefono o PIN incorrectos")

    token = crear_token(str(row["id"]), str(row["tenant_id"]))
    return {
        "token": token,
        "chofer": {
            "id":       str(row["id"]),
            "nombre":   row["nombre"],
            "apellido": row["apellido"] or "",
        },
    }


@router.get("/ruta/hoy")
async def ruta_hoy(driver: dict = Depends(chofer_actual)):
    chofer_id = driver["sub"]
    hoy = datetime.now(timezone.utc).date()

    pool = await get_pool()
    async with pool.acquire() as conn:
        ruta = await conn.fetchrow(
            """
            SELECT r.id, r.fecha, r.estado, r.salida_plan, r.salida_real, r.notas,
                   v.patente, v.descripcion AS vehiculo_desc
            FROM rutas r
            LEFT JOIN vehiculos v ON v.id = r.vehiculo_id
            WHERE r.chofer_id = $1
              AND r.fecha      = $2
              AND r.estado NOT IN ('cancelada')
            ORDER BY r.created_at DESC
            LIMIT 1
            """,
            chofer_id, hoy,
        )

        if not ruta:
            raise HTTPException(status_code=404, detail="No tenes ruta asignada para hoy")

        paradas = await conn.fetch(
            """
            SELECT id, orden, cliente_nombre, direccion, lat, lng,
                   horario_plan, bultos, notas
            FROM paradas_ruta
            WHERE ruta_id = $1
            ORDER BY orden
            """,
            ruta["id"],
        )

        parada_ids = [str(p["id"]) for p in paradas]
        eventos = {}
        if parada_ids:
            rows = await conn.fetch(
                """
                SELECT DISTINCT ON (parada_id)
                    parada_id, tipo, timestamp, motivo, bultos_real
                FROM eventos_paradas
                WHERE parada_id = ANY($1::uuid[])
                ORDER BY parada_id, timestamp DESC
                """,
                [UUID(pid) for pid in parada_ids],
            )
            for ev in rows:
                eventos[str(ev["parada_id"])] = {
                    "tipo":        ev["tipo"],
                    "timestamp":   ev["timestamp"].isoformat(),
                    "motivo":      ev["motivo"],
                    "bultos_real": ev["bultos_real"],
                }

    return {
        "ruta": {
            "id":          str(ruta["id"]),
            "fecha":       str(ruta["fecha"]),
            "estado":      ruta["estado"],
            "salida_plan": str(ruta["salida_plan"]) if ruta["salida_plan"] else None,
            "salida_real": ruta["salida_real"].isoformat() if ruta["salida_real"] else None,
            "vehiculo":    f"{ruta['vehiculo_desc']} ({ruta['patente']})" if ruta["patente"] else None,
            "notas":       ruta["notas"],
        },
        "paradas": [
            {
                "id":             str(p["id"]),
                "orden":          p["orden"],
                "cliente_nombre": p["cliente_nombre"],
                "direccion":      p["direccion"],
                "lat":            p["lat"],
                "lng":            p["lng"],
                "horario_plan":   p["horario_plan"].isoformat() if p["horario_plan"] else None,
                "bultos":         p["bultos"],
                "notas":          p["notas"],
                "ultimo_evento":  eventos.get(str(p["id"])),
            }
            for p in paradas
        ],
    }


@router.post("/paradas/{parada_id}/evento")
async def registrar_evento(
    parada_id: UUID,
    body: EventoRequest,
    driver: dict = Depends(chofer_actual),
):
    TIPOS_VALIDOS = {"entregado", "fallido", "parcial", "foto", "comentario", "reagendado"}
    if body.tipo not in TIPOS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"tipo debe ser uno de: {TIPOS_VALIDOS}")

    if body.tipo in ("fallido", "reagendado") and not body.motivo:
        raise HTTPException(status_code=422, detail="motivo es requerido para fallido/reagendado")

    chofer_id = driver["sub"]

    pool = await get_pool()
    async with pool.acquire() as conn:
        ok = await conn.fetchval(
            """
            SELECT 1
            FROM paradas_ruta pr
            JOIN rutas r ON r.id = pr.ruta_id
            WHERE pr.id = $1 AND r.chofer_id = $2
            """,
            parada_id, chofer_id,
        )
        if not ok:
            raise HTTPException(status_code=404, detail="Parada no encontrada")

        await conn.execute(
            """
            INSERT INTO eventos_paradas
              (parada_id, tipo, lat, lng, foto_url, motivo, bultos_real)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            parada_id,
            body.tipo,
            body.lat,
            body.lng,
            body.foto_url,
            body.motivo,
            body.bultos_real,
        )

    return {"ok": True}


@router.post("/gps")
async def ping_gps(body: GpsRequest, driver: dict = Depends(chofer_actual)):
    chofer_id = driver["sub"]

    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO gps_choferes
              (chofer_id, ruta_id, lat, lng, precision_m, velocidad_kmh, heading)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            chofer_id,
            UUID(body.ruta_id) if body.ruta_id else None,
            body.lat,
            body.lng,
            body.precision_m,
            body.velocidad_kmh,
            body.heading,
        )

    return {"ok": True}
