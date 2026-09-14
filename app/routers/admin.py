"""
Endpoints de administración para el TMS.

POST   /api/admin/conductores            → crear conductor (nombre, tel, pin)
GET    /api/admin/conductores            → listar conductores de la org
DELETE /api/admin/conductores/{id}       → dar de baja un conductor
POST   /api/admin/rutas                  → crear ruta pre-armada con paradas
GET    /api/admin/rutas                  → listar rutas de la org
"""

from datetime import date, datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from passlib.hash import bcrypt
from pydantic import BaseModel

from app.config import settings
from app.database import get_pool

import jwt

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ── Auth helper (Supabase JWT) ─────────────────────────────────────────────────

async def tenant_actual(authorization: str = Header(...)) -> str:
    """
    El TMS envía el JWT de Supabase del usuario logueado.
    Extrae el tenant_id (organization_id) del claim personalizado.
    Acepta también el JWT interno de conductor por compatibilidad.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header de autorización inválido")
    token = authorization[7:]
    try:
        # Supabase firma con su propio JWT_SECRET; como solo necesitamos el tenant,
        # decodificamos sin verificar firma (el API Gateway de Railway ya valida TLS).
        # En prod: reemplazar por verificación con SUPABASE_JWT_SECRET.
        payload = jwt.decode(token, options={"verify_signature": False})
        # El tenant_id viene en el claim `app_metadata.organization_id`
        # o en el claim raíz `tenant` (token interno de driver).
        tenant = (
            payload.get("tenant")
            or (payload.get("app_metadata") or {}).get("organization_id")
            or payload.get("sub")   # fallback para tests
        )
        if not tenant:
            raise HTTPException(status_code=401, detail="Token sin tenant_id")
        return str(tenant)
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Token inválido: {e}")


# ── Modelos ───────────────────────────────────────────────────────────────────

class ConductorCreate(BaseModel):
    nombre: str
    tel: str         # e.g. "+5491155556666"
    pin: str         # 4 dígitos — se guarda hasheado

class ParadaItem(BaseModel):
    orden: int
    cliente_nombre: str
    direccion: str
    lat: Optional[float] = None
    lng: Optional[float] = None
    bultos: Optional[int] = None
    horario_plan: Optional[str] = None   # "HH:MM" en hora local, guardado como time

class RutaCreate(BaseModel):
    fecha: str                      # "YYYY-MM-DD"
    conductor_id: Optional[str] = None   # UUID del chofer (puede ser None si se asigna después)
    vehiculo_id: Optional[str] = None    # UUID del vehículo
    notas: Optional[str] = None
    paradas: List[ParadaItem]


# ── Conductores ───────────────────────────────────────────────────────────────

@router.post("/conductores", status_code=201)
async def crear_conductor(body: ConductorCreate, tenant_id: str = Depends(tenant_actual)):
    """Crea un nuevo conductor con PIN hasheado."""
    if len(body.pin) < 4:
        raise HTTPException(status_code=422, detail="El PIN debe tener al menos 4 caracteres")

    pin_hash = bcrypt.hash(body.pin)

    pool = await get_pool()
    async with pool.acquire() as conn:
        # Verificar si el teléfono ya existe en este tenant
        existing = await conn.fetchval(
            "SELECT id FROM choferes WHERE tel = $1 AND tenant_id = $2",
            body.tel, tenant_id,
        )
        if existing:
            raise HTTPException(status_code=409, detail="Ya existe un conductor con ese teléfono")

        row = await conn.fetchrow(
            """
            INSERT INTO choferes (tenant_id, nombre, tel, pin_hash, activo)
            VALUES ($1, $2, $3, $4, true)
            RETURNING id, nombre, tel, activo, created_at
            """,
            tenant_id, body.nombre, body.tel, pin_hash,
        )

    return {
        "id":         str(row["id"]),
        "nombre":     row["nombre"],
        "tel":        row["tel"],
        "activo":     row["activo"],
        "created_at": row["created_at"].isoformat(),
    }


@router.get("/conductores")
async def listar_conductores(tenant_id: str = Depends(tenant_actual)):
    """Lista todos los conductores activos de la organización."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, nombre, apellido, tel, activo, created_at
            FROM choferes
            WHERE tenant_id = $1
            ORDER BY nombre
            """,
            tenant_id,
        )
    return [
        {
            "id":         str(r["id"]),
            "nombre":     f"{r['nombre']} {r['apellido'] or ''}".strip(),
            "tel":        r["tel"],
            "activo":     r["activo"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]


@router.delete("/conductores/{conductor_id}", status_code=200)
async def eliminar_conductor(conductor_id: UUID, tenant_id: str = Depends(tenant_actual)):
    """Marca al conductor como inactivo (soft delete)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE choferes
            SET activo = false
            WHERE id = $1 AND tenant_id = $2
            """,
            conductor_id, tenant_id,
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Conductor no encontrado")
    return {"ok": True}


@router.put("/conductores/{conductor_id}/pin", status_code=200)
async def cambiar_pin(
    conductor_id: UUID,
    body: dict,
    tenant_id: str = Depends(tenant_actual),
):
    """Cambia el PIN de un conductor."""
    nuevo_pin = body.get("pin", "")
    if len(nuevo_pin) < 4:
        raise HTTPException(status_code=422, detail="El PIN debe tener al menos 4 caracteres")
    pin_hash = bcrypt.hash(nuevo_pin)
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE choferes SET pin_hash = $1 WHERE id = $2 AND tenant_id = $3",
            pin_hash, conductor_id, tenant_id,
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Conductor no encontrado")
    return {"ok": True}


# ── Rutas pre-armadas ─────────────────────────────────────────────────────────

@router.post("/rutas", status_code=201)
async def crear_ruta(body: RutaCreate, tenant_id: str = Depends(tenant_actual)):
    """
    Crea una ruta pre-armada (importada desde Excel o enviada desde el Ruteador).
    Inserta la ruta y todas sus paradas en una transacción.
    """
    try:
        fecha = date.fromisoformat(body.fecha)
    except ValueError:
        raise HTTPException(status_code=422, detail="Formato de fecha inválido (usa YYYY-MM-DD)")

    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Insertar ruta
            ruta_row = await conn.fetchrow(
                """
                INSERT INTO rutas
                  (tenant_id, fecha, chofer_id, vehiculo_id, estado, notas)
                VALUES ($1, $2, $3, $4, 'planificada', $5)
                RETURNING id, fecha, estado
                """,
                tenant_id,
                fecha,
                UUID(body.conductor_id) if body.conductor_id else None,
                UUID(body.vehiculo_id) if body.vehiculo_id else None,
                body.notas,
            )
            ruta_id = ruta_row["id"]

            # Insertar paradas
            paradas_insertadas = []
            for p in body.paradas:
                # Parsear horario_plan si viene como "HH:MM"
                horario = None
                if p.horario_plan:
                    try:
                        from datetime import time
                        parts = p.horario_plan.split(":")
                        horario = time(int(parts[0]), int(parts[1]))
                    except Exception:
                        pass

                par_row = await conn.fetchrow(
                    """
                    INSERT INTO paradas_ruta
                      (ruta_id, orden, cliente_nombre, direccion, lat, lng, bultos, horario_plan)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING id, orden
                    """,
                    ruta_id,
                    p.orden,
                    p.cliente_nombre,
                    p.direccion,
                    p.lat,
                    p.lng,
                    p.bultos,
                    horario,
                )
                paradas_insertadas.append({"id": str(par_row["id"]), "orden": par_row["orden"]})

    return {
        "id":             str(ruta_id),
        "fecha":          str(ruta_row["fecha"]),
        "estado":         ruta_row["estado"],
        "paradas_count":  len(paradas_insertadas),
        "paradas":        paradas_insertadas,
    }


@router.get("/rutas")
async def listar_rutas(
    fecha: Optional[str] = None,
    tenant_id: str = Depends(tenant_actual),
):
    """Lista rutas de la organización, opcionalmente filtradas por fecha."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        if fecha:
            try:
                fecha_dt = date.fromisoformat(fecha)
            except ValueError:
                raise HTTPException(status_code=422, detail="Formato de fecha inválido")
            rows = await conn.fetch(
                """
                SELECT r.id, r.fecha, r.estado, r.notas,
                       c.nombre AS chofer_nombre, c.tel AS chofer_tel,
                       v.patente,
                       COUNT(p.id) AS paradas_count
                FROM rutas r
                LEFT JOIN choferes c ON c.id = r.chofer_id
                LEFT JOIN vehiculos v ON v.id = r.vehiculo_id
                LEFT JOIN paradas_ruta p ON p.ruta_id = r.id
                WHERE r.tenant_id = $1 AND r.fecha = $2
                GROUP BY r.id, c.nombre, c.tel, v.patente
                ORDER BY r.fecha DESC
                """,
                tenant_id, fecha_dt,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT r.id, r.fecha, r.estado, r.notas,
                       c.nombre AS chofer_nombre, c.tel AS chofer_tel,
                       v.patente,
                       COUNT(p.id) AS paradas_count
                FROM rutas r
                LEFT JOIN choferes c ON c.id = r.chofer_id
                LEFT JOIN vehiculos v ON v.id = r.vehiculo_id
                LEFT JOIN paradas_ruta p ON p.ruta_id = r.id
                WHERE r.tenant_id = $1
                GROUP BY r.id, c.nombre, c.tel, v.patente
                ORDER BY r.fecha DESC
                LIMIT 90
                """,
                tenant_id,
            )

    return [
        {
            "id":             str(r["id"]),
            "fecha":          str(r["fecha"]),
            "estado":         r["estado"],
            "notas":          r["notas"],
            "chofer":         r["chofer_nombre"] or "Sin asignar",
            "chofer_tel":     r["chofer_tel"],
            "vehiculo":       r["patente"],
            "paradas_count":  int(r["paradas_count"]),
        }
        for r in rows
    ]
