"""
Endpoints para el TMS web (operadores y administradores).

POST /api/tms/login                  -> login con email + password
GET  /api/tms/routes                 -> listar rutas (filtros: fecha, estado)
GET  /api/tms/routes/{id}            -> detalle de ruta con paradas y eventos
POST /api/tms/routes                 -> crear ruta
PATCH /api/tms/routes/{id}/status    -> cambiar estado de ruta
GET  /api/tms/tracking               -> ultima posicion de choferes activos
GET  /api/tms/drivers                -> listar choferes de la org
POST /api/tms/drivers                -> crear chofer
GET  /api/tms/clients                -> listar clientes
POST /api/tms/clients                -> crear cliente
GET  /api/tms/orders                 -> listar pedidos
POST /api/tms/orders                 -> crear pedido
"""

from datetime import datetime, timedelta, timezone, date
from typing import Optional
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, HTTPException, Header
from passlib.context import CryptContext
from pydantic import BaseModel

from app.config import settings
from app.database import get_pool

router = APIRouter(prefix="/api/tms", tags=["tms"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# -- Modelos --

class TmsLoginRequest(BaseModel):
    email: str
    password: str
    org_slug: str

class RouteCreateRequest(BaseModel):
    fecha: date
    chofer_id: str
    vehiculo_id: Optional[str] = None
    cd_id: Optional[str] = None
    salida_plan: Optional[datetime] = None
    paradas: list[dict]

class RouteStatusRequest(BaseModel):
    estado: str

class DriverCreateRequest(BaseModel):
    codigo: str
    nombre: str
    apellido: str
    licencia: Optional[str] = None
    tel: Optional[str] = None

class ClientUpsertRequest(BaseModel):
    nombre: str
    razon_social: Optional[str] = None
    direccion: str
    lat: float
    lng: float
    contacto_nombre: Optional[str] = None
    contacto_tel: Optional[str] = None
    notas_entrega: Optional[str] = None
    ventana_desde: Optional[str] = None
    ventana_hasta: Optional[str] = None
    tiempo_servicio: Optional[int] = None

class OrderCreateRequest(BaseModel):
    cliente_id: str
    referencia: Optional[str] = None
    bultos: int = 1
    peso_kg: Optional[float] = None
    notas: Optional[str] = None


# -- Auth helpers --

def create_tms_token(usuario_id: str, org_id: str, rol: str) -> str:
    payload = {
        "sub": usuario_id,
        "org": org_id,
        "rol": rol,
        "tipo": "tms",
        "exp": datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_tms_token(token: str) -> dict:
    try:
        data = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if data.get("tipo") != "tms":
            raise HTTPException(status_code=401, detail="Token invalido para TMS")
        return data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalido")

async def get_current_operator(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Header de autorizacion invalido")
    return decode_tms_token(authorization[7:])


# -- Endpoints --

@router.post("/login")
async def tms_login(body: TmsLoginRequest):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT u.id, u.org_id, u.nombre, u.apellido, u.password_hash, u.rol, u.estado
            FROM usuarios u
            JOIN organizaciones o ON o.id = u.org_id
            WHERE u.email = $1
              AND o.slug  = $2
              AND o.activo = true
            """,
            body.email, body.org_slug
        )

    if not row:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    if row["estado"] != "activo":
        raise HTTPException(status_code=403, detail="Usuario inactivo")
    if not pwd_context.verify(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    token = create_tms_token(str(row["id"]), str(row["org_id"]), row["rol"])
    return {
        "token": token,
        "usuario": {
            "id": str(row["id"]),
            "nombre": row["nombre"],
            "apellido": row["apellido"],
            "rol": row["rol"],
        }
    }


@router.get("/routes")
async def list_routes(
    fecha: Optional[date] = None,
    estado: Optional[str] = None,
    operator=Depends(get_current_operator),
):
    org_id = operator["org"]
    fecha = fecha or datetime.now(timezone.utc).date()

    pool = await get_pool()
    async with pool.acquire() as conn:
        query = """
            SELECT
                r.id, r.fecha, r.estado, r.salida_plan, r.salida_real,
                ch.nombre || ' ' || ch.apellido AS chofer_nombre,
                ch.codigo AS chofer_codigo,
                v.patente, v.tipo AS vehiculo_tipo,
                cd.nombre AS cd_nombre,
                COUNT(pa.id) AS total_paradas,
                COUNT(pa.id) FILTER (WHERE pa.estado = 'entregado')    AS entregadas,
                COUNT(pa.id) FILTER (WHERE pa.estado = 'reprogramado') AS reprogramadas
            FROM rutas r
            JOIN choferes ch ON ch.id = r.chofer_id
            LEFT JOIN vehiculos v ON v.id = r.vehiculo_id
            LEFT JOIN centros_distribucion cd ON cd.id = r.cd_id
            LEFT JOIN paradas pa ON pa.ruta_id = r.id
            WHERE r.org_id = $1
              AND r.fecha  = $2
        """
        params = [org_id, fecha]

        if estado:
            query += " AND r.estado = $3"
            params.append(estado)

        query += " GROUP BY r.id, ch.nombre, ch.apellido, ch.codigo, v.patente, v.tipo, cd.nombre ORDER BY r.created_at DESC"

        rows = await conn.fetch(query, *params)

    return [
        {
            "id": str(r["id"]),
            "fecha": str(r["fecha"]),
            "estado": r["estado"],
            "salida_plan": r["salida_plan"].isoformat() if r["salida_plan"] else None,
            "salida_real": r["salida_real"].isoformat() if r["salida_real"] else None,
            "chofer": r["chofer_nombre"],
            "chofer_codigo": r["chofer_codigo"],
            "vehiculo": f"{r['vehiculo_tipo']} {r['patente']}" if r["patente"] else None,
            "cd_nombre": r["cd_nombre"],
            "total_paradas": r["total_paradas"],
            "entregadas": r["entregadas"],
            "reprogramadas": r["reprogramadas"],
        }
        for r in rows
    ]


@router.get("/routes/{route_id}")
async def get_route(route_id: UUID, operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        ruta = await conn.fetchrow(
            """
            SELECT r.id, r.fecha, r.estado, r.salida_plan, r.salida_real,
                   ch.id AS chofer_id, ch.nombre || ' ' || ch.apellido AS chofer_nombre,
                   v.patente, v.tipo AS vehiculo_tipo,
                   cd.nombre AS cd_nombre, cd.direccion AS cd_direccion
            FROM rutas r
            JOIN choferes ch ON ch.id = r.chofer_id
            LEFT JOIN vehiculos v ON v.id = r.vehiculo_id
            LEFT JOIN centros_distribucion cd ON cd.id = r.cd_id
            WHERE r.id = $1 AND r.org_id = $2
            """,
            route_id, org_id
        )
        if not ruta:
            raise HTTPException(status_code=404, detail="Ruta no encontrada")

        paradas = await conn.fetch(
            """
            SELECT
                pa.id, pa.secuencia, pa.estado, pa.llegada_plan, pa.llegada_real,
                pa.salida_real, pa.motivo_reprog,
                pe.id AS pedido_id, pe.referencia, pe.bultos, pe.peso_kg, pe.notas AS pedido_notas,
                cl.nombre AS cliente_nombre, cl.razon_social, cl.direccion AS cliente_direccion,
                cl.contacto_nombre, cl.contacto_tel, cl.notas_entrega,
                cl.ventana_desde, cl.ventana_hasta
            FROM paradas pa
            JOIN pedidos pe  ON pe.id = pa.pedido_id
            JOIN clientes cl ON cl.id = pe.cliente_id
            WHERE pa.ruta_id = $1
            ORDER BY pa.secuencia
            """,
            route_id
        )

    return {
        "ruta": {
            "id": str(ruta["id"]),
            "fecha": str(ruta["fecha"]),
            "estado": ruta["estado"],
            "chofer_id": str(ruta["chofer_id"]),
            "chofer": ruta["chofer_nombre"],
            "vehiculo": f"{ruta['vehiculo_tipo']} {ruta['patente']}" if ruta["patente"] else None,
            "cd_nombre": ruta["cd_nombre"],
        },
        "paradas": [
            {
                "id": str(p["id"]),
                "secuencia": p["secuencia"],
                "estado": p["estado"],
                "llegada_plan": p["llegada_plan"].isoformat() if p["llegada_plan"] else None,
                "llegada_real": p["llegada_real"].isoformat() if p["llegada_real"] else None,
                "pedido": {
                    "id": str(p["pedido_id"]),
                    "referencia": p["referencia"],
                    "bultos": p["bultos"],
                },
                "cliente": {
                    "nombre": p["cliente_nombre"],
                    "direccion": p["cliente_direccion"],
                    "contacto_tel": p["contacto_tel"],
                    "notas_entrega": p["notas_entrega"],
                },
            }
            for p in paradas
        ],
    }


@router.post("/routes", status_code=201)
async def create_route(body: RouteCreateRequest, operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            ruta = await conn.fetchrow(
                """
                INSERT INTO rutas (org_id, fecha, chofer_id, vehiculo_id, cd_id, salida_plan, estado)
                VALUES ($1, $2, $3, $4, $5, $6, 'confirmada')
                RETURNING id
                """,
                org_id, body.fecha, body.chofer_id, body.vehiculo_id, body.cd_id, body.salida_plan,
            )
            ruta_id = ruta["id"]

            for p in body.paradas:
                await conn.execute(
                    """
                    INSERT INTO paradas (ruta_id, pedido_id, secuencia, llegada_plan, estado)
                    VALUES ($1, $2, $3, $4, 'pendiente')
                    """,
                    ruta_id, p["pedido_id"], p["secuencia"], p.get("llegada_plan"),
                )

    return {"id": str(ruta_id), "estado": "confirmada"}


@router.patch("/routes/{route_id}/status")
async def update_route_status(
    route_id: UUID,
    body: RouteStatusRequest,
    operator=Depends(get_current_operator),
):
    ESTADOS_VALIDOS = {"confirmada", "en_curso", "completada", "cancelada"}
    if body.estado not in ESTADOS_VALIDOS:
        raise HTTPException(status_code=422, detail=f"estado debe ser uno de: {ESTADOS_VALIDOS}")

    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        campos_extra = ""
        if body.estado == "en_curso":
            campos_extra = ", salida_real = now()"
        elif body.estado == "completada":
            campos_extra = ", fin_real = now()"

        result = await conn.execute(
            f"UPDATE rutas SET estado = $1{campos_extra} WHERE id = $2 AND org_id = $3",
            body.estado, route_id, org_id
        )

    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Ruta no encontrada")

    return {"ok": True, "estado": body.estado}


@router.get("/tracking")
async def get_tracking(operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                g.chofer_id,
                c.nombre || ' ' || c.apellido AS chofer_nombre,
                c.tel,
                g.ruta_id,
                r.estado AS ruta_estado,
                g.lat,
                g.lng,
                g.velocidad_kmh,
                g.timestamp AS ultimo_ping
            FROM gps_choferes g
            JOIN choferes c ON c.id = g.chofer_id
            JOIN rutas r ON r.id = g.ruta_id
            WHERE c.tenant_id = $1
              AND r.fecha = CURRENT_DATE
              AND r.estado IN ('planificada', 'en_curso')
              AND g.timestamp = (
                  SELECT MAX(g2.timestamp) FROM gps_choferes g2 WHERE g2.chofer_id = g.chofer_id
              )
            """,
            org_id
        )

    return [
        {
            "chofer_id": str(r["chofer_id"]),
            "chofer": r["chofer_nombre"],
            "ruta_id": str(r["ruta_id"]),
            "ruta_estado": r["ruta_estado"],
            "lat": r["lat"],
            "lng": r["lng"],
            "velocidad_kmh": r["velocidad_kmh"],
            "ultimo_ping": r["ultimo_ping"].isoformat() if r["ultimo_ping"] else None,
        }
        for r in rows
    ]


@router.get("/drivers")
async def list_drivers(operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, nombre, apellido, licencia, tel, activo FROM choferes WHERE tenant_id = $1 ORDER BY apellido, nombre",
            org_id
        )
    return [
        {"id": str(r["id"]), "nombre": r["nombre"], "apellido": r["apellido"],
         "licencia": r["licencia"], "tel": r["tel"], "activo": r["activo"]}
        for r in rows
    ]


@router.post("/drivers", status_code=201)
async def create_driver(body: DriverCreateRequest, operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO choferes (tenant_id, nombre, apellido, licencia, tel) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            org_id, body.nombre, body.apellido, body.licencia, body.tel
        )
    return {"id": str(row["id"])}


@router.get("/clients")
async def list_clients(q: Optional[str] = None, operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        if q:
            rows = await conn.fetch(
                "SELECT id, nombre, razon_social, direccion, lat, lng, contacto_nombre, contacto_tel, notas_entrega FROM clientes WHERE tenant_id = $1 AND (nombre ILIKE $2 OR direccion ILIKE $2) ORDER BY nombre LIMIT 100",
                org_id, f"%{q}%"
            )
        else:
            rows = await conn.fetch(
                "SELECT id, nombre, razon_social, direccion, lat, lng, contacto_nombre, contacto_tel, notas_entrega FROM clientes WHERE tenant_id = $1 ORDER BY nombre LIMIT 500",
                org_id
            )
    return [
        {"id": str(r["id"]), "nombre": r["nombre"], "razon_social": r["razon_social"],
         "direccion": r["direccion"], "lat": r["lat"], "lng": r["lng"],
         "contacto_nombre": r["contacto_nombre"], "contacto_tel": r["contacto_tel"],
         "notas_entrega": r["notas_entrega"]}
        for r in rows
    ]


@router.post("/clients", status_code=201)
async def create_client(body: ClientUpsertRequest, operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO clientes (tenant_id, nombre, razon_social, direccion, lat, lng,
                contacto_nombre, contacto_tel, notas_entrega, ventana_desde, ventana_hasta, tiempo_servicio)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id
            """,
            org_id, body.nombre, body.razon_social, body.direccion, body.lat, body.lng,
            body.contacto_nombre, body.contacto_tel, body.notas_entrega,
            body.ventana_desde, body.ventana_hasta, body.tiempo_servicio
        )
    return {"id": str(row["id"])}


@router.get("/orders")
async def list_orders(sin_asignar: bool = False, operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, referencia, bultos, peso_kg, notas, estado, created_at FROM pedidos WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200",
            org_id
        )
    return [
        {"id": str(r["id"]), "referencia": r["referencia"], "bultos": r["bultos"],
         "peso_kg": float(r["peso_kg"]) if r["peso_kg"] else None,
         "notas": r["notas"], "estado": r["estado"],
         "created_at": r["created_at"].isoformat()}
        for r in rows
    ]


@router.post("/orders", status_code=201)
async def create_order(body: OrderCreateRequest, operator=Depends(get_current_operator)):
    org_id = operator["org"]
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO pedidos (tenant_id, cliente_id, referencia, bultos, peso_kg, notas) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            org_id, body.cliente_id, body.referencia, body.bultos, body.peso_kg, body.notas
        )
    return {"id": str(row["id"])}
