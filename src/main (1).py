import asyncio
import json
import os
import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
try:
    import psutil
except Exception:
    psutil = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Gateway")

app = FastAPI(title="CORE", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", "default-secret-key"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "app_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"CORE started on port {CONFIG['port']}")

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", os.environ.get("APP_DOMAIN", "aether-shah1398000-bit.wasmer.app"))).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "CORE", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    """Turn a number of days into an absolute ISO expiry timestamp. 0/empty = no expiry."""
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    """True if the link has an expiry date that is in the past."""
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False

def expiry_epoch(link) -> int:
    """Expiry as a unix timestamp for the subscription-userinfo header (0 = never)."""
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except (TypeError, ValueError):
        return 0

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["Default"] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""}

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

@app.get("/")
async def root():
    return {"service": "CORE", "version": "1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": (psutil.cpu_percent(interval=0.1) if psutil else 0),
        "memory_percent": (psutil.virtual_memory().percent if psutil else 0),
        "hourly_traffic": dict(hourly_traffic),
    }


@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    expiry = compute_expiry(body.get("expiry_days"))
    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "created_at": datetime.now().isoformat(), "active": True, "expiry": expiry}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "active": True, "expiry": expiry, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"CORE-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": data["used_bytes"], "max_connections": data.get("max_connections", 0), "active": data["active"], "expiry": data.get("expiry", ""), "expired": is_expired(data), "created_at": data["created_at"], "current_connections": count_connections_for_link(uid), "vless_link": generate_vless_link(uid, remark=f"CORE-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}


@app.get("/api/domain")
async def get_custom_domain(_=Depends(require_auth)):
    async with CUSTOM_DOMAIN_LOCK:
        return {"domain": CUSTOM_DOMAIN}


@app.post("/api/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    if domain:
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    async with CUSTOM_DOMAIN_LOCK:
        global CUSTOM_DOMAIN
        CUSTOM_DOMAIN = domain
    return {"ok": True, "domain": CUSTOM_DOMAIN}


@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}


@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Address must contain only English letters, numbers, and characters: - _ .")
    async with CUSTOM_ADDRESSES_LOCK:
        if address in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(address)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}


@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(uid, remark=f"CORE-{link['label']}")
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    import base64
    sub_content = f"""# Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: {link.get('expiry', '')[:10] if link.get('expiry') else 'Unlimited'}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
    }


@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    if is_expired(link):
        raise HTTPException(status_code=403, detail="link expired")
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"CORE-{link['label']}-Server")
    sub_links.append(server_link)
    for i, addr in enumerate(addresses):
        remark = f"CORE-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}"
    }
    return Response(content=encoded, headers=headers)

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if is_expired(link): return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            if is_expired(link_data):
                await websocket.close(code=1008, reason="link expired"); return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)


PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark" data-design="aurum">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gateway</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Vazirmatn:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}

/* ===================== DESIGN TOKENS ===================== */
:root{--font:'Inter','Vazirmatn',-apple-system,BlinkMacSystemFont,sans-serif;--font-head:'Inter','Vazirmatn',sans-serif;--font-mono:'JetBrains Mono',monospace;--sb-w:232px}

/* ---- CORE CLASSIC (signature crimson) ---- */
html[data-design="core"][data-theme="dark"]{--bg:#0a0808;--bg2:#120a0b;--surface:#161213;--surface2:#1d1719;--surface3:#2a2124;--border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.16);--text:rgba(255,255,255,0.94);--text2:rgba(255,255,255,0.55);--text3:rgba(255,255,255,0.33);--primary:#ef2b3d;--primary2:#fb5069;--pglow:rgba(239,43,61,0.34);--pdim:rgba(239,43,61,0.12);--green:#22c55e;--greendim:rgba(34,197,94,0.12);--red:#f87171;--reddim:rgba(248,113,113,0.12);--yellow:#f59e0b;--sidebar:#0d0a0b;--radius:14px;--radiuslg:18px;--radiussm:10px;--blur:none;--cardshadow:0 6px 26px rgba(0,0,0,0.4);--hovershadow:0 12px 34px rgba(239,43,61,0.22)}
html[data-design="core"][data-theme="light"]{--bg:#f7f6f6;--bg2:#efeaea;--surface:#ffffff;--surface2:#faf7f7;--surface3:#f1ebeb;--border:rgba(0,0,0,0.07);--border2:rgba(0,0,0,0.14);--text:#1a1416;--text2:rgba(20,15,17,0.6);--text3:rgba(20,15,17,0.4);--primary:#dc2626;--primary2:#e11d48;--pglow:rgba(220,38,38,0.2);--pdim:rgba(220,38,38,0.08);--green:#16a34a;--greendim:rgba(22,163,74,0.09);--red:#dc2626;--reddim:rgba(220,38,38,0.08);--yellow:#d97706;--sidebar:#ffffff;--radius:14px;--radiuslg:18px;--radiussm:10px;--blur:none;--cardshadow:0 4px 18px rgba(120,20,30,0.08);--hovershadow:0 10px 30px rgba(220,38,38,0.14)}

/* ---- AURORA GLASS ---- */
html[data-design="aurora"][data-theme="dark"]{--bg:#0a0713;--bg2:#140b26;--surface:rgba(32,24,54,0.55);--surface2:rgba(44,33,72,0.5);--surface3:rgba(255,255,255,0.07);--border:rgba(255,255,255,0.10);--border2:rgba(255,255,255,0.18);--text:rgba(255,255,255,0.95);--text2:rgba(255,255,255,0.6);--text3:rgba(255,255,255,0.34);--primary:#8b5cf6;--primary2:#22d3ee;--pglow:rgba(139,92,246,0.35);--pdim:rgba(139,92,246,0.14);--green:#34d399;--greendim:rgba(52,211,153,0.14);--red:#fb7185;--reddim:rgba(251,113,133,0.14);--yellow:#fbbf24;--sidebar:rgba(18,12,32,0.55);--radius:20px;--radiuslg:26px;--radiussm:12px;--blur:blur(24px) saturate(150%);--cardshadow:0 8px 40px rgba(0,0,0,0.35);--hovershadow:0 14px 50px rgba(139,92,246,0.28)}
html[data-design="aurora"][data-theme="light"]{--bg:#eef0fb;--bg2:#e3ddfb;--surface:rgba(255,255,255,0.58);--surface2:rgba(255,255,255,0.72);--surface3:rgba(90,70,150,0.07);--border:rgba(110,95,160,0.20);--border2:rgba(110,95,160,0.34);--text:#1a1533;--text2:rgba(28,22,60,0.62);--text3:rgba(28,22,60,0.4);--primary:#7c3aed;--primary2:#0891b2;--pglow:rgba(124,58,237,0.24);--pdim:rgba(124,58,237,0.10);--green:#059669;--greendim:rgba(5,150,105,0.10);--red:#e11d48;--reddim:rgba(225,29,72,0.10);--yellow:#d97706;--sidebar:rgba(255,255,255,0.5);--radius:20px;--radiuslg:26px;--radiussm:12px;--blur:blur(24px) saturate(170%);--cardshadow:0 8px 40px rgba(80,60,140,0.12);--hovershadow:0 14px 50px rgba(124,58,237,0.18)}

/* ---- AURUM (custom: obsidian + gold, cursor spotlight) ---- */
html[data-design="aurum"][data-theme="dark"]{--bg:#0b0a08;--bg2:#12100b;--surface:#161310;--surface2:#1e1a15;--surface3:#2a251d;--border:rgba(240,200,120,0.13);--border2:rgba(240,200,120,0.3);--text:rgba(255,251,244,0.95);--text2:rgba(232,222,202,0.58);--text3:rgba(200,188,165,0.4);--primary:#f0b429;--primary2:#ffd873;--pglow:rgba(240,180,41,0.34);--pdim:rgba(240,180,41,0.12);--green:#34d399;--greendim:rgba(52,211,153,0.14);--red:#fb7185;--reddim:rgba(251,113,133,0.12);--yellow:#f5c542;--sidebar:#100e0a;--radius:16px;--radiuslg:20px;--radiussm:10px;--blur:blur(14px);--cardshadow:0 8px 34px rgba(0,0,0,0.45);--hovershadow:0 14px 44px rgba(240,180,41,0.2)}
html[data-design="aurum"][data-theme="light"]{--bg:#faf7f0;--bg2:#f3ece0;--surface:#ffffff;--surface2:#faf6ee;--surface3:#f1eadd;--border:rgba(180,140,40,0.18);--border2:rgba(180,140,40,0.34);--text:#221c10;--text2:rgba(60,50,28,0.6);--text3:rgba(60,50,28,0.4);--primary:#c98a00;--primary2:#e6a600;--pglow:rgba(201,138,0,0.2);--pdim:rgba(201,138,0,0.08);--green:#059669;--greendim:rgba(5,150,105,0.09);--red:#e11d48;--reddim:rgba(225,29,72,0.09);--yellow:#ca8a04;--sidebar:#ffffff;--radius:16px;--radiuslg:20px;--radiussm:10px;--blur:blur(14px);--cardshadow:0 8px 30px rgba(120,90,20,0.1);--hovershadow:0 14px 40px rgba(201,138,0,0.16)}

/* ---- NEXUS (custom: network constellation + holographic) ---- */
html[data-design="nexus"][data-theme="dark"]{--bg:#070709;--bg2:#0b0b12;--surface:rgba(20,21,30,0.6);--surface2:rgba(28,30,42,0.55);--surface3:rgba(255,255,255,0.06);--border:rgba(160,170,255,0.12);--border2:rgba(180,190,255,0.24);--text:rgba(255,255,255,0.95);--text2:rgba(210,215,235,0.6);--text3:rgba(180,185,215,0.36);--primary:#8b7bff;--primary2:#22d3ee;--pglow:rgba(139,123,255,0.4);--pdim:rgba(139,123,255,0.13);--green:#34d399;--greendim:rgba(52,211,153,0.14);--red:#fb7185;--reddim:rgba(251,113,133,0.12);--yellow:#fbbf24;--sidebar:rgba(12,13,20,0.6);--radius:18px;--radiuslg:22px;--radiussm:11px;--blur:blur(22px) saturate(150%);--cardshadow:0 8px 40px rgba(0,0,0,0.45);--hovershadow:0 14px 50px rgba(139,123,255,0.3)}
html[data-design="nexus"][data-theme="light"]{--bg:#eef0f9;--bg2:#e7eaf6;--surface:rgba(255,255,255,0.62);--surface2:rgba(255,255,255,0.76);--surface3:rgba(90,100,180,0.06);--border:rgba(100,110,200,0.18);--border2:rgba(100,110,200,0.32);--text:#141527;--text2:rgba(25,28,60,0.6);--text3:rgba(25,28,60,0.4);--primary:#6d5cff;--primary2:#0891b2;--pglow:rgba(109,92,255,0.22);--pdim:rgba(109,92,255,0.09);--green:#059669;--greendim:rgba(5,150,105,0.09);--red:#e11d48;--reddim:rgba(225,29,72,0.09);--yellow:#d97706;--sidebar:rgba(255,255,255,0.55);--radius:18px;--radiuslg:22px;--radiussm:11px;--blur:blur(22px) saturate(170%);--cardshadow:0 8px 34px rgba(60,60,140,0.12);--hovershadow:0 14px 44px rgba(109,92,255,0.18)}

html,body{height:100%}
body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;transition:background .4s,color .4s;overflow-x:hidden}
body[dir="rtl"]{direction:rtl}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:4px}

/* ===================== BACKGROUND DECOR ===================== */
.decor{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.decor>div{display:none;position:absolute}
/* aurora */
html[data-design="aurora"] .aurora-blob{display:block;border-radius:50%;filter:blur(90px);opacity:.7}
.aurora-blob.b1{width:520px;height:520px;background:radial-gradient(circle,#8b5cf6,transparent 65%);top:-12%;inset-inline-start:-8%;animation:blobFloat 22s ease-in-out infinite}
.aurora-blob.b2{width:460px;height:460px;background:radial-gradient(circle,#22d3ee,transparent 65%);bottom:-14%;inset-inline-end:-6%;animation:blobFloat 26s ease-in-out infinite reverse}
.aurora-blob.b3{width:380px;height:380px;background:radial-gradient(circle,#ec4899,transparent 65%);top:38%;inset-inline-start:52%;animation:blobFloat 30s ease-in-out infinite}
html[data-theme="light"] .aurora-blob{opacity:.5}
@keyframes blobFloat{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(60px,-50px) scale(1.15)}66%{transform:translate(-40px,60px) scale(.9)}}
/* aurum */
.aurum-amb,.aurum-spot{display:none}
html[data-design="aurum"] .aurum-amb{display:block;position:absolute;top:-22%;inset-inline-start:50%;transform:translateX(-50%);width:820px;height:520px;background:radial-gradient(ellipse,var(--pglow),transparent 70%);filter:blur(30px);opacity:.55}
html[data-design="aurum"] .aurum-spot{display:block;position:fixed;inset:0;background:radial-gradient(340px circle at var(--sx,50%) var(--sy,12%),var(--pglow),transparent 62%);opacity:.5;mix-blend-mode:screen}
html[data-design="aurum"][data-theme="light"] .aurum-amb{opacity:.4}
html[data-design="aurum"][data-theme="light"] .aurum-spot{mix-blend-mode:multiply;opacity:.22}
/* core */
html[data-design="core"] .core-glow{display:block;border-radius:50%;filter:blur(100px);opacity:.42;animation:blobFloat 28s ease-in-out infinite}
.core-glow.rg1{width:500px;height:500px;background:radial-gradient(circle,#ef2b3d,transparent 65%);top:-16%;inset-inline-end:-10%}
.core-glow.rg2{width:360px;height:360px;background:radial-gradient(circle,#7f1d1d,transparent 65%);bottom:-14%;inset-inline-start:-8%;animation-direction:reverse}
html[data-theme="light"] .core-glow{opacity:.2}
/* nexus */
.nexus-canvas{display:none;position:absolute;inset:0;width:100%;height:100%}
html[data-design="nexus"] .nexus-canvas{display:block}

/* ===================== LOGIN ===================== */
.login-wrap{position:relative;z-index:2;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login-card{width:100%;max-width:400px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radiuslg);padding:44px 36px 34px;backdrop-filter:var(--blur);box-shadow:var(--cardshadow);position:relative;overflow:hidden;animation:cardIn .8s cubic-bezier(.16,1,.3,1) both}
.login-card::before{content:'';position:absolute;top:0;inset-inline:0;height:2px;background:linear-gradient(90deg,transparent,var(--primary),var(--primary2),transparent);animation:shimmer 3s ease-in-out infinite}
.login-logo{display:flex;justify-content:center;margin-bottom:18px}
.login-title{text-align:center;font-family:var(--font-head);font-size:24px;font-weight:800;letter-spacing:-.02em}
html[data-design="aurum"] .login-title{letter-spacing:-.02em}
.login-sub{text-align:center;font-size:11px;color:var(--text3);margin-top:6px;text-transform:uppercase;letter-spacing:.14em;font-weight:600}
.login-form{margin-top:30px}
.demo-note{margin-top:16px;text-align:center;font-size:11px;color:var(--text3)}
.login-controls{position:fixed;top:18px;inset-inline-end:18px;display:flex;gap:6px;z-index:5}

/* ===================== APP LAYOUT ===================== */
#app{display:none;position:relative;z-index:2;min-height:100vh}
#app.on{display:flex}
.sidebar{width:var(--sb-w);background:var(--sidebar);border-inline-end:1px solid var(--border);display:flex;flex-direction:column;position:fixed;inset-block:0;inset-inline-start:0;z-index:100;backdrop-filter:var(--blur);transition:transform .3s}
.sb-brand{padding:16px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);position:relative}
.sb-brand::after{content:'';position:absolute;bottom:-1px;inset-inline:0;height:1px;background:linear-gradient(90deg,transparent,var(--primary),transparent);animation:shimmer 4s ease-in-out infinite}
.sb-brand-l{display:flex;align-items:center;gap:11px}
.sb-brand-name{font-family:var(--font-head);font-size:16px;font-weight:800;letter-spacing:-.02em}
.icon-btn{width:30px;height:30px;border-radius:var(--radiussm);border:1px solid var(--border);background:var(--surface2);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.icon-btn:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-1px)}
.sb-nav{flex:1;padding:10px;overflow-y:auto}
.nav-sec{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.1em;padding:14px 12px 6px}
.nav-item{display:flex;align-items:center;gap:11px;padding:10px 12px;margin:2px 0;border-radius:var(--radiussm);color:var(--text2);font-size:13.5px;font-weight:500;cursor:pointer;transition:all .18s;border:none;background:none;width:100%;text-align:start;position:relative;font-family:inherit}
.nav-item:hover{background:var(--pdim);color:var(--text)}
.nav-item .nav-ico{width:18px;height:18px;flex-shrink:0;opacity:.75}
.nav-item.active{background:var(--pdim);color:var(--primary);font-weight:700}
.nav-item.active .nav-ico{opacity:1}
.nav-item.active::before{content:'';position:absolute;inset-inline-start:0;top:18%;bottom:18%;width:3px;border-radius:3px;background:var(--primary)}
html[data-design="aurum"] .nav-item.active{box-shadow:inset 0 0 0 1px var(--border)}
.nav-badge{margin-inline-start:auto;background:var(--surface3);color:var(--text2);font-size:10px;padding:2px 8px;border-radius:20px;font-weight:700}
.sb-foot{padding:12px;border-top:1px solid var(--border)}
.seg{display:flex;gap:4px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radiussm);padding:3px;margin-bottom:8px}
.seg button{flex:1;padding:6px;border:none;background:none;color:var(--text3);font-family:inherit;font-size:11px;font-weight:700;cursor:pointer;border-radius:calc(var(--radiussm) - 3px);transition:all .2s}
.seg button.active{background:var(--primary);color:#fff}
.mini-designs{display:flex;gap:5px;margin-bottom:8px}
.mini-d{flex:1;height:26px;border-radius:var(--radiussm);border:1px solid var(--border);cursor:pointer;position:relative;overflow:hidden;transition:transform .2s}
.mini-d:hover{transform:translateY(-2px)}
.mini-d.active{border-color:var(--primary);box-shadow:0 0 0 2px var(--pglow)}
.mini-d.md-core{background:linear-gradient(135deg,#7f1d1d,#ef2b3d)}
.mini-d.md-aurora{background:linear-gradient(135deg,#8b5cf6,#22d3ee)}
.mini-d.md-aurum{background:linear-gradient(135deg,#4a3410,#ffd873)}
.mini-d.md-nexus{background:linear-gradient(135deg,#8b7bff,#22d3ee,#ec4899);background-size:180% 100%}
.logout{width:100%;padding:8px;border:1px solid var(--border);border-radius:var(--radiussm);background:none;color:var(--text3);font-family:inherit;font-size:11.5px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.logout:hover{background:var(--reddim);border-color:var(--red);color:var(--red)}
.ver{text-align:center;font-size:10px;color:var(--text3);margin-top:8px}

.main{margin-inline-start:var(--sb-w);flex:1;padding:26px 30px 60px;min-height:100vh;min-width:0}
.page{display:none}
.page.active{display:block;animation:pageIn .45s cubic-bezier(.16,1,.3,1)}
.page-head{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;gap:12px;flex-wrap:wrap}
.page-title{font-family:var(--font-head);font-size:22px;font-weight:800;letter-spacing:-.02em}
.page-sub{font-size:12.5px;color:var(--text3);margin-top:4px}

/* ---- stat cards ---- */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;backdrop-filter:var(--blur);box-shadow:var(--cardshadow);transition:transform .3s,box-shadow .3s;position:relative;overflow:hidden;animation:cardUp .5s both}
.stat:nth-child(1){animation-delay:.05s}.stat:nth-child(2){animation-delay:.12s}.stat:nth-child(3){animation-delay:.19s}.stat:nth-child(4){animation-delay:.26s}
.stat:hover{transform:translateY(-4px);box-shadow:var(--hovershadow)}
.stat-ico{position:absolute;inset-inline-end:14px;top:14px;width:34px;height:34px;border-radius:10px;background:var(--pdim);color:var(--primary);display:flex;align-items:center;justify-content:center}
.stat-label{font-size:11px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}
.stat-value{font-family:var(--font-head);font-size:26px;font-weight:800;letter-spacing:-.02em}
html[data-design="aurum"] .stat-value{letter-spacing:-.03em}
.stat-unit{font-size:13px;font-weight:500;color:var(--text3)}

.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;backdrop-filter:var(--blur);box-shadow:var(--cardshadow);transition:transform .3s,box-shadow .3s;animation:cardUp .5s both;animation-delay:.2s}
.card.hoverable:hover{transform:translateY(-2px);box-shadow:var(--hovershadow)}
.card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.card-title{font-size:13.5px;font-weight:700;display:flex;align-items:center;gap:9px}
html[data-design="aurum"] .card-title{letter-spacing:0}

/* ---- buttons ---- */
.btn{font-family:inherit;font-size:12.5px;font-weight:700;border-radius:var(--radiussm);padding:9px 16px;cursor:pointer;display:inline-flex;align-items:center;gap:7px;border:1px solid transparent;transition:all .18s;white-space:nowrap}
.btn-primary{background:var(--primary);color:#fff}
html[data-design="aurora"] .btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary2))}
html[data-design="core"] .btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary2))}
html[data-design="aurum"] .btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary2));color:#1a1305}
.btn-primary:hover{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 8px 22px var(--pglow)}
.btn-ghost{background:var(--surface2);color:var(--text2);border:1px solid var(--border)}
.btn-ghost:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-2px)}
.btn-danger{background:var(--reddim);color:var(--red);border:1px solid var(--red)}
.btn-danger:hover{background:var(--red);color:#fff}
.btn-sm{padding:6px 11px;font-size:11.5px}

/* ---- system bars ---- */
.sysbar{height:8px;background:var(--surface3);border-radius:20px;overflow:hidden}
.sysbar-fill{height:100%;border-radius:20px;transition:width .6s cubic-bezier(.16,1,.3,1);background:linear-gradient(90deg,var(--primary),var(--primary2))}
.big-pct{font-family:var(--font-head);font-size:20px;font-weight:800}
html[data-design="aurum"] .big-pct{letter-spacing:-.02em}

/* ---- custom chart (no external deps) ---- */
.chart{display:flex;align-items:stretch;gap:8px;height:200px;padding-top:8px}
.chart .col{flex:1;display:flex;flex-direction:column;align-items:center;gap:7px;min-width:0}
.chart .barwrap{width:100%;flex:1;display:flex;align-items:flex-end;justify-content:center}
.chart .bar{width:74%;max-width:36px;border-radius:7px 7px 0 0;background:linear-gradient(180deg,var(--primary),var(--primary2));box-shadow:0 0 16px var(--pdim);transition:height .7s cubic-bezier(.16,1,.3,1),filter .2s;position:relative}
.chart .bar:hover{filter:brightness(1.2)}
.chart .bar::after{content:attr(data-v) ' MB';position:absolute;top:-22px;inset-inline-start:50%;transform:translateX(-50%);font-size:10px;font-weight:700;color:var(--text2);opacity:0;transition:opacity .2s;white-space:nowrap;font-family:var(--font-mono)}
body[dir="rtl"] .chart .bar::after{transform:translateX(50%)}
.chart .bar:hover::after{opacity:1}
.chart .xl{font-size:9.5px;color:var(--text3);font-family:var(--font-mono)}

/* ---- rows ---- */
.row-item{display:flex;align-items:center;justify-content:space-between;padding:13px 0;border-bottom:1px solid var(--border)}
.row-item:last-child{border-bottom:none}
.row-key{color:var(--text2);font-size:12.5px}
.row-val{font-weight:700;font-size:12.5px}
html[data-design="aurum"] .row-val{font-weight:800}

/* ---- table ---- */
.tbl-wrap{overflow-x:auto;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);backdrop-filter:var(--blur);box-shadow:var(--cardshadow)}
table.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:start;font-size:10.5px;font-weight:700;color:var(--text3);padding:12px 14px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border);background:var(--surface2)}
.tbl td{padding:12px 14px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tbody tr{transition:background .15s}
.tbl tbody tr:hover td{background:var(--pdim)}
.tag{display:inline-flex;align-items:center;padding:3px 9px;border-radius:6px;font-size:10px;font-weight:800;letter-spacing:.03em;text-transform:uppercase}
.tag-vless{background:var(--pdim);color:var(--primary)}
.tag-on{background:var(--greendim);color:var(--green)}
.tag-off{background:var(--reddim);color:var(--red)}
.usepill{display:flex;align-items:center;gap:9px;font-size:11.5px;color:var(--text2);min-width:170px}
.usepill .used{color:var(--text);font-weight:700}
html[data-design="aurum"] .usepill .used{font-weight:700}
.usepill .bar{flex:1;height:5px;background:var(--surface3);border-radius:3px;min-width:54px;overflow:hidden}
.usepill .fill{height:100%;border-radius:3px;transition:width .5s}
.toggle{width:38px;height:21px;border-radius:20px;background:var(--surface3);position:relative;cursor:pointer;transition:all .3s;border:1px solid var(--border);flex-shrink:0}
.toggle::after{content:'';position:absolute;width:15px;height:15px;border-radius:50%;background:var(--text3);top:2px;inset-inline-start:2px;transition:all .3s cubic-bezier(.34,1.56,.64,1)}
.toggle.on{background:var(--green);border-color:var(--green)}
.toggle.on::after{inset-inline-start:19px;background:#fff}
body[dir="rtl"] .toggle.on::after{inset-inline-start:auto;inset-inline-end:19px}

.actions{display:flex;gap:4px;align-items:center}
.act{width:28px;height:28px;border-radius:7px;border:1px solid var(--border);background:var(--surface2);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .18s}
.act:hover{transform:translateY(-2px)}
.act.a-edit:hover{border-color:var(--yellow);color:var(--yellow)}
.act.a-copy:hover{border-color:var(--primary);color:var(--primary)}
.act.a-sub:hover{border-color:var(--green);color:var(--green)}
.act.a-qr:hover{border-color:var(--primary2);color:var(--primary2)}
.act.a-del:hover{border-color:var(--red);color:var(--red)}

/* ---- inbounds toolbar ---- */
.inb-summary{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.inb-chip{display:flex;align-items:center;gap:8px;padding:8px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radiussm);backdrop-filter:var(--blur);font-size:12px;color:var(--text2)}
.inb-chip b{font-size:15px;color:var(--text);font-family:var(--font-head);margin-inline-start:2px}
.inb-chip .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.mono{width:32px;height:32px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;color:#fff;flex-shrink:0;box-shadow:inset 0 0 0 1px rgba(255,255,255,.12)}
.remark-cell{display:flex;align-items:center;gap:11px}
.remark-cell .rk-name{font-weight:700}
.tbl td.stripe{border-inline-start:3px solid var(--border)}
.usepill .pct{color:var(--text3);font-size:10.5px;min-width:30px;text-align:end}
@media(max-width:900px){.tbl .col-type{display:none}}
@media(max-width:640px){.tbl .col-ips,.tbl .col-id{display:none}}
.inb-toolbar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap}
.searchbox{flex:1;min-width:200px;position:relative}
.searchbox input{width:100%;padding:10px 14px 10px 38px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radiussm);color:var(--text);font-size:13px;font-family:inherit;outline:none;transition:all .2s;backdrop-filter:var(--blur)}
body[dir="rtl"] .searchbox input{padding:10px 38px 10px 14px}
.searchbox input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--pglow)}
.searchbox svg{position:absolute;inset-inline-start:12px;top:50%;transform:translateY(-50%);color:var(--text3)}
.chips{display:flex;gap:4px;padding:4px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radiussm);backdrop-filter:var(--blur)}
.chip{padding:6px 14px;border-radius:calc(var(--radiussm) - 3px);font-size:11.5px;font-weight:700;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .2s;font-family:inherit}
.chip.active{background:var(--primary);color:#fff}

/* ---- forms ---- */
.fg{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.fl{font-size:11px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.04em}
.fi,textarea.fi{padding:10px 13px;border-radius:var(--radiussm);border:1px solid var(--border);font-family:inherit;font-size:13px;outline:none;color:var(--text);background:var(--surface2);transition:all .2s;width:100%}
.fi:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--pglow)}
.frow{display:flex;gap:12px;flex-wrap:wrap}
.frow .fg{flex:1;min-width:110px;margin-bottom:0}

.empty{text-align:center;padding:50px 16px;color:var(--text3)}
.empty svg{opacity:.4;margin-bottom:12px}

/* ---- settings ---- */
.design-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
.design-opt{border:1px solid var(--border);border-radius:var(--radius);padding:14px;cursor:pointer;transition:all .25s;position:relative;background:var(--surface2)}
.design-opt:hover{transform:translateY(-3px);border-color:var(--border2)}
.design-opt.active{border-color:var(--primary);box-shadow:0 0 0 3px var(--pglow)}
.design-opt .swatch{height:80px;border-radius:var(--radiussm);margin-bottom:12px;position:relative;overflow:hidden;border:1px solid var(--border)}
.sw-core{background:radial-gradient(circle at 25% 30%,rgba(239,43,61,.95),transparent 55%),radial-gradient(circle at 85% 80%,rgba(127,29,29,.85),transparent 55%),#0a0808}
.sw-aurora{background:radial-gradient(circle at 20% 20%,#8b5cf6,transparent 55%),radial-gradient(circle at 80% 70%,#22d3ee,transparent 55%),#0a0713}
.sw-aurum{background:radial-gradient(circle at 30% 25%,rgba(240,180,41,.9),transparent 55%),radial-gradient(circle at 82% 85%,rgba(120,80,20,.75),transparent 55%),#0b0a08;position:relative;overflow:hidden}
.sw-aurum::after{content:'';position:absolute;inset:0;background:radial-gradient(220px circle at 62% 32%,rgba(255,216,115,.28),transparent 60%)}
.sw-nexus{background:radial-gradient(circle at 30% 35%,rgba(139,123,255,.6),transparent 52%),radial-gradient(circle at 78% 68%,rgba(34,211,238,.5),transparent 52%),#070709;position:relative;overflow:hidden}
.sw-nexus::after{content:'';position:absolute;inset:0;background-image:radial-gradient(rgba(200,210,255,.8) 1.2px,transparent 1.3px);background-size:18px 18px;opacity:.5}
.design-opt .d-name{font-family:var(--font-head);font-size:14px;font-weight:800;margin-bottom:3px}
.design-opt .d-desc{font-size:11px;color:var(--text3);line-height:1.5}
.design-opt .d-check{position:absolute;top:12px;inset-inline-end:12px;width:22px;height:22px;border-radius:50%;background:var(--primary);color:#fff;display:none;align-items:center;justify-content:center;font-size:12px;z-index:2}
.design-opt.active .d-check{display:flex}
.set-block{margin-top:16px}

/* ---- toast ---- */
.toast{position:fixed;bottom:24px;inset-inline-start:50%;transform:translateX(-50%) translateY(24px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:var(--radiussm);padding:12px 22px;font-size:13px;font-weight:600;opacity:0;transition:all .35s cubic-bezier(.16,1,.3,1);z-index:999;display:flex;align-items:center;gap:9px;box-shadow:var(--cardshadow);backdrop-filter:var(--blur)}
body[dir="rtl"] .toast{transform:translateX(50%) translateY(24px)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
body[dir="rtl"] .toast.show{transform:translateX(50%) translateY(0)}
.toast.err{border-color:var(--red);color:var(--red)}

/* ---- modal ---- */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(6px);padding:16px}
.modal-bg.show{display:flex;animation:fadeIn .2s}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:var(--radiuslg);padding:26px;width:100%;max-width:470px;position:relative;box-shadow:var(--cardshadow);backdrop-filter:var(--blur);transform:scale(.9);opacity:0;transition:all .4s cubic-bezier(.34,1.56,.64,1);max-height:90vh;overflow-y:auto}
.modal-bg.show .modal{transform:scale(1);opacity:1}
.modal-title{font-family:var(--font-head);font-size:17px;font-weight:800;margin-bottom:18px}
.modal-x{position:absolute;top:16px;inset-inline-end:16px;background:var(--surface3);border:1px solid var(--border);color:var(--text2);width:30px;height:30px;border-radius:8px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.modal-x:hover{background:var(--reddim);color:var(--red)}
.qr-box{text-align:center;padding:22px;background:#fff;border-radius:var(--radius);margin:8px auto 0;width:fit-content}
.qr-box img{width:220px;height:220px;display:block}

/* ---- mobile ---- */
body[dir="rtl"] .stat-value,body[dir="rtl"] .big-pct,body[dir="rtl"] .row-val,body[dir="rtl"] .tag,body[dir="rtl"] #domain-cur{direction:ltr;unicode-bidi:isolate}
body[dir="rtl"] .usepill{direction:ltr}
.mob-head{display:none;position:fixed;top:0;inset-inline:0;height:52px;background:var(--sidebar);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 16px;backdrop-filter:var(--blur)}
.sb-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:99}
.sb-overlay.show{display:block}
@media(max-width:860px){
 .sidebar{transform:translateX(-100%);z-index:200}
 body[dir="rtl"] .sidebar{transform:translateX(100%)}
 .sidebar.open{transform:translateX(0)!important}
 .main{margin-inline-start:0;padding:66px 14px 40px}
 .mob-head{display:flex}
 .stats{grid-template-columns:1fr 1fr}
 .grid2{grid-template-columns:1fr}
 .design-grid{grid-template-columns:1fr}
}
@media(max-width:480px){.stats{grid-template-columns:1fr}}

/* ---- NEXUS accents ---- */
@keyframes holo{to{background-position:300% 0}}
html[data-design="nexus"] .btn-primary{background:linear-gradient(120deg,#8b7bff,#22d3ee,#a855f7,#ec4899,#8b7bff);background-size:300% 100%;animation:holo 7s linear infinite;color:#0b0b14}
html[data-design="nexus"] .sysbar-fill,html[data-design="nexus"] .chart .bar{background:linear-gradient(120deg,#8b7bff,#22d3ee,#a855f7,#ec4899,#8b7bff);background-size:300% 100%;animation:holo 7s linear infinite}
html[data-design="nexus"] .card,html[data-design="nexus"] .stat{position:relative}
html[data-design="nexus"] .card::before,html[data-design="nexus"] .stat::before{content:'';position:absolute;top:0;inset-inline:14px;height:1px;background:linear-gradient(90deg,transparent,#8b7bff,#22d3ee,#ec4899,transparent);opacity:.75;z-index:1}
html[data-design="nexus"] .login-logo svg,html[data-design="nexus"] .sb-brand svg{filter:drop-shadow(0 0 14px rgba(139,123,255,.6))}
html[data-design="nexus"] .nav-item.active{text-shadow:0 0 10px var(--pglow)}
html[data-design="nexus"] .tag-vless{background:linear-gradient(120deg,rgba(139,123,255,.22),rgba(34,211,238,.22));color:#a9b4ff}

/* ---- AURUM accents ---- */
html[data-design="aurum"] .card,html[data-design="aurum"] .stat{position:relative}
html[data-design="aurum"] .card::before,html[data-design="aurum"] .stat::before{content:'';position:absolute;top:0;inset-inline:16px;height:1px;background:linear-gradient(90deg,transparent,var(--primary2),transparent);opacity:.6}
html[data-design="aurum"] .chart .bar{box-shadow:0 0 16px var(--pdim)}
html[data-design="aurum"] .login-logo svg,html[data-design="aurum"] .sb-brand svg{filter:drop-shadow(0 0 12px var(--pglow))}

/* ===================== ANIMATIONS ===================== */
@keyframes shimmer{0%,100%{opacity:.4;transform:scaleX(.4)}50%{opacity:1;transform:scaleX(1)}}
@keyframes cardIn{from{opacity:0;transform:translateY(30px) scale(.96)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes cardUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
@keyframes pageIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes spin{to{transform:rotate(360deg)}}
.logo-spin{transform-box:fill-box;transform-origin:center;animation:spin 22s linear infinite}
</style>
</head>
<body dir="ltr">

<div class="decor">
  <div class="aurora-blob b1"></div><div class="aurora-blob b2"></div><div class="aurora-blob b3"></div>
  <div class="aurum-amb"></div><div class="aurum-spot"></div>
  <div class="core-glow rg1"></div><div class="core-glow rg2"></div>
  <canvas class="nexus-canvas" id="nexus-canvas"></canvas>
</div>

<!-- ============ LOGIN ============ -->
<div class="login-controls" id="login-controls">
  <button class="icon-btn" onclick="cycleDesign()" title="Design">✦</button>
  <button class="icon-btn" onclick="toggleTheme()" title="Theme" id="lc-theme"></button>
  <button class="icon-btn" onclick="cycleLang()" title="Language" id="lc-lang" style="font-size:11px;font-weight:700">EN</button>
</div>
<div class="login-wrap" id="login-screen">
  <div class="login-card">
    <div class="login-logo" id="login-logo"></div>
    <div class="login-title">CORE</div>
    <div class="login-sub" data-en="Gateway Panel" data-fa="پنل مدیریت">Gateway Panel</div>
    <form class="login-form" onsubmit="doLogin(event)">
      <div class="fg">
        <label class="fl" data-en="Password" data-fa="رمز عبور">Password</label>
        <input class="fi" type="password" id="login-pw" placeholder="admin" autofocus>
      </div>
      <button class="btn btn-primary" type="submit" style="width:100%;justify-content:center;margin-top:6px" data-en="Sign In" data-fa="ورود">Sign In</button>
    </form>
    <div class="demo-note" data-en="Default password: admin" data-fa="رمز پیش‌فرض: admin">Default password: admin</div>
  </div>
</div>

<!-- ============ APP ============ -->
<div id="app">
  <div class="mob-head">
    <span style="font-family:var(--font-head);font-weight:800;font-size:15px">CORE</span>
    <button class="icon-btn" onclick="toggleSidebar()">☰</button>
  </div>
  <div class="sb-overlay" id="sb-overlay" onclick="toggleSidebar()"></div>

  <aside class="sidebar" id="sidebar">
    <div class="sb-brand">
      <div class="sb-brand-l">
        <span id="brand-logo"></span>
        <span class="sb-brand-name">CORE</span>
      </div>
      <button class="icon-btn" onclick="toggleTheme()" id="theme-btn"></button>
    </div>
    <nav class="sb-nav" id="nav"></nav>
    <div class="sb-foot">
      <div class="mini-designs" id="mini-designs"></div>
      <div class="seg" id="lang-seg">
        <button data-lang="en" onclick="setLang('en')">EN</button>
        <button data-lang="fa" onclick="setLang('fa')">FA</button>
      </div>
      <button class="logout" onclick="doLogout()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span data-en="Logout" data-fa="خروج">Logout</span>
      </button>
      <div class="ver">v1.0</div>
    </div>
  </aside>

  <main class="main">

    <!-- Dashboard -->
    <section class="page active" id="page-dashboard">
      <div class="page-head">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
          <div class="page-sub" id="last-update">—</div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-ghost" onclick="quickCreate(0.5)">+ 0.5 GB</button>
          <button class="btn btn-primary" onclick="quickCreate(1)">+ 1 GB</button>
        </div>
      </div>
      <div class="stats" id="stat-cards"></div>
      <div class="grid2">
        <div class="card hoverable">
          <div class="card-head"><div class="card-title" data-en="CPU Usage" data-fa="مصرف CPU">CPU Usage</div><span class="big-pct" id="cpu-val" style="color:var(--primary)">—</span></div>
          <div class="sysbar"><div class="sysbar-fill" id="cpu-bar" style="width:0%"></div></div>
        </div>
        <div class="card hoverable">
          <div class="card-head"><div class="card-title" data-en="Memory" data-fa="حافظه">Memory</div><span class="big-pct" id="mem-val" style="color:var(--green)">—</span></div>
          <div class="sysbar"><div class="sysbar-fill" id="mem-bar" style="width:0%;background:linear-gradient(90deg,var(--green),var(--primary2))"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><div class="card-title" data-en="Traffic (last 12h)" data-fa="ترافیک (۱۲ ساعت اخیر)">Traffic (last 12h)</div></div>
        <div class="chart" id="chart"></div>
      </div>
    </section>

    <!-- Inbounds -->
    <section class="page" id="page-inbounds">
      <div class="page-head">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
          <div class="page-sub">VLESS over WebSocket</div>
        </div>
        <button class="btn btn-primary" onclick="openModal('add-modal')"><span data-en="+ Add" data-fa="+ افزودن">+ Add</span></button>
      </div>
      <div class="inb-summary" id="inb-summary"></div>
      <div class="inb-toolbar">
        <div class="searchbox">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="search" placeholder="Search…" data-en-ph="Search by name…" data-fa-ph="جستجو بر اساس نام…" oninput="renderLinks()">
        </div>
        <div class="chips">
          <button class="chip active" data-f="all" onclick="setFilter('all',this)" data-en="All" data-fa="همه">All</button>
          <button class="chip" data-f="active" onclick="setFilter('active',this)" data-en="Active" data-fa="فعال">Active</button>
          <button class="chip" data-f="disabled" onclick="setFilter('disabled',this)" data-en="Disabled" data-fa="غیرفعال">Disabled</button>
        </div>
      </div>
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr>
            <th class="col-id" style="width:34px">#</th>
            <th data-en="Remark" data-fa="نام">Remark</th>
            <th class="col-type" style="width:60px" data-en="Type" data-fa="نوع">Type</th>
            <th data-en="Traffic" data-fa="ترافیک">Traffic</th>
            <th class="col-ips" style="width:70px">IPs</th>
            <th style="width:64px" data-en="Status" data-fa="وضعیت">Status</th>
            <th style="width:180px" data-en="Actions" data-fa="عملیات">Actions</th>
          </tr></thead>
          <tbody id="links-body"></tbody>
        </table>
        <div class="empty" id="links-empty" style="display:none">
          <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg>
          <div data-en="No inbounds found" data-fa="اینباندی یافت نشد">No inbounds found</div>
        </div>
      </div>
    </section>

    <!-- Traffic -->
    <section class="page" id="page-traffic">
      <div class="page-head"><div><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="page-sub" data-en="Overall statistics" data-fa="آمار کلی">Overall statistics</div></div></div>
      <div class="grid2">
        <div class="card hoverable">
          <div class="card-head"><div class="card-title" data-en="Overview" data-fa="نمای کلی">Overview</div></div>
          <div class="row-item"><span class="row-key" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</span><span class="row-val" id="t-traffic">—</span></div>
          <div class="row-item"><span class="row-key" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="row-val" id="t-reqs">—</span></div>
          <div class="row-item"><span class="row-key" data-en="Active Connections" data-fa="اتصالات فعال">Active Connections</span><span class="row-val" id="t-conns">—</span></div>
          <div class="row-item"><span class="row-key" data-en="Uptime" data-fa="آپتایم">Uptime</span><span class="row-val" id="t-uptime">—</span></div>
        </div>
        <div class="card hoverable">
          <div class="card-head"><div class="card-title" data-en="Top Inbounds" data-fa="پرمصرف‌ترین‌ها">Top Inbounds</div></div>
          <div id="top-inbounds"></div>
        </div>
      </div>
    </section>

    <!-- Clean IP -->
    <section class="page" id="page-cleanip">
      <div class="page-head">
        <div><div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div><div class="page-sub" data-en="IPs & domains for subscription configs" data-fa="آی‌پی و دامنه برای کانفیگ‌های سابسکریپشن">IPs & domains for subscription configs</div></div>
        <button class="btn btn-primary" onclick="openModal('addr-modal')"><span data-en="+ Add" data-fa="+ افزودن">+ Add</span></button>
      </div>
      <div class="card">
        <div class="card-head"><div class="card-title" data-en="Clean IP List" data-fa="لیست آی‌پی تمیز">Clean IP List</div></div>
        <div id="addr-list" style="display:flex;flex-direction:column;gap:8px"></div>
      </div>
    </section>

    <!-- Domain -->
    <section class="page" id="page-domain">
      <div class="page-head"><div><div class="page-title" data-en="Domain" data-fa="دامنه">Domain</div><div class="page-sub" data-en="Replace the host domain in configs with your own" data-fa="جایگزینی دامنه هاست با دامنه اختصاصی">Replace the host domain in configs with your own</div></div></div>
      <div class="card" style="max-width:540px">
        <div class="card-head"><div class="card-title" data-en="Custom Domain" data-fa="دامنه اختصاصی">Custom Domain</div></div>
        <div style="padding:13px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radiussm);margin-bottom:14px">
          <div class="fl" style="margin-bottom:5px" data-en="Current" data-fa="فعلی">Current</div>
          <div id="domain-cur" style="font-family:var(--font-mono);font-size:13px;color:var(--text)">—</div>
        </div>
        <div class="fg">
          <label class="fl" data-en="New Domain" data-fa="دامنه جدید">New Domain</label>
          <div style="display:flex;gap:8px">
            <input class="fi" id="domain-input" placeholder="example.com" style="flex:1">
            <button class="btn btn-primary" onclick="saveDomain()" data-en="Save" data-fa="ذخیره">Save</button>
            <button class="btn btn-danger" onclick="clearDomain()" data-en="Clear" data-fa="پاک">Clear</button>
          </div>
        </div>
        <div style="margin-top:10px;padding:11px;background:var(--pdim);border:1px solid var(--border);border-radius:var(--radiussm);font-size:11.5px;color:var(--text2);line-height:1.6" data-en="Point your domain to this service via CNAME or A record, then set it here." data-fa="دامنه‌ات را با CNAME یا A record به این سرویس وصل کن، بعد اینجا ثبتش کن.">Point your domain to this service via CNAME or A record, then set it here.</div>
      </div>
    </section>

    <!-- Security -->
    <section class="page" id="page-security">
      <div class="page-head"><div><div class="page-title" data-en="Security" data-fa="امنیت">Security</div><div class="page-sub" data-en="Change panel password" data-fa="تغییر رمز پنل">Change panel password</div></div></div>
      <div class="card" style="max-width:440px">
        <div class="fg"><label class="fl" data-en="Current Password" data-fa="رمز فعلی">Current Password</label><input class="fi" type="password" id="cur-pw" placeholder="••••••"></div>
        <div class="fg"><label class="fl" data-en="New Password" data-fa="رمز جدید">New Password</label><input class="fi" type="password" id="new-pw" placeholder="min 4 chars"></div>
        <button class="btn btn-primary" onclick="changePw()" style="margin-top:4px" data-en="Update Password" data-fa="بروزرسانی رمز">Update Password</button>
      </div>
    </section>

    <!-- Backup -->
    <section class="page" id="page-backup">
      <div class="page-head"><div><div class="page-title" data-en="Backup & Restore" data-fa="پشتیبان‌گیری و بازیابی">Backup &amp; Restore</div><div class="page-sub" data-en="Export your config, or restore it on another panel" data-fa="از کانفیگت خروجی بگیر، یا روی یه پنل دیگه بازیابی کن">Export your config, or restore it on another panel</div></div></div>
      <div class="grid2">
        <div class="card hoverable">
          <div class="card-head"><div class="card-title" data-en="Export Backup" data-fa="خروجی پشتیبان">Export Backup</div></div>
          <div style="font-size:12.5px;color:var(--text2);line-height:1.7;margin-bottom:16px" data-en="Download a .json file with all your inbounds, clean IPs and domain. Keep it somewhere safe." data-fa="یک فایل json شامل همه‌ی اینباندها، آی‌پی‌های تمیز و دامنه دانلود کن و جای امن نگهش دار.">Download a .json file with all your inbounds, clean IPs and domain. Keep it somewhere safe.</div>
          <button class="btn btn-primary" onclick="exportBackup()"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> <span data-en="Download Backup" data-fa="دانلود پشتیبان">Download Backup</span></button>
        </div>
        <div class="card hoverable">
          <div class="card-head"><div class="card-title" data-en="Import / Restore" data-fa="ایمپورت / بازیابی">Import / Restore</div></div>
          <div style="font-size:12.5px;color:var(--text2);line-height:1.7;margin-bottom:16px" data-en="Select a CORE backup file to restore your inbounds and settings." data-fa="یک فایل پشتیبان CORE انتخاب کن تا اینباندها و تنظیماتت بازیابی بشن.">Select a CORE backup file to restore your inbounds and settings.</div>
          <input type="file" id="backup-file" accept=".json,application/json" style="display:none" onchange="importBackup(event)">
          <button class="btn btn-ghost" onclick="$('#backup-file').click()" style="border-color:var(--primary);color:var(--primary)"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg> <span data-en="Choose backup file…" data-fa="انتخاب فایل پشتیبان…">Choose backup file…</span></button>
          <div style="margin-top:12px;padding:10px 12px;background:var(--reddim);border:1px solid var(--border);border-radius:var(--radiussm);font-size:11px;color:var(--text2);line-height:1.6" data-en="⚠ Restoring overwrites current inbounds, clean IPs and domain." data-fa="⚠ بازیابی، اینباندها، آی‌پی‌های تمیز و دامنه‌ی فعلی رو بازنویسی می‌کنه.">⚠ Restoring overwrites current inbounds, clean IPs and domain.</div>
        </div>
      </div>
    </section>

    <!-- Settings -->
    <section class="page" id="page-settings">
      <div class="page-head"><div><div class="page-title" data-en="Settings" data-fa="تنظیمات">Settings</div><div class="page-sub" data-en="Personalize your panel" data-fa="شخصی‌سازی پنل">Personalize your panel</div></div></div>
      <div class="card">
        <div class="card-head"><div class="card-title" data-en="Design" data-fa="طراحی">Design</div></div>
        <div class="design-grid" id="design-grid"></div>
      </div>
      <div class="grid2 set-block">
        <div class="card">
          <div class="card-title" style="margin-bottom:12px" data-en="Theme" data-fa="تم">Theme</div>
          <div class="seg" id="theme-seg" style="margin-bottom:0">
            <button data-th="dark" onclick="setTheme('dark')" data-en="Dark" data-fa="تیره">Dark</button>
            <button data-th="light" onclick="setTheme('light')" data-en="Light" data-fa="روشن">Light</button>
          </div>
        </div>
        <div class="card">
          <div class="card-title" style="margin-bottom:12px" data-en="Language" data-fa="زبان">Language</div>
          <div class="seg" style="margin-bottom:0">
            <button data-lang="en" onclick="setLang('en')">English</button>
            <button data-lang="fa" onclick="setLang('fa')">فارسی</button>
          </div>
        </div>
      </div>
    </section>
  </main>
</div>

<!-- ============ MODALS ============ -->
<div class="modal-bg" id="add-modal" onclick="if(event.target===this)closeModal('add-modal')">
  <div class="modal">
    <button class="modal-x" onclick="closeModal('add-modal')">✕</button>
    <div class="modal-title" data-en="Add Inbound" data-fa="افزودن اینباند">Add Inbound</div>
    <div class="fg"><label class="fl" data-en="Remark" data-fa="نام">Remark</label><input class="fi" id="add-label" placeholder="e.g. Ali"></div>
    <div class="frow">
      <div class="fg"><label class="fl" data-en="Traffic (GB)" data-fa="ترافیک (GB)">Traffic (GB)</label><input class="fi" id="add-limit" type="number" min="0" step="0.1" placeholder="0 = ∞"></div>
      <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="add-maxconn" type="number" min="0" step="1" placeholder="0 = ∞"></div>
      <div class="fg"><label class="fl" data-en="Expiry (days)" data-fa="انقضا (روز)">Expiry (days)</label><input class="fi" id="add-expiry" type="number" min="0" step="1" placeholder="0 = ∞"></div>
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;justify-content:center;margin-top:6px" data-en="Create" data-fa="ساخت">Create</button>
  </div>
</div>

<div class="modal-bg" id="edit-modal" onclick="if(event.target===this)closeModal('edit-modal')">
  <div class="modal">
    <button class="modal-x" onclick="closeModal('edit-modal')">✕</button>
    <div class="modal-title" id="edit-title" data-en="Edit Inbound" data-fa="ویرایش اینباند">Edit Inbound</div>
    <input type="hidden" id="edit-uid">
    <div class="fg"><label class="fl" data-en="Name" data-fa="نام">Name</label><input class="fi" id="edit-name" readonly style="opacity:.6"></div>
    <div class="frow">
      <div class="fg"><label class="fl" data-en="Traffic (GB)" data-fa="ترافیک (GB)">Traffic (GB)</label><input class="fi" id="edit-limit" type="number" min="0" step="0.1" placeholder="0 = ∞"></div>
      <div class="fg"><label class="fl" data-en="Max IPs" data-fa="حداکثر آی‌پی">Max IPs</label><input class="fi" id="edit-maxconn" type="number" min="0" step="1" placeholder="0 = ∞"></div>
      <div class="fg"><label class="fl" data-en="Expiry (days)" data-fa="انقضا (روز)">Expiry (days)</label><input class="fi" id="edit-expiry" type="number" min="0" step="1" placeholder="0 = ∞"></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:8px">
      <button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center" data-en="Save" data-fa="ذخیره">Save</button>
      <button class="btn btn-danger" onclick="resetTraffic()" data-en="Reset Traffic" data-fa="ریست ترافیک">Reset Traffic</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="qr-modal" onclick="if(event.target===this)closeModal('qr-modal')">
  <div class="modal" style="max-width:320px">
    <button class="modal-x" onclick="closeModal('qr-modal')">✕</button>
    <div class="modal-title" data-en="QR Code" data-fa="کد QR">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <button class="btn btn-ghost" onclick="closeModal('qr-modal')" style="width:100%;justify-content:center;margin-top:14px" data-en="Close" data-fa="بستن">Close</button>
  </div>
</div>

<div class="modal-bg" id="addr-modal" onclick="if(event.target===this)closeModal('addr-modal')">
  <div class="modal">
    <button class="modal-x" onclick="closeModal('addr-modal')">✕</button>
    <div class="modal-title" data-en="Add Clean IP" data-fa="افزودن آی‌پی تمیز">Add Clean IP</div>
    <div class="fg"><label class="fl" data-en="IPs or domains (one per line)" data-fa="آی‌پی یا دامنه (هر خط یکی)">IPs or domains (one per line)</label><textarea class="fi" id="addr-input" rows="5" style="resize:vertical;font-family:var(--font-mono)" placeholder="1.1.1.1&#10;cf.example.com"></textarea></div>
    <button class="btn btn-primary" onclick="addAddrs()" style="width:100%;justify-content:center" data-en="Add All" data-fa="افزودن همه">Add All</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
/* ================= STATE (persisted via localStorage) ================= */
var LS=window.localStorage;
function lsGet(k,d){try{var v=LS.getItem(k);return v==null?d:v}catch(e){return d}}
function lsSet(k,v){try{LS.setItem(k,v)}catch(e){}}
var state={design:lsGet('app_design','aurum'),theme:lsGet('app_theme','dark'),lang:lsGet('app_lang','en'),filter:'all'};
var GB=1073741824;
function logoSVG(size){return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 56 56" fill="none"><rect width="56" height="56" rx="14" fill="url(#lg)"/><circle class="logo-spin" cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.35"/><circle cx="28" cy="18" r="3.5" fill="#fff"/><circle cx="19" cy="33" r="3.5" fill="#fff"/><circle cx="37" cy="33" r="3.5" fill="#fff"/><line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/><line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/><line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/><circle cx="28" cy="28" r="2" fill="#fff"/><defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="var(--primary)"/><stop offset="1" stop-color="var(--primary2)"/></linearGradient></defs></svg>'}

var links=[];var addresses=[];var customDomain='';var renderDomain='';
var stats={total_requests:0,active_connections:0,uptime:'--',cpu_percent:0,memory_percent:0,total_traffic_mb:0,links_count:0,domain:'',hourly_traffic:{}};

var DESIGNS=[
 {id:'core',en:'CORE Classic',fa:'کلاسیک CORE',den:'Signature crimson — sharp & clean',dfa:'قرمز کلاسیک CORE، تیز و تمیز'},
 {id:'aurora',en:'Aurora Glass',fa:'شیشه‌ای آرورا',den:'Frosted glass, aurora gradients, soft glow',dfa:'شیشه‌ای مات، گرادینت آرورا، درخشش نرم'},
 {id:'aurum',en:'Aurum',fa:'اروم',den:'Obsidian & gold, cursor spotlight, minimal luxe',dfa:'ابسیدین و طلا، نورافکنِ دنبال‌کن، مینیمال لاکچری'},
 {id:'nexus',en:'Nexus',fa:'نکسوس',den:'Live network constellation + holographic accents',dfa:'کهکشانِ شبکه‌ی زنده + جلوه‌های هولوگرافیک'}
];

var NAV=[
 {sec:{en:'Main',fa:'اصلی'}},
 {id:'dashboard',en:'Dashboard',fa:'داشبورد',ico:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>'},
 {id:'inbounds',en:'Inbounds',fa:'اینباندها',badge:true,ico:'<path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/>'},
 {id:'traffic',en:'Traffic',fa:'ترافیک',ico:'<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'},
 {id:'cleanip',en:'Clean IP',fa:'آی‌پی تمیز',ico:'<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>'},
 {id:'domain',en:'Domain',fa:'دامنه',ico:'<path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>'},
 {sec:{en:'System',fa:'سیستم'}},
 {id:'backup',en:'Backup',fa:'پشتیبان',ico:'<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>'},
 {id:'security',en:'Security',fa:'امنیت',ico:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>'},
 {id:'settings',en:'Settings',fa:'تنظیمات',ico:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>'}
];

var $=function(s){return document.querySelector(s)};
var $$=function(s){return document.querySelectorAll(s)};

/* ================= i18n ================= */
function t(en,fa){return state.lang==='fa'?fa:en}
function applyLang(){
  document.body.dir=state.lang==='fa'?'rtl':'ltr';
  document.documentElement.lang=state.lang;
  $$('[data-en]').forEach(function(el){var v=el.getAttribute('data-'+state.lang);if(v!=null)el.textContent=v});
  $$('[data-en-ph]').forEach(function(el){var v=el.getAttribute('data-'+state.lang+'-ph');if(v!=null)el.placeholder=v});
  $$('[data-lang]').forEach(function(b){b.classList.toggle('active',b.dataset.lang===state.lang)});
  var ll=$('#lc-lang');if(ll)ll.textContent=state.lang.toUpperCase();
}
function setLang(l){state.lang=l;lsSet('app_lang',l);applyLang();renderAll()}
function cycleLang(){setLang(state.lang==='en'?'fa':'en')}

/* ================= theme / design ================= */
function themeIcon(){return state.theme==='dark'
  ?'<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4"/></svg>'
  :'<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1111.2 3 7 7 0 0021 12.8z"/></svg>'}
function setTheme(th){state.theme=th;lsSet('app_theme',th);document.documentElement.setAttribute('data-theme',th);
  var tb=$('#theme-btn');if(tb)tb.innerHTML=themeIcon();var lt=$('#lc-theme');if(lt)lt.innerHTML=themeIcon();
  $$('#theme-seg button').forEach(function(b){b.classList.toggle('active',b.dataset.th===th)})}
function toggleTheme(){setTheme(state.theme==='dark'?'light':'dark')}
function designName(id){var d=DESIGNS.find(function(x){return x.id===id});return d?t(d.en,d.fa):id}
function setDesign(d){state.design=d;lsSet('app_design',d);document.documentElement.setAttribute('data-design',d);
  $$('.mini-d').forEach(function(m){m.classList.toggle('active',m.dataset.d===d)});
  $$('.design-opt').forEach(function(o){o.classList.toggle('active',o.dataset.d===d)});
  if(d==='nexus')nexusStart();else nexusStop();}
function cycleDesign(){var i=DESIGNS.findIndex(function(x){return x.id===state.design});setDesign(DESIGNS[(i+1)%DESIGNS.length].id);toast(t('Design: ','دیزاین: ')+designName(state.design))}

/* ================= sidebar/nav ================= */
function buildNav(){
  var el=$('#nav');if(!el)return;var h='';
  NAV.forEach(function(n){
    if(n.sec){h+='<div class="nav-sec">'+t(n.sec.en,n.sec.fa)+'</div>';return}
    h+='<button class="nav-item'+(n.id==='dashboard'?' active':'')+'" data-page="'+n.id+'" onclick="switchPage(\''+n.id+'\')">'
      +'<svg class="nav-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+n.ico+'</svg>'
      +'<span data-en="'+n.en+'" data-fa="'+n.fa+'">'+t(n.en,n.fa)+'</span>'
      +(n.badge?'<span class="nav-badge" id="nav-badge">'+links.length+'</span>':'')+'</button>';
  });
  el.innerHTML=h;
}
function switchPage(id){
  $$('.page').forEach(function(p){p.classList.remove('active')});
  var el=$('#page-'+id);if(el)el.classList.add('active');
  $$('.nav-item').forEach(function(n){n.classList.toggle('active',n.dataset.page===id)});
  if(window.innerWidth<=860)closeSidebar();
  if(id==='dashboard')setTimeout(renderChart,60);
}
function toggleSidebar(){$('#sidebar').classList.toggle('open');$('#sb-overlay').classList.toggle('show')}
function closeSidebar(){$('#sidebar').classList.remove('open');$('#sb-overlay').classList.remove('show')}
function buildMiniDesigns(){var el=$('#mini-designs');if(!el)return;el.innerHTML=DESIGNS.map(function(d){return '<div class="mini-d md-'+d.id+(d.id===state.design?' active':'')+'" data-d="'+d.id+'" title="'+d.en+'" onclick="setDesign(\''+d.id+'\')"></div>'}).join('')}
function buildDesignGrid(){var el=$('#design-grid');if(!el)return;el.innerHTML=DESIGNS.map(function(d){return '<div class="design-opt'+(d.id===state.design?' active':'')+'" data-d="'+d.id+'" onclick="setDesign(\''+d.id+'\')"><div class="d-check">✓</div><div class="swatch sw-'+d.id+'"></div><div class="d-name">'+d.en+'</div><div class="d-desc" data-en="'+d.den+'" data-fa="'+d.dfa+'">'+t(d.den,d.dfa)+'</div></div>'}).join('')}

/* ================= format ================= */
function fmtBytes(b){b=b||0;return b>=GB?(b/GB).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(1)+' MB':(b/1024).toFixed(0)+' KB'}
function fmtLimit(b){if(!b)return t('Unlimited','نامحدود');var g=b/GB;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB'}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}

/* ================= toast ================= */
var toastTimer;
function toast(msg,err){var el=$('#toast');if(!el)return;el.textContent=msg;el.className='toast'+(err?' err':'')+' show';clearTimeout(toastTimer);toastTimer=setTimeout(function(){el.classList.remove('show')},2600)}

/* ================= fetch helper ================= */
function api(url,opts){opts=opts||{};return fetch(url,opts).then(function(r){if(r.status===401){location.href='/login';throw new Error('unauth')}return r})}
function jpost(url,obj,method){return api(url,{method:method||'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj||{})})}

/* ================= data loads ================= */
function loadStats(){api('/stats').then(function(r){if(!r.ok)throw 0;return r.json()}).then(function(d){stats=d;renderStats();renderChart();renderDomainInfo()}).catch(function(){})}
function loadLinks(){api('/api/links').then(function(r){return r.json()}).then(function(d){links=d.links||[];renderLinks()}).catch(function(){})}
function loadAddresses(){api('/api/addresses').then(function(r){return r.json()}).then(function(d){addresses=d.addresses||[];renderAddresses()}).catch(function(){})}
function loadDomain(){api('/api/domain').then(function(r){return r.json()}).then(function(d){customDomain=d.domain||'';renderDomainInfo()}).catch(function(){})}

/* ================= stats render ================= */
function statIco(p){return '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+p+'</svg>'}
function renderStats(){
  var sc=$('#stat-cards');if(!sc)return;
  var cards=[
    {label:t('Traffic','ترافیک'),val:(stats.total_traffic_mb||0).toLocaleString()+'<span class="stat-unit"> MB</span>',ico:'<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'},
    {label:t('Inbounds','اینباندها'),val:(stats.links_count!=null?stats.links_count:links.length),ico:'<circle cx="9" cy="7" r="4"/><path d="M17 21v-2a4 4 0 00-3-3.87"/>'},
    {label:t('Uptime','آپتایم'),val:'<span style="font-size:20px">'+(stats.uptime||'--')+'</span>',ico:'<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>'},
    {label:t('Connections','اتصالات'),val:(stats.active_connections||0),ico:'<path d="M5 12.55a11 11 0 0114 0M8.5 16.1a6 6 0 017 0M2 8.8a16 16 0 0120 0"/><line x1="12" y1="20" x2="12" y2="20"/>'}
  ];
  sc.innerHTML=cards.map(function(c){return '<div class="stat"><div class="stat-ico">'+statIco(c.ico)+'</div><div class="stat-label">'+c.label+'</div><div class="stat-value">'+c.val+'</div></div>'}).join('');
  var cpu=stats.cpu_percent||0,mem=stats.memory_percent||0;
  var cc=cpu>80?'var(--red)':cpu>50?'var(--yellow)':'var(--primary)';
  if($('#cpu-val')){$('#cpu-val').textContent=cpu.toFixed(1)+'%';$('#cpu-val').style.color=cc;$('#cpu-bar').style.width=cpu+'%'}
  if($('#mem-val')){$('#mem-val').textContent=mem.toFixed(1)+'%';$('#mem-bar').style.width=mem+'%'}
  if($('#last-update'))$('#last-update').textContent=t('Updated: ','بروزرسانی: ')+new Date().toLocaleTimeString(state.lang==='fa'?'fa-IR':'en-US');
  var nb=$('#nav-badge');if(nb)nb.textContent=(stats.links_count!=null?stats.links_count:links.length);
  if($('#t-traffic'))$('#t-traffic').textContent=(stats.total_traffic_mb||0).toLocaleString()+' MB';
  if($('#t-reqs'))$('#t-reqs').textContent=(stats.total_requests||0).toLocaleString();
  if($('#t-conns'))$('#t-conns').textContent=(stats.active_connections||0);
  if($('#t-uptime'))$('#t-uptime').textContent=(stats.uptime||'--');
  var ti=$('#top-inbounds');
  if(ti){var top=links.slice().sort(function(a,b){return (b.used_bytes||0)-(a.used_bytes||0)}).slice(0,5);
    ti.innerHTML=top.map(function(l){var pct=l.limit_bytes>0?Math.min(100,l.used_bytes/l.limit_bytes*100):Math.min(100,(l.used_bytes||0)/(2*GB)*100);
      return '<div style="padding:9px 0;border-bottom:1px solid var(--border)"><div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:6px"><span style="font-weight:600">'+esc(l.label)+'</span><span style="color:var(--text3)">'+fmtBytes(l.used_bytes)+'</span></div><div class="usepill"><div class="bar"><div class="fill" style="width:'+pct+'%;background:linear-gradient(90deg,var(--primary),var(--primary2))"></div></div></div></div>'}).join('')||('<div style="color:var(--text3);font-size:12.5px;padding:6px 0">'+t('No data','داده‌ای نیست')+'</div>');
  }
}
function renderInbSummary(){var el=$('#inb-summary');if(!el)return;var act=0;links.forEach(function(l){if(l.active)act++});var dis=links.length-act;
  function c(dc,label,val){return '<div class="inb-chip"><span class="dot" style="background:'+dc+'"></span>'+label+' <b>'+val+'</b></div>'}
  el.innerHTML=c('var(--primary)',t('Total','کل'),links.length)+c('var(--green)',t('Active','فعال'),act)+c('var(--red)',t('Disabled','غیرفعال'),dis)+'<div class="inb-chip">'+t('Traffic','ترافیک')+' <b>'+(stats.total_traffic_mb||0).toLocaleString()+' MB</b></div>';}

/* ================= chart (self-contained) ================= */
function renderChart(){
  var el=$('#chart');if(!el)return;var ht=stats.hourly_traffic||{};var keys=Object.keys(ht).sort().slice(-12);
  var vals=keys.map(function(k){return Math.round(ht[k]/1048576)});
  if(!keys.length){el.innerHTML='<div style="margin:auto;color:var(--text3);font-size:12.5px">'+t('No traffic yet','هنوز ترافیکی نیست')+'</div>';return}
  var maxv=Math.max.apply(null,vals.concat([1]));
  el.innerHTML=keys.map(function(k,i){var h=Math.max(4,Math.round(vals[i]/maxv*100));return '<div class="col"><div class="barwrap"><div class="bar" data-v="'+vals[i]+'" data-h="'+h+'" style="height:0"></div></div><div class="xl">'+k+'</div></div>'}).join('');
  requestAnimationFrame(function(){el.querySelectorAll('.bar').forEach(function(b,i){setTimeout(function(){b.style.height=b.dataset.h+'%'},i*45)})});
}

/* ================= links ================= */
function setFilter(f,el){state.filter=f;$$('.chip').forEach(function(c){c.classList.remove('active')});el.classList.add('active');renderLinks()}
function daysLeft(exp){if(!exp)return null;var d=Math.ceil((new Date(exp).getTime()-Date.now())/86400000);return d}
function renderLinks(){
  renderInbSummary();
  var sb=$('#search');var q=(sb&&sb.value||'').toLowerCase();
  var list=links.filter(function(l){
    if(state.filter==='active'&&!l.active)return false;
    if(state.filter==='disabled'&&l.active)return false;
    if(q&&l.label.toLowerCase().indexOf(q)<0&&String(l.uuid).toLowerCase().indexOf(q)<0)return false;
    return true;
  });
  var body=$('#links-body'),empty=$('#links-empty');if(!body)return;
  if(!list.length){body.innerHTML='';if(empty)empty.style.display='block';return}
  if(empty)empty.style.display='none';
  body.innerHTML=list.map(function(l,i){
    var pct=l.limit_bytes>0?Math.min(100,l.used_bytes/l.limit_bytes*100):0;
    var col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    var mc=l.max_connections||0,cc=l.current_connections||0;
    var ipcol=mc>0&&cc>=mc?'var(--red)':'var(--text2)';
    var exp='';
    if(l.expired)exp='<div style="font-size:10px;font-weight:600;color:var(--red);margin-top:2px">'+t('expired','منقضی')+'</div>';
    else{var dl=daysLeft(l.expiry);if(dl!=null&&dl>=0)exp='<div style="font-size:10px;font-weight:500;color:var(--text3);margin-top:2px">⏳ '+dl+'d</div>';}
    var hue=0;var lab=l.label||'';for(var k=0;k<lab.length;k++)hue+=lab.charCodeAt(k);hue=(hue*47)%360;
    var mono='<div class="mono" style="background:hsl('+hue+' 58% 46%)">'+esc((lab.charAt(0)||'?').toUpperCase())+'</div>';
    var pctTxt=l.limit_bytes>0?'<span class="pct">'+pct.toFixed(0)+'%</span>':'';
    var vl=esc(l.vless_link||'');
    return '<tr>'
      +'<td class="col-id" style="color:var(--text3);font-size:11px">'+(i+1)+'</td>'
      +'<td class="stripe" style="border-inline-start-color:'+(l.active?'var(--green)':'var(--red)')+'"><div class="remark-cell">'+mono+'<div><div class="rk-name">'+esc(l.label)+'</div>'+exp+'</div></div></td>'
      +'<td class="col-type"><span class="tag tag-vless">VLESS</span></td>'
      +'<td><div class="usepill"><span class="used">'+fmtBytes(l.used_bytes)+'</span><div class="bar"><div class="fill" style="width:'+pct+'%;background:'+col+'"></div></div><span>'+fmtLimit(l.limit_bytes)+'</span>'+pctTxt+'</div></td>'
      +'<td class="col-ips" style="font-weight:700;color:'+ipcol+'">'+cc+'/'+(mc||'∞')+'</td>'
      +'<td><span class="tag '+(l.active?'tag-on':'tag-off')+'">'+(l.active?'ON':'OFF')+'</span></td>'
      +'<td><div class="actions">'
        +'<div class="toggle '+(l.active?'on':'')+'" onclick="toggleLink(\''+l.uuid+'\')" title="Toggle"></div>'
        +'<button class="act a-edit" onclick="openEdit(\''+l.uuid+'\')" title="Edit"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.1 2.1 0 013 3L12 15l-4 1 1-4z"/></svg></button>'
        +'<button class="act a-copy" onclick="copyText(\''+vl+'\')" title="Copy config"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>'
        +'<button class="act a-sub" onclick="copySub(\''+l.uuid+'\')" title="Subscription"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 019 9M4 4a16 16 0 0116 16"/><circle cx="5" cy="19" r="1"/></svg></button>'
        +'<button class="act a-qr" onclick="showQR(\''+vl+'\')" title="QR"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><line x1="14" y1="14" x2="14" y2="21"/><line x1="21" y1="14" x2="21" y2="21"/><line x1="17.5" y1="17.5" x2="17.5" y2="17.5"/></svg></button>'
        +'<button class="act a-del" onclick="delLink(\''+l.uuid+'\')" title="Delete"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6M10 11v6M14 11v6"/></svg></button>'
      +'</div></td></tr>';
  }).join('');
}
function toggleLink(uid){var l=links.find(function(x){return x.uuid===uid});if(!l)return;jpost('/api/links/'+encodeURIComponent(uid),{active:!l.active},'PATCH').then(function(){loadLinks();loadStats()}).catch(function(){})}
function delLink(uid){if(!confirm(t('Delete this inbound?','این اینباند حذف شود؟')))return;api('/api/links/'+encodeURIComponent(uid),{method:'DELETE'}).then(function(){loadLinks();loadStats();toast(t('Deleted','حذف شد'))}).catch(function(){})}
function quickCreate(gb){var names=['Ali','Sara','Reza','Nima','Mina','Arash','Yalda','Kian','Roya','Omid'];var nm=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*90+10);jpost('/api/links',{label:nm,limit_value:gb,limit_unit:'GB'}).then(function(r){if(!r.ok)throw 0;loadLinks();loadStats();toast(t('Created: ','ساخته شد: ')+nm)}).catch(function(){toast(t('Error','خطا'),true)})}
function createLink(){var label=($('#add-label').value||'').trim();if(!label){toast(t('Name required','نام لازم است'),true);return}var lim=parseFloat($('#add-limit').value)||0;var mc=parseInt($('#add-maxconn').value)||0;var ex=parseInt($('#add-expiry').value)||0;
  jpost('/api/links',{label:label,limit_value:lim,limit_unit:'GB',max_connections:mc,expiry_days:ex}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d}})}).then(function(x){if(!x.ok)throw new Error(x.d.detail||'err');$('#add-label').value='';$('#add-limit').value='';$('#add-maxconn').value='';$('#add-expiry').value='';closeModal('add-modal');loadLinks();loadStats();toast(t('Created','ساخته شد'))}).catch(function(e){toast(e.message||t('Error','خطا'),true)})}
function openEdit(uid){var l=links.find(function(x){return x.uuid===uid});if(!l)return;$('#edit-uid').value=uid;$('#edit-name').value=l.label;$('#edit-limit').value=l.limit_bytes>0?(l.limit_bytes/GB):'';$('#edit-maxconn').value=l.max_connections>0?l.max_connections:'';var dl=daysLeft(l.expiry);$('#edit-expiry').value=(dl!=null&&dl>0)?dl:'';$('#edit-title').textContent=t('Edit: ','ویرایش: ')+l.label;openModal('edit-modal')}
function saveEdit(){var uid=$('#edit-uid').value;var body={limit_value:parseFloat($('#edit-limit').value)||0,limit_unit:'GB',max_connections:parseInt($('#edit-maxconn').value)||0};var ex=$('#edit-expiry').value;if(ex!=='')body.expiry_days=parseInt(ex)||0;jpost('/api/links/'+encodeURIComponent(uid),body,'PATCH').then(function(r){if(!r.ok)throw 0;closeModal('edit-modal');loadLinks();toast(t('Updated','بروزرسانی شد'))}).catch(function(){toast(t('Error','خطا'),true)})}
function resetTraffic(){var uid=$('#edit-uid').value;if(!confirm(t('Reset traffic to zero?','ترافیک صفر شود؟')))return;jpost('/api/links/'+encodeURIComponent(uid),{reset_usage:true},'PATCH').then(function(){loadLinks();loadStats();toast(t('Traffic reset','ترافیک ریست شد'))}).catch(function(){})}

/* ================= clipboard / qr ================= */
function copyText(txt){navigator.clipboard.writeText(txt).then(function(){toast(t('Copied','کپی شد'))}).catch(function(){toast(t('Copy failed','کپی نشد'),true)})}
function copySub(uid){copyText(location.origin+'/sub/'+encodeURIComponent(uid));toast(t('Subscription URL copied','لینک ساب کپی شد'))}
function showQR(txt){if(!txt)return;$('#qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(txt);openModal('qr-modal')}

/* ================= addresses ================= */
function renderAddresses(){var el=$('#addr-list');if(!el)return;
  if(!addresses.length){el.innerHTML='<div style="color:var(--text3);font-size:12.5px;padding:6px 0">'+t('No addresses added','آدرسی اضافه نشده')+'</div>';return}
  el.innerHTML=addresses.map(function(a,i){return '<div style="display:flex;align-items:center;justify-content:space-between;padding:11px 13px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radiussm)"><div style="display:flex;align-items:center;gap:11px"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15 15 0 010 20 15 15 0 010-20z"/></svg><div><div style="font-size:13px;font-weight:600;font-family:var(--font-mono)">'+esc(a)+'</div><div style="font-size:10px;color:var(--text3)">#'+(i+1)+'</div></div></div><button class="act a-del" onclick="delAddr('+i+')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/></svg></button></div>'}).join('');}
function addAddrs(){var txt=($('#addr-input').value||'').trim();if(!txt){toast(t('Enter an IP or domain','یک آی‌پی یا دامنه وارد کن'),true);return}var lines=txt.split('\n').map(function(x){return x.trim()}).filter(Boolean);
  var chain=Promise.resolve();var added=0;lines.forEach(function(a){chain=chain.then(function(){return jpost('/api/addresses',{address:a}).then(function(r){if(r.ok)added++}).catch(function(){})})});
  chain.then(function(){$('#addr-input').value='';closeModal('addr-modal');loadAddresses();toast(t('Added ','افزوده شد ')+added)})}
function delAddr(i){if(!confirm(t('Delete this address?','این آدرس حذف شود؟')))return;api('/api/addresses/'+i,{method:'DELETE'}).then(function(){loadAddresses();toast(t('Deleted','حذف شد'))}).catch(function(){})}

/* ================= domain ================= */
function renderDomainInfo(){renderDomain=stats.domain||location.host;var el=$('#domain-cur');if(!el)return;el.textContent=customDomain?customDomain:renderDomain+' ('+t('default','پیش‌فرض')+')';el.style.color=customDomain?'var(--green)':'var(--text2)'}
function saveDomain(){var d=($('#domain-input').value||'').trim();if(!d){toast(t('Enter a domain','یک دامنه وارد کن'),true);return}jpost('/api/domain',{domain:d}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){if(!x.ok)throw new Error(x.j.detail||'err');$('#domain-input').value='';loadDomain();loadLinks();toast(t('Domain saved','دامنه ذخیره شد'))}).catch(function(e){toast(e.message||t('Error','خطا'),true)})}
function clearDomain(){jpost('/api/domain',{domain:''}).then(function(){loadDomain();loadLinks();toast(t('Domain cleared','دامنه پاک شد'))}).catch(function(){})}

/* ================= security ================= */
function changePw(){var c=$('#cur-pw').value,n=$('#new-pw').value;if(!c||!n){toast(t('Fill all fields','همه فیلدها را پر کن'),true);return}jpost('/api/change-password',{current_password:c,new_password:n}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){if(!x.ok)throw new Error(x.j.detail||'err');$('#cur-pw').value='';$('#new-pw').value='';toast(t('Password updated','رمز بروزرسانی شد'))}).catch(function(e){toast(e.message||t('Error','خطا'),true)})}

/* ================= backup / restore ================= */
function exportBackup(){window.location.href='/api/backup';toast(t('Backup downloaded','پشتیبان دانلود شد'))}
function importBackup(ev){var f=ev.target.files&&ev.target.files[0];if(!f)return;var rd=new FileReader();rd.onload=function(){var payload;try{payload=JSON.parse(rd.result)}catch(e){toast(t('Invalid backup file','فایل پشتیبان نامعتبر'),true);return}
  api('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){if(!x.ok)throw new Error(x.j.detail||'err');loadLinks();loadAddresses();loadDomain();loadStats();switchPage('inbounds');toast(t('Restored ','بازیابی شد ')+(x.j.imported||0)+t(' inbounds',' اینباند'))}).catch(function(e){toast(e.message||t('Import failed','ایمپورت ناموفق'),true)})};rd.readAsText(f);ev.target.value=''}

/* ================= modals ================= */
function openModal(id){$('#'+id).classList.add('show')}
function closeModal(id){$('#'+id).classList.remove('show')}

/* ================= nexus constellation ================= */
var nexus={c:null,ctx:null,nodes:[],raf:0,w:0,h:0,mx:-999,my:-999};
function nexusResize(){var c=nexus.c;if(!c)return;nexus.w=c.width=c.clientWidth||window.innerWidth;nexus.h=c.height=c.clientHeight||window.innerHeight}
function nexusInit(){nexus.c=$('#nexus-canvas');if(!nexus.c)return;nexus.ctx=nexus.c.getContext('2d');nexusResize();var count=Math.max(28,Math.min(74,Math.floor(nexus.w*nexus.h/17000)));nexus.nodes=[];for(var i=0;i<count;i++){nexus.nodes.push({x:Math.random()*nexus.w,y:Math.random()*nexus.h,vx:(Math.random()-0.5)*0.35,vy:(Math.random()-0.5)*0.35})}}
function nexusStep(){var ctx=nexus.ctx;if(!ctx)return;var ns=nexus.nodes,W=nexus.w,H=nexus.h;ctx.clearRect(0,0,W,H);
  var light=state.theme==='light';var line=light?'80,90,200':'150,165,255';var dot=light?'rgba(90,100,205,0.7)':'rgba(170,192,255,0.9)';
  for(var i=0;i<ns.length;i++){var p=ns[i];p.x+=p.vx;p.y+=p.vy;if(p.x<0){p.x=0;p.vx*=-1}else if(p.x>W){p.x=W;p.vx*=-1}if(p.y<0){p.y=0;p.vy*=-1}else if(p.y>H){p.y=H;p.vy*=-1}
    var dxm=p.x-nexus.mx,dym=p.y-nexus.my,dm=Math.sqrt(dxm*dxm+dym*dym);if(dm<130&&dm>0.5){var f=(130-dm)/130*0.9;p.x+=dxm/dm*f;p.y+=dym/dm*f}}
  for(var i=0;i<ns.length;i++){for(var j=i+1;j<ns.length;j++){var a=ns[i],b=ns[j];var dx=a.x-b.x,dy=a.y-b.y,d=Math.sqrt(dx*dx+dy*dy);if(d<128){var al=(1-d/128)*0.42;ctx.strokeStyle='rgba('+line+','+al+')';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke()}}}
  ctx.fillStyle=dot;for(var i=0;i<ns.length;i++){var p=ns[i];ctx.beginPath();ctx.arc(p.x,p.y,1.6,0,6.2832);ctx.fill()}
  nexus.raf=requestAnimationFrame(nexusStep)}
function nexusStart(){if(nexus.raf)return;nexusInit();if(!nexus.c)return;nexus.raf=requestAnimationFrame(nexusStep)}
function nexusStop(){if(nexus.raf){cancelAnimationFrame(nexus.raf);nexus.raf=0}if(nexus.ctx)nexus.ctx.clearRect(0,0,nexus.w,nexus.h)}
window.addEventListener('resize',function(){if(state.design==='nexus')nexusResize()});
window.addEventListener('mousemove',function(e){nexus.mx=e.clientX;nexus.my=e.clientY;var r=document.documentElement;r.style.setProperty('--sx',e.clientX+'px');r.style.setProperty('--sy',e.clientY+'px')});
window.addEventListener('mouseout',function(){nexus.mx=-999;nexus.my=-999});

/* ================= auth / init ================= */
function doLogin(e){e.preventDefault();var pw=$('#login-pw').value;jpost('/api/login',{password:pw}).then(function(r){if(!r.ok)throw new Error('bad');location.href='/dashboard'}).catch(function(){toast(t('Invalid password','رمز اشتباه است'),true)})}
function doLogout(){fetch('/api/logout',{method:'POST'}).then(function(){location.href='/login'})}
function initApp(){var ls=$('#login-screen');if(ls)ls.style.display='none';var lc=$('#login-controls');if(lc)lc.style.display='none';$('#app').classList.add('on');
  loadStats();loadLinks();loadAddresses();loadDomain();setInterval(loadStats,10000);if(state.design==='nexus')setTimeout(nexusStart,60)}
function renderAll(){buildNav();buildMiniDesigns();buildDesignGrid();renderStats();renderLinks();renderAddresses();renderDomainInfo();renderChart();applyLang()}
function init(){
  var ll=$('#login-logo');if(ll)ll.innerHTML=logoSVG(58);
  var bl=$('#brand-logo');if(bl)bl.innerHTML=logoSVG(30);
  document.documentElement.setAttribute('data-design',state.design);
  document.documentElement.setAttribute('data-theme',state.theme);
  setDesign(state.design);setTheme(state.theme);
  buildNav();buildMiniDesigns();buildDesignGrid();applyLang();
  if(location.pathname.indexOf('/dashboard')>=0){initApp()}
  else{if(state.design==='nexus')setTimeout(nexusStart,60)}
}
init();

</script>
</body>
</html>
"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=PANEL_HTML)

@app.get("/api/backup")
async def export_backup(_=Depends(require_auth)):
    async with LINKS_LOCK:
        links_copy = {k: dict(v) for k, v in LINKS.items()}
    async with CUSTOM_ADDRESSES_LOCK:
        addrs = list(CUSTOM_ADDRESSES)
    async with CUSTOM_DOMAIN_LOCK:
        dom = CUSTOM_DOMAIN
    data = {"version": 1, "app": "CORE", "exported_at": datetime.now().isoformat(), "links": links_copy, "addresses": addrs, "domain": dom}
    content = json.dumps(data, ensure_ascii=False, indent=2)
    headers = {"Content-Disposition": 'attachment; filename="backup.json"'}
    return Response(content=content, headers=headers, media_type="application/json")


@app.post("/api/import")
async def import_backup(request: Request, _=Depends(require_auth)):
    global CUSTOM_DOMAIN
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    if not isinstance(body, dict) or not isinstance(body.get("links"), dict):
        raise HTTPException(status_code=400, detail="Invalid backup file")
    clean = {}
    for uid, v in body["links"].items():
        if not isinstance(v, dict):
            continue
        try:
            clean[str(uid)] = {
                "label": str(v.get("label") or uid)[:60],
                "limit_bytes": int(float(v.get("limit_bytes") or 0)),
                "used_bytes": int(float(v.get("used_bytes") or 0)),
                "max_connections": int(v.get("max_connections") or 0),
                "created_at": v.get("created_at") or datetime.now().isoformat(),
                "active": bool(v.get("active", True)),
                "expiry": v.get("expiry") or "",
            }
        except (TypeError, ValueError):
            continue
    async with LINKS_LOCK:
        LINKS.clear()
        LINKS.update(clean)
    addrs = body.get("addresses")
    if isinstance(addrs, list):
        async with CUSTOM_ADDRESSES_LOCK:
            CUSTOM_ADDRESSES.clear()
            CUSTOM_ADDRESSES.extend([str(a) for a in addrs])
    dom = body.get("domain")
    if isinstance(dom, str):
        async with CUSTOM_DOMAIN_LOCK:
            CUSTOM_DOMAIN = dom
    return {"ok": True, "imported": len(clean)}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
