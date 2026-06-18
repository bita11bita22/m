"""
پنل مدیریت XRAY — FastAPI + Nginx + Reality + Sub Page + Edit User + Restore
"""
import os, json, uuid, asyncio, hashlib, secrets, time, subprocess, re, base64
from datetime import datetime
from collections import deque
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
import uvicorn

# ── تنظیمات ──────────────────────────────────────────────
PORT         = 5000
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "admin1234")
ADMIN_PATH   = os.environ.get("ADMIN_PATH", "panel").strip("/")
PUBLIC_HOST  = os.environ.get("PUBLIC_HOST", "")
XRAY_WS_PORT = 18080
XRAY_XH_PORT = 18081
MASTER_UUID  = os.environ.get("UUID", "90cd4a77-141a-43c9-991b-08263cfe9c10")
LINKS_FILE   = "/app/links.json"
CFG_FILE     = "/app/cfg.json"
XRAY_LOG     = "/tmp/xray_access.log"
NGINX_LOG    = "/tmp/nginx_access.log"
STATS_FILE   = "/app/stats.json"
XRAY_API_PORT = 10085

XRAY_GRPC_PORT = 18083
XRAY_HU_PORT   = 18084
XRAY_TJ_PORT   = 18085
XRAY_VM_PORT   = 18086

REALITY_PORT = int(os.environ.get("REALITY_PORT", 18443))
REALITY_DOMAIN = os.environ.get("REALITY_DOMAIN", "")
REALITY_PUBLIC_PORT = os.environ.get("REALITY_PUBLIC_PORT", "18443")
REALITY_SNI  = os.environ.get("REALITY_SNI", "yahoo.com")
XRAY_XH_INTERNAL_PORT = 18082

PASS_HASH = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()

# ── state ─────────────────────────────────────────────────
SESSIONS = {}
LINKS = {}
error_log = deque(maxlen=50)
stats = {"bytes": 0, "start": time.time()}
xray_process = None
xray_log_pos = 0
nginx_log_pos = 0
user_traffic = {}       
user_last_active = {}   
active_connections = {} 
total_unique_ips = set()
reality_keys = {"priv": "", "pub": ""}

def log_err(msg):
    error_log.append({"e": msg, "t": datetime.now().isoformat()})

# ── Xray Core Manager ────────────────────────────────────
def load_data():
    global LINKS, total_unique_ips, reality_keys, user_traffic, stats
    try:
        if os.path.exists(LINKS_FILE):
            with open(LINKS_FILE, "r") as f: LINKS = json.load(f)
    except: LINKS = {}
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, "r") as f:
                data = json.load(f)
                total_unique_ips = set(data.get("total_unique_ips", []))
                stats["bytes"] = data.get("bytes", 0)
                stats["start"] = data.get("start", time.time())
                user_traffic = data.get("user_traffic", {})
                if "reality_priv" in data:
                    reality_keys["priv"] = data["reality_priv"]
                    reality_keys["pub"] = data["reality_pub"]
    except: pass

    updated = False
    for uid, info in LINKS.items():
        if "short_id" not in info:
            info["short_id"] = secrets.token_hex(4)[:7]
            updated = True
        if "clean_ip" not in info:
            info["clean_ip"] = ""
            updated = True
    if updated: save_links()

def save_links():
    with open(LINKS_FILE, "w") as f: json.dump(LINKS, f)

def save_stats():
    with open(STATS_FILE, "w") as f:
        json.dump({
            "total_unique_ips": list(total_unique_ips), "bytes": stats["bytes"], "start": stats["start"],
            "user_traffic": user_traffic, "reality_priv": reality_keys["priv"], "reality_pub": reality_keys["pub"]
        }, f)

def generate_reality_keys():
    global reality_keys
    if not reality_keys["priv"]:
        try:
            result = subprocess.run(["/usr/local/bin/xray", "x25519"], capture_output=True, text=True, timeout=5)
            out = result.stdout
            if "PrivateKey:" in out: reality_keys["priv"] = out.split("PrivateKey:")[1].split("\n")[0].strip()
            elif "Private key:" in out: reality_keys["priv"] = out.split("Private key:")[1].split("\n")[0].strip()
            if "Password (PublicKey):" in out: reality_keys["pub"] = out.split("Password (PublicKey):")[1].split("\n")[0].strip()
            elif "PublicKey:" in out: reality_keys["pub"] = out.split("PublicKey:")[1].split("\n")[0].strip()
            elif "Public key:" in out: reality_keys["pub"] = out.split("Public key:")[1].split("\n")[0].strip()
            if reality_keys["priv"] and reality_keys["pub"]: save_stats()
        except Exception as e: log_err(str(e))

def sync_xray_config():
    global xray_process
    generate_reality_keys()
    
    active_links = {}
    reality_snis = set()
    for uid, info in LINKS.items():
        if info.get("status") == "expired": continue
        if info.get("expiry_time") and time.time() > info["expiry_time"]:
            info["status"] = "expired"; continue
        if info.get("data_limit") and user_traffic.get(uid, 0) >= info["data_limit"]:
            info["status"] = "expired"; continue
        active_links[uid] = info
        if info.get("sni"): reality_snis.add(info["sni"])
    
    save_links()
    if not reality_snis: reality_snis.add(REALITY_SNI)
    
    ws_xh_clients = [{"id": uid, "level": 0, "email": uid} for uid in active_links.keys()]
    reality_clients = [{"id": uid, "level": 0, "email": uid, "flow": "xtls-rprx-vision"} for uid in active_links.keys()]
    trojan_clients = [{"password": uid, "email": uid} for uid in active_links.keys()]
    vmess_clients = [{"id": uid, "level": 0, "email": uid, "alterId": 0} for uid in active_links.keys()]
    
    inbounds = [
        {"port": XRAY_WS_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}},
        {"port": XRAY_XH_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/xh", "mode": "auto"}}},
        {"port": XRAY_GRPC_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "grpc"}}},
        {"port": XRAY_HU_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "httpupgrade", "httpupgradeSettings": {"path": "/hu"}}},
        {"port": XRAY_TJ_PORT, "listen": "127.0.0.1", "protocol": "trojan", "settings": {"clients": trojan_clients}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/tj"}}},
        {"port": XRAY_VM_PORT, "listen": "127.0.0.1", "protocol": "vmess", "settings": {"clients": vmess_clients}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/vm"}}},
        {"port": XRAY_XH_INTERNAL_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/xh", "mode": "auto"}}}
    ]
    
    if reality_keys["priv"]:
        inbounds.append({
            "port": REALITY_PORT, "listen": "0.0.0.0", "protocol": "vless",
            "settings": {"clients": reality_clients, "decryption": "none", "fallbacks": [{"dest": "127.0.0.1:" + str(XRAY_XH_INTERNAL_PORT)}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": False, "dest": list(reality_snis)[0] + ":443", "xver": 0, "serverNames": list(reality_snis), "privateKey": reality_keys["priv"], "shortIds": ["", "0123456789abcdef"]}}
        })
    
    cfg = {
        "log": {"loglevel": "info", "access": XRAY_LOG}, "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "api": {"tag": "api_service", "services": ["HandlerService", "LoggerService", "StatsService"]},
        "inbounds": [{"listen": "127.0.0.1", "port": XRAY_API_PORT, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}, "tag": "api_in"}, *inbounds],
        "outbounds": [{"protocol": "freedom"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api_in"], "outboundTag": "api_service"}]}
    }
    
    with open(CFG_FILE, "w") as f: json.dump(cfg, f, indent=2)
    try:
        if xray_process:
            xray_process.terminate()
            try: xray_process.wait(timeout=2)
            except: xray_process.kill()
        if os.path.exists(XRAY_LOG): os.remove(XRAY_LOG)
        xray_process = subprocess.Popen(["/usr/local/bin/xray", "-config", CFG_FILE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e: log_err(str(e))

async def stats_updater():
    global xray_log_pos, nginx_log_pos
    await asyncio.sleep(3)
    while True:
        try:
            result = subprocess.run(["/usr/local/bin/xray", "api", "statsquery", "127.0.0.1:" + str(XRAY_API_PORT), "-reset"], capture_output=True, text=True, timeout=3)
            if result.stdout:
                data = json.loads(result.stdout)
                for stat in data.get("stat", []):
                    name  = stat.get("name", "")
                    value = int(stat.get("value", "0") or "0")
                    parts = name.split(">>>")
                    if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                        uid = parts[1]
                        if uid not in user_traffic: user_traffic[uid] = 0
                        user_traffic[uid] += value
                        stats["bytes"] += value
                        if value > 0: user_last_active[uid] = time.time()
            save_stats()
        except: pass

        try:
            if os.path.exists(NGINX_LOG):
                if os.path.getsize(NGINX_LOG) > 1 * 1024 * 1024:
                    open(NGINX_LOG, 'w').close()
                    nginx_log_pos = 0
                current_size = os.path.getsize(NGINX_LOG)
                if current_size < nginx_log_pos: nginx_log_pos = 0
                with open(NGINX_LOG, "r") as f:
                    f.seek(nginx_log_pos)
                    new_data = f.read()
                    nginx_log_pos = f.tell()
                for line in new_data.splitlines():
                    parts = line.strip().split()
                    if len(parts) == 2:
                        ip, b = parts[0], int(parts[1])
                        if ip and ip != "127.0.0.1": total_unique_ips.add(ip)
                        if b > 0: stats["bytes"] += b
        except: pass

        try:
            if os.path.exists(XRAY_LOG):
                if os.path.getsize(XRAY_LOG) > 5 * 1024 * 1024:
                    open(XRAY_LOG, 'w').close()
                    xray_log_pos = 0
                current_size = os.path.getsize(XRAY_LOG)
                if current_size < xray_log_pos: xray_log_pos = 0
                with open(XRAY_LOG, "r") as f:
                    f.seek(xray_log_pos)
                    new_data = f.read()
                    xray_log_pos = f.tell()
                
                # تشخیص هر نوع فرمت لاگ (با from یا بدون from)
                matches = re.findall(r'([0-9a-fA-F:.]+):\d+\s+accepted.*?email:\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', new_data, re.IGNORECASE)
                now_t = time.time()
                for ip, uid in matches:
                    if uid in LINKS:
                        if uid not in active_connections: active_connections[uid] = {}
                        if ip == "127.0.0.1":
                            active_connections[uid]["local"] = now_t
                        else:
                            active_connections[uid][ip] = now_t
                            total_unique_ips.add(ip)
                        user_last_active[uid] = now_t
        except: pass

        now = time.time()
        for uid in list(user_last_active.keys()):
            if now - user_last_active[uid] > 60: del user_last_active[uid]
        for uid in list(active_connections.keys()):
            for ip in list(active_connections[uid].keys()):
                if now - active_connections[uid][ip] > 60: del active_connections[uid][ip]
            if not active_connections[uid]: del active_connections[uid]
            
        needs_restart = False
        for uid, info in LINKS.items():
            if info.get("status") != "expired":
                if info.get("expiry_time") and time.time() > info["expiry_time"]: needs_restart = True
                if info.get("data_limit") and user_traffic.get(uid, 0) >= info["data_limit"]: needs_restart = True
        if needs_restart: sync_xray_config()
            
        await asyncio.sleep(5)

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_data()
    if MASTER_UUID not in LINKS:
        LINKS[MASTER_UUID] = {"label": "Master", "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "sni": REALITY_SNI, "status": "active", "short_id": secrets.token_hex(4)[:7], "clean_ip": ""}
        save_links()
    sync_xray_config()
    asyncio.create_task(stats_updater())
    yield
    if xray_process: xray_process.terminate()

app = FastAPI(docs_url=None, redoc_url=None, lifespan=lifespan)

# ── helpers ───────────────────────────────────────────────
def get_domain(request: Request) -> str:
    h = (PUBLIC_HOST or os.environ.get("RENDER_EXTERNAL_URL","") or os.environ.get("RAILWAY_PUBLIC_DOMAIN","") or request.headers.get("host","localhost"))
    return h.replace("https://","").replace("http://","").strip("/")

def make_links(uid: str, domain: str, label: str, sni: str, short_id: str, clean_ip: str = "") -> dict:
    addr = clean_ip if clean_ip else domain
    ws   = "vless://" + uid + "@" + addr + ":443?encryption=none&security=tls&type=ws&host=" + domain + "&path=%2Fws&sni=" + domain + "&fp=chrome#" + label + "-WS"
    xhttp = "vless://" + uid + "@" + addr + ":443?encryption=none&security=tls&type=xhttp&host=" + domain + "&path=%2Fxh&sni=" + domain + "&fp=chrome&mode=auto#" + label + "-XHTTP"
    grpc = "vless://" + uid + "@" + addr + ":443?encryption=none&security=tls&type=grpc&host=" + domain + "&serviceName=grpc&sni=" + domain + "&fp=chrome&mode=gun#" + label + "-gRPC"
    httpupgrade = "vless://" + uid + "@" + addr + ":443?encryption=none&security=tls&type=httpupgrade&host=" + domain + "&path=%2Fhu&sni=" + domain + "&fp=chrome#" + label + "-HTTPUpgrade"
    trojan = "trojan://" + uid + "@" + addr + ":443?security=tls&type=ws&host=" + domain + "&path=%2Ftj&sni=" + domain + "&fp=chrome#" + label + "-Trojan"
    vmess_json = json.dumps({"v":"2","ps":label+"-VMess","add":addr,"port":"443","id":uid,"aid":"0","scy":"auto","net":"ws","type":"none","host":domain,"path":"/vm","tls":"tls","sni":domain})
    vmess = "vmess://" + base64.b64encode(vmess_json.encode()).decode()
    
    user_sni = sni or REALITY_SNI
    reality = "خطا: REALITY_DOMAIN ست نشده"
    xhttp_reality = "خطا: REALITY_DOMAIN ست نشده"
    if REALITY_DOMAIN and reality_keys["pub"]:
        reality = "vless://" + uid + "@" + REALITY_DOMAIN + ":" + REALITY_PUBLIC_PORT + "?encryption=none&security=reality&sni=" + user_sni + "&fp=chrome&pbk=" + reality_keys['pub'] + "&sid=0123456789abcdef&type=tcp&flow=xtls-rprx-vision#" + label + "-Reality"
        xhttp_reality = "vless://" + uid + "@" + REALITY_DOMAIN + ":" + REALITY_PUBLIC_PORT + "?encryption=none&security=reality&sni=" + user_sni + "&fp=chrome&pbk=" + reality_keys['pub'] + "&sid=0123456789abcdef&type=xhttp&path=%2Fxh&mode=auto#" + label + "-XHTTP-Reality"
        
    all_links = [ws, xhttp, grpc, httpupgrade, trojan, vmess, reality, xhttp_reality]
    sub_link = "https://" + domain + "/sub/" + short_id
    sub_base64 = base64.b64encode("\n".join(all_links).encode()).decode()
    return {"ws": ws, "xhttp": xhttp, "grpc": grpc, "httpupgrade": httpupgrade, "trojan": trojan, "vmess": vmess, "reality": reality, "xhttp_reality": xhttp_reality, "sub_link": sub_link, "sub_base64": sub_base64}

def auth_check(token: Optional[str] = Cookie(None)) -> bool:
    if not token: return False
    return time.time() < SESSIONS.get(token, 0)

def uptime_str() -> str:
    s = int(time.time() - stats["start"]); h, r = divmod(s, 3600); m, sc = divmod(r, 60)
    return str(h).zfill(2) + ":" + str(m).zfill(2) + ":" + str(sc).zfill(2)

def fmt_bytes(b):
    if b < 1024: return str(b) + " B"
    if b < 1024**2: return str(round(b/1024, 1)) + " KB"
    if b < 1024**3: return str(round(b/1024**2, 2)) + " MB"
    return str(round(b/1024**3, 2)) + " GB"

# ── auth & api ───────────────────────────────────────────
@app.post("/api/login")
async def login(request: Request):
    d = await request.json()
    if hashlib.sha256(d.get("password","").encode()).hexdigest() != PASS_HASH: raise HTTPException(403, "رمز اشتباه است")
    token = secrets.token_urlsafe(32); SESSIONS[token] = time.time() + 86400
    r = JSONResponse({"ok": True}); r.set_cookie("token", token, httponly=True, samesite="lax", max_age=86400); return r

@app.post("/api/logout")
async def logout(token: Optional[str] = Cookie(None)):
    SESSIONS.pop(token, None); r = JSONResponse({"ok": True}); r.delete_cookie("token"); return r

@app.get("/api/stats")
async def api_stats(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    return {
        "total_users": len(LINKS), 
        "total_connected": len(total_unique_ips), 
        "active_uuids": len(user_last_active), 
        "active_ips": sum(len(ips) for ips in active_connections.values()), 
        "bytes": stats["bytes"], 
        "uptime": uptime_str()
    }

@app.get("/api/links")
async def api_links(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    domain = get_domain(request); out = []
    for uid, info in LINKS.items():
        conn_count = len(active_connections.get(uid, {}))
        data_limit = info.get("data_limit", 0)
        used_traffic = user_traffic.get(uid, 0)
        remaining_data = (data_limit - used_traffic) if data_limit else 0
        expiry_time = info.get("expiry_time", 0)
        remaining_days = max(0, int((expiry_time - time.time()) / 86400)) if expiry_time else 0
        out.append({
            "uuid": uid, "label": info["label"], "created_at": info["created_at"], 
            "online_ips": conn_count, "used_traffic": used_traffic, 
            "status": info.get("status", "active"),
            "data_limit": data_limit, "remaining_data": remaining_data,
            "remaining_days": remaining_days, "short_id": info.get("short_id", ""),
            **make_links(uid, domain, info["label"], info.get("sni", REALITY_SNI), info.get("short_id", ""), info.get("clean_ip", ""))
        })
    return {"links": out}

@app.post("/api/links")
async def create_link(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    d = await request.json()
    uid = d.get("uuid") or str(uuid.uuid4())
    label = d.get("label", "کاربر")
    sni = d.get("sni", REALITY_SNI) or REALITY_SNI
    clean_ip = d.get("clean_ip", "")
    short_id = d.get("short_id") or secrets.token_hex(4)[:7]
    days = int(d.get("days", 0) or 0)
    gb = float(d.get("gb", 0) or 0)
    
    info = {"label": label, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "sni": sni, "status": "active", "short_id": short_id, "clean_ip": clean_ip}
    if days > 0: info["expiry_time"] = time.time() + (days * 86400)
    if gb > 0: info["data_limit"] = int(gb * 1024 * 1024 * 1024)
    
    LINKS[uid] = info
    save_links(); sync_xray_config(); domain = get_domain(request)
    return {"ok": True, "uuid": uid, **make_links(uid, domain, label, sni, short_id, clean_ip)}

@app.post("/api/links/{uid}/edit")
async def edit_link(uid: str, request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid not in LINKS: raise HTTPException(404, "کاربر یافت نشد")
    d = await request.json()
    days = int(d.get("days", 0) or 0)
    gb = float(d.get("gb", 0) or 0)
    
    if days > 0: LINKS[uid]["expiry_time"] = time.time() + (days * 86400)
    else: LINKS[uid].pop("expiry_time", None)
    
    if gb > 0: LINKS[uid]["data_limit"] = int(gb * 1024 * 1024 * 1024)
    else: LINKS[uid].pop("data_limit", None)
        
    LINKS[uid]["status"] = "active"
    save_links(); sync_xray_config(); return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid == MASTER_UUID: raise HTTPException(403, "کاربر اصلی قابل حذف نیست")
    LINKS.pop(uid, None); save_links(); sync_xray_config(); return {"ok": True}

@app.post("/api/change-password")
async def change_pass(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    global PASS_HASH; d = await request.json()
    if hashlib.sha256(d.get("current","").encode()).hexdigest() != PASS_HASH: raise HTTPException(403, "رمز فعلی اشتباه است")
    PASS_HASH = hashlib.sha256(d.get("new","").encode()).hexdigest(); return {"ok": True}

# ── Subscription Link & HTML Page ────────────────────────
@app.get("/sub/{sid}")
async def subscription(sid: str, request: Request):
    user_uid, user_info = None, None
    for uid, info in LINKS.items():
        if info.get("short_id") == sid:
            user_uid, user_info = uid, info
            break
            
    if not user_info: return HTMLResponse("<h1>404 Not Found</h1>", status_code=404)

    domain = get_domain(request)
    links = make_links(user_uid, domain, user_info["label"], user_info.get("sni", REALITY_SNI), sid, user_info.get("clean_ip", ""))
    
    user_agent = request.headers.get("user-agent", "").lower()
    is_browser = any(b in user_agent for b in ["mozilla", "chrome", "safari", "opera", "edge", "firefox"])

    if not is_browser:
        return PlainTextResponse(links["sub_base64"], media_type="text/plain")

    used_traffic = user_traffic.get(user_uid, 0)
    data_limit = user_info.get("data_limit", 0)
    remaining_data = (data_limit - used_traffic) if data_limit else 0
    expiry_time = user_info.get("expiry_time", 0)
    remaining_days = max(0, int((expiry_time - time.time()) / 86400)) if expiry_time else 0
    status = user_info.get("status", "active")
    
    html_template = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل کاربری</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0;font-family:'Vazirmatn',sans-serif}body{background:#f0f4ff;color:#1e293b;display:flex;justify-content:center;padding:20px}.container{max-width:600px;width:100%}.header{text-align:center;margin-bottom:30px}.header h1{color:#6366f1;font-size:24px;margin-bottom:5px}.header p{color:#64748b;font-size:14px}.stats-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:15px;margin-bottom:30px}.stat-card{background:#fff;padding:20px;border-radius:16px;box-shadow:0 2px 8px rgba(0,0,0,0.05);text-align:center;border:1px solid #e2e8f0}.stat-icon{font-size:24px;margin-bottom:8px}.stat-val{font-size:18px;font-weight:700;color:#1e293b}.stat-label{font-size:12px;color:#64748b;margin-top:4px}.config-box{background:#fff;border-radius:12px;padding:15px;margin-bottom:12px;border:1px solid #e2e8f0;display:flex;justify-content:space-between;align-items:center;gap:10px}.config-info{flex:1;overflow:hidden}.config-title{font-size:13px;font-weight:600;color:#6366f1;margin-bottom:4px}.config-link{font-size:10px;color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;direction:ltr;text-align:left}.copy-btn{padding:8px 15px;background:#6366f1;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;white-space:nowrap}.copy-btn:hover{background:#4f46e5}.copy-all-btn{display:block;width:100%;padding:15px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;border-radius:12px;cursor:pointer;font-size:15px;font-weight:700;margin-top:20px}.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;margin-bottom:15px}.badge-active{background:#d1fae5;color:#065f46}.badge-expired{background:#fee2e2;color:#991b1b}</style></head><body><div class="container"><div class="header"><h1>⚡ پنل کاربری __LABEL__</h1><p>اطلاعات اشتراک و کانفیگ‌های شما</p><div class="badge __BADGE_CLASS__">__STATUS_TEXT__</div></div><div class="stats-grid"><div class="stat-card"><div class="stat-icon">📦</div><div class="stat-val">__USED__</div><div class="stat-label">حجم مصرف شده</div></div><div class="stat-card"><div class="stat-icon">📊</div><div class="stat-val">__REMAIN__</div><div class="stat-label">حجم باقی‌مانده</div></div><div class="stat-card"><div class="stat-icon">📈</div><div class="stat-val">__TOTAL__</div><div class="stat-label">حجم کل</div></div><div class="stat-card"><div class="stat-icon">⏳</div><div class="stat-val">__DAYS__</div><div class="stat-label">روزهای باقی‌مانده</div></div></div><div id="configs"><div class="config-box"><div class="config-info"><div class="config-title">🔗 VLESS + WS + TLS</div><div class="config-link">__LINK_WS__</div></div><button class="copy-btn" onclick="copyText('__LINK_WS__', this)">کپی</button></div><div class="config-box"><div class="config-info"><div class="config-title">⚡ VLESS + XHTTP + TLS</div><div class="config-link">__LINK_XHTTP__</div></div><button class="copy-btn" onclick="copyText('__LINK_XHTTP__', this)">کپی</button></div><div class="config-box"><div class="config-info"><div class="config-title">🚀 VLESS + gRPC + TLS</div><div class="config-link">__LINK_GRPC__</div></div><button class="copy-btn" onclick="copyText('__LINK_GRPC__', this)">کپی</button></div><div class="config-box"><div class="config-info"><div class="config-title">🛡️ VLESS + HTTPUpgrade + TLS</div><div class="config-link">__LINK_HU__</div></div><button class="copy-btn" onclick="copyText('__LINK_HU__', this)">کپی</button></div><div class="config-box"><div class="config-info"><div class="config-title">👻 Trojan + WS + TLS</div><div class="config-link">__LINK_TROJAN__</div></div><button class="copy-btn" onclick="copyText('__LINK_TROJAN__', this)">کپی</button></div><div class="config-box"><div class="config-info"><div class="config-title">🌀 VMess + WS + TLS</div><div class="config-link">__LINK_VMESS__</div></div><button class="copy-btn" onclick="copyText('__LINK_VMESS__', this)">کپی</button></div><div class="config-box"><div class="config-info"><div class="config-title">🔥 VLESS + Reality + Vision</div><div class="config-link">__LINK_REALITY__</div></div><button class="copy-btn" onclick="copyText('__LINK_REALITY__', this)">کپی</button></div><div class="config-box"><div class="config-info"><div class="config-title">🛡️ VLESS + XHTTP + Reality</div><div class="config-link">__LINK_XHTTP_R__</div></div><button class="copy-btn" onclick="copyText('__LINK_XHTTP_R__', this)">کپی</button></div></div><button class="copy-all-btn" onclick="copyAll()">📋 کپی همه کانفیگ‌ها</button></div><script>function copyText(t,btn){navigator.clipboard.writeText(t).then(function(){var o=btn.textContent;btn.textContent='کپی شد ✓';btn.style.background='#10b981';setTimeout(function(){btn.textContent=o;btn.style.background='#6366f1'},2000)})}function copyAll(){var t='__SUB_BASE64__';navigator.clipboard.writeText(atob(t)).then(function(){alert('همه کانفیگ‌ها کپی شدند ✓')})}</script></body></html>"""

    html_content = html_template.replace("__LABEL__", user_info['label']) \
        .replace("__BADGE_CLASS__", 'badge-active' if status=='active' else 'badge-expired') \
        .replace("__STATUS_TEXT__", '🟢 فعال' if status=='active' else '🔴 منقضی شده') \
        .replace("__USED__", fmt_bytes(used_traffic)) \
        .replace("__REMAIN__", fmt_bytes(remaining_data) if data_limit else 'نامحدود') \
        .replace("__TOTAL__", fmt_bytes(data_limit) if data_limit else 'نامحدود') \
        .replace("__DAYS__", str(remaining_days) if expiry_time else 'نامحدود') \
        .replace("__LINK_WS__", links['ws']) \
        .replace("__LINK_XHTTP__", links['xhttp']) \
        .replace("__LINK_GRPC__", links['grpc']) \
        .replace("__LINK_HU__", links['httpupgrade']) \
        .replace("__LINK_TROJAN__", links['trojan']) \
        .replace("__LINK_VMESS__", links['vmess']) \
        .replace("__LINK_REALITY__", links['reality']) \
        .replace("__LINK_XHTTP_R__", links['xhttp_reality']) \
        .replace("__SUB_BASE64__", links['sub_base64'])
    
    return HTMLResponse(html_content)

# ── صفحات HTML ادمین ──────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود — پنل XRAY</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Vazirmatn',sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:rgba(255,255,255,0.05);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.1);border-radius:24px;padding:48px 40px;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,0.4)}.logo{text-align:center;margin-bottom:32px}.logo-icon{width:64px;height:64px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:28px;margin-bottom:12px}.logo h1{color:#fff;font-size:22px;font-weight:700}.logo p{color:rgba(255,255,255,0.5);font-size:13px;margin-top:4px}label{display:block;color:rgba(255,255,255,0.7);font-size:13px;margin-bottom:6px}input{width:100%;padding:12px 16px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);border-radius:12px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:15px;outline:none;transition:.2s}input:focus{border-color:#6366f1;background:rgba(99,102,241,0.1)}.btn{width:100%;padding:13px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;border-radius:12px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:16px;font-weight:600;cursor:pointer;margin-top:24px;transition:.2s}.btn:hover{transform:translateY(-1px);box-shadow:0 8px 25px rgba(99,102,241,0.4)}.err{color:#f87171;font-size:13px;text-align:center;margin-top:12px;min-height:20px}</style></head><body><div class="card"><div class="logo"><div class="logo-icon">⚡</div><h1>پنل XRAY</h1><p>مدیریت کانفیگ‌های پروکسی</p></div><div><label>رمز عبور</label><input type="password" id="pass" placeholder="رمز عبور خود را وارد کنید" onkeydown="if(event.key==='Enter')login()"></div><button class="btn" onclick="login()">ورود به پنل</button><div class="err" id="err"></div></div><script>async function login(){const p=document.getElementById('pass').value;const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});if(r.ok)location.href='/ADMIN_PATH_PLACEHOLDER';else document.getElementById('err').textContent='رمز عبور اشتباه است'}</script></body></html>"""

PANEL_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل XRAY</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#f0f4ff;--card:#fff;--accent:#6366f1;--accent2:#8b5cf6;--text:#1e293b;--muted:#64748b;--border:#e2e8f0;--green:#10b981;--red:#ef4444;--yellow:#f59e0b}body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex}.sidebar{width:220px;min-height:100vh;background:var(--card);border-left:1px solid var(--border);display:flex;flex-direction:column;padding:24px 0;position:fixed;right:0;top:0;bottom:0;z-index:10}.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}.sidebar-logo h2{font-size:18px;font-weight:700;color:var(--accent)}.sidebar-logo p{font-size:11px;color:var(--muted);margin-top:2px}.nav-item{display:flex;align-items:center;gap:10px;padding:11px 20px;cursor:pointer;color:var(--muted);font-size:14px;font-weight:500;transition:.15s;border-radius:0}.nav-item:hover,.nav-item.active{color:var(--accent);background:rgba(99,102,241,0.08)}.nav-item.active{border-right:3px solid var(--accent)}.nav-icon{font-size:18px;width:22px;text-align:center}.sidebar-bottom{margin-top:auto;padding:16px 20px;border-top:1px solid var(--border)}.logout-btn{width:100%;padding:9px;background:none;border:1px solid var(--border);border-radius:10px;color:var(--muted);font-family:'Vazirmatn',sans-serif;font-size:13px;cursor:pointer;transition:.15s}.logout-btn:hover{border-color:var(--red);color:var(--red)}.main{margin-right:220px;flex:1;padding:28px;min-height:100vh}.page{display:none}.page.active{display:block}.page-title{font-size:22px;font-weight:700;margin-bottom:24px;color:var(--text)}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}.stat-card{background:var(--card);border-radius:16px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border)}.stat-icon{font-size:24px;margin-bottom:10px}.stat-val{font-size:26px;font-weight:700;color:var(--text)}.stat-label{font-size:12px;color:var(--muted);margin-top:2px}.card{background:var(--card);border-radius:16px;box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border);overflow:hidden}.card-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}.card-header h3{font-size:15px;font-weight:600}.btn-add{padding:8px 16px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:10px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:13px;font-weight:600;cursor:pointer;transition:.2s}.btn-add:hover{opacity:.9;transform:translateY(-1px)}table{width:100%;border-collapse:collapse}th{padding:11px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);background:#f8fafc;border-bottom:1px solid var(--border)}td{padding:13px 16px;font-size:13px;border-bottom:1px solid var(--border)}tr:last-child td{border-bottom:none}tr:hover td{background:#f8fafc}.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:600}.badge-green{background:#d1fae5;color:#065f46}.badge-blue{background:#dbeafe;color:#1e40af}.badge-red{background:#fee2e2;color:#991b1b}.badge-yellow{background:#fef3c7;color:#92400e}.tag{display:inline-block;padding:2px 8px;background:rgba(99,102,241,0.1);color:var(--accent);border-radius:6px;font-size:11px}.btn-sm{padding:5px 11px;border:1px solid var(--border);background:none;border-radius:8px;font-family:'Vazirmatn',sans-serif;font-size:12px;cursor:pointer;transition:.15s;color:var(--muted);margin-right:4px;margin-bottom:4px}.btn-sm:hover{border-color:var(--accent);color:var(--accent)}.btn-del{color:var(--red)}.btn-del:hover{border-color:var(--red);color:var(--red)}.overlay{position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:100;display:none;align-items:center;justify-content:center}.overlay.show{display:flex}.modal{background:#fff;border-radius:20px;padding:28px;width:100%;max-width:480px;box-shadow:0 20px 60px rgba(0,0,0,0.2);max-height:90vh;overflow-y:auto}.modal h3{font-size:17px;font-weight:700;margin-bottom:20px}.form-group{margin-bottom:16px}.form-group label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}.form-group input,.form-group select{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-family:'Vazirmatn',sans-serif;font-size:14px;outline:none;transition:.2s}.form-group input:focus,.form-group select:focus{border-color:var(--accent)}.modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}.btn-cancel{padding:9px 18px;border:1px solid var(--border);background:none;border-radius:10px;font-family:'Vazirmatn',sans-serif;cursor:pointer;font-size:13px}.btn-confirm{padding:9px 18px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:10px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:13px;font-weight:600;cursor:pointer}.link-box{background:#f8fafc;border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:12px}.link-type{font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px}.link-val{font-size:11px;color:var(--muted);word-break:break-all;direction:ltr;text-align:left;line-height:1.6}.copy-btn{margin-top:8px;padding:5px 12px;background:var(--accent);border:none;border-radius:7px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:11px;cursor:pointer;margin-right:5px}.qr-btn{margin-top:8px;padding:5px 12px;background:var(--muted);border:none;border-radius:7px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:11px;cursor:pointer}.settings-card{background:var(--card);border-radius:16px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border);max-width:480px}.settings-card h3{font-size:15px;font-weight:600;margin-bottom:20px}@media(max-width:768px){.sidebar{width:100%;min-height:auto;position:fixed;bottom:0;top:auto;flex-direction:row;padding:0;border-left:none;border-top:1px solid var(--border)}.sidebar-logo,.sidebar-bottom{display:none}.nav-item{flex-direction:column;gap:3px;padding:8px 0;flex:1;justify-content:center;font-size:10px;border-right:none!important}.nav-item.active{border-top:2px solid var(--accent);border-right:none}.nav-icon{font-size:20px}.main{margin-right:0;margin-bottom:65px;padding:16px}}</style></head><body><div class="sidebar"><div class="sidebar-logo"><h2>⚡ پنل XRAY</h2><p>مدیریت پروکسی</p></div><div class="nav-item active" onclick="showPage('dashboard',this)"><span class="nav-icon">📊</span><span>داشبورد</span></div><div class="nav-item" onclick="showPage('users',this)"><span class="nav-icon">👥</span><span>کاربران</span></div><div class="nav-item" onclick="showPage('settings',this)"><span class="nav-icon">⚙️</span><span>تنظیمات</span></div><div class="sidebar-bottom"><button class="logout-btn" onclick="logout()">خروج</button></div></div><div class="main"><div class="page active" id="page-dashboard"><div class="page-title">داشبورد</div><div class="stats-grid"><div class="stat-card"><div class="stat-icon">👤</div><div class="stat-val" id="s-total">—</div><div class="stat-label">کل کاربران ساخته شده</div></div><div class="stat-card"><div class="stat-icon">🌐</div><div class="stat-val" id="s-connected">—</div><div class="stat-label">کل ایپی‌های وصل شده (تا الان)</div></div><div class="stat-card"><div class="stat-icon">🟢</div><div class="stat-val" id="s-online">—</div><div class="stat-label">کاربران آنلاین هم‌اکنون</div></div><div class="stat-card"><div class="stat-icon">📦</div><div class="stat-val" id="s-bytes">—</div><div class="stat-label">ترافیک کل</div></div><div class="stat-card"><div class="stat-icon">⏱️</div><div class="stat-val" id="s-uptime">—</div><div class="stat-label">آپتایم</div></div></div><div class="card"><div class="card-header"><h3>راهنما</h3></div><div style="padding:20px;color:var(--muted);font-size:13px;text-align:center">برای دیدن تعداد افراد متصل به هر کانفیگ، به بخش «کاربران» مراجعه کنید.</div></div></div><div class="page" id="page-users"><div class="page-title">کاربران</div><div class="card"><div class="card-header"><h3>لیست کاربران</h3><button class="btn-add" onclick="openAdd()">+ کاربر جدید</button></div><table><thead><tr><th>نام</th><th>UUID</th><th>تاریخ ساخت</th><th>حجم مصرف شده</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody id="users-tbody"><tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">در حال بارگذاری...</td></tr></tbody></table></div></div><div class="page" id="page-settings"><div class="page-title">تنظیمات</div><div class="settings-card"><h3>تغییر رمز عبور</h3><div class="form-group"><label>رمز فعلی</label><input type="password" id="cp-old" placeholder="رمز عبور فعلی"></div><div class="form-group"><label>رمز جدید</label><input type="password" id="cp-new" placeholder="رمز عبور جدید"></div><button class="btn-confirm" onclick="changePass()" style="width:100%;padding:11px">تغییر رمز عبور</button><div id="cp-msg" style="margin-top:10px;font-size:13px;text-align:center"></div></div></div></div><div class="overlay" id="add-modal"><div class="modal"><h3>کاربر جدید</h3><div class="form-group"><label>نام کاربر</label><input id="new-label" placeholder="مثلاً: علی"></div><div class="form-group"><label>UUID (اختیاری - برای بازگردانی کاربر قبلی)</label><input id="new-uuid" placeholder="خالی بگذارید برای ساخت خودکار"></div><div class="form-group"><label>کد ساب لینک ۷ رقمی (اختیاری)</label><input id="new-shortid" placeholder="خالی بگذارید برای ساخت خودکار" maxlength="7"></div><div class="form-group"><label>SNI سفارشی برای Reality (اختیاری)</label><input id="new-sni" placeholder="مثلاً: yahoo.com" value="yahoo.com"></div><div class="form-group"><label>ایپی تمیز برای ۶ کانفیگ اول (اختیاری)</label><input id="new-cleanip" placeholder="مثلاً: 1.1.1.1"></div><div style="display:flex;gap:10px"><div class="form-group" style="flex:1"><label>انقضا (روز)</label><input type="number" id="new-days" placeholder="0 = نامحدود" value="0"></div><div class="form-group" style="flex:1"><label>محدودیت حجم (GB)</label><input type="number" id="new-gb" placeholder="0 = نامحدود" value="0"></div></div><div class="modal-footer"><button class="btn-cancel" onclick="closeAdd()">انصراف</button><button class="btn-confirm" onclick="createUser()">ساخت کاربر</button></div></div></div><div class="overlay" id="edit-modal"><div class="modal"><h3>ویرایش کاربر</h3><input type="hidden" id="edit-uid"><div class="form-group"><label>نام کاربر</label><input id="edit-label" disabled style="background:#f1f5f9"></div><div style="display:flex;gap:10px"><div class="form-group" style="flex:1"><label>انقضای جدید (روز)</label><input type="number" id="edit-days" placeholder="0 = نامحدود" value="0"></div><div class="form-group" style="flex:1"><label>محدودیت حجم جدید (GB)</label><input type="number" id="edit-gb" placeholder="0 = نامحدود" value="0"></div></div><div class="modal-footer"><button class="btn-cancel" onclick="closeEdit()">انصراف</button><button class="btn-confirm" onclick="saveEdit()">ذخیره تغییرات</button></div></div></div><div class="overlay" id="link-modal"><div class="modal"><h3 id="link-modal-title">کانفیگ‌ها</h3><div class="link-box" style="text-align:center"><div class="link-type">🚀 لینک اشتراک (Sub Link)</div><div class="link-val" id="lnk-sub">—</div><button class="copy-btn" onclick="copy('lnk-sub')">کپی Sub Link</button></div><div style="text-align:center;margin-bottom:15px"><button class="btn-confirm" onclick="copyAllLinks()">📋 کپی همه کانفیگ‌ها</button></div><div class="link-box"><div class="link-type">🔗 VLESS + WebSocket + TLS</div><div class="link-val" id="lnk-ws">—</div><button class="copy-btn" onclick="copy('lnk-ws')">کپی</button><button class="qr-btn" onclick="showQR('ws')">QR</button></div><div class="link-box"><div class="link-type">⚡ VLESS + XHTTP + TLS</div><div class="link-val" id="lnk-xhttp">—</div><button class="copy-btn" onclick="copy('lnk-xhttp')">کپی</button><button class="qr-btn" onclick="showQR('xhttp')">QR</button></div><div class="link-box"><div class="link-type">🚀 VLESS + gRPC + TLS</div><div class="link-val" id="lnk-grpc">—</div><button class="copy-btn" onclick="copy('lnk-grpc')">کپی</button><button class="qr-btn" onclick="showQR('grpc')">QR</button></div><div class="link-box"><div class="link-type">🛡️ VLESS + HTTPUpgrade + TLS</div><div class="link-val" id="lnk-hu">—</div><button class="copy-btn" onclick="copy('lnk-hu')">کپی</button><button class="qr-btn" onclick="showQR('hu')">QR</button></div><div class="link-box"><div class="link-type">👻 Trojan + WebSocket + TLS</div><div class="link-val" id="lnk-trojan">—</div><button class="copy-btn" onclick="copy('lnk-trojan')">کپی</button><button class="qr-btn" onclick="showQR('trojan')">QR</button></div><div class="link-box"><div class="link-type">🌀 VMess + WebSocket + TLS</div><div class="link-val" id="lnk-vmess">—</div><button class="copy-btn" onclick="copy('lnk-vmess')">کپی</button><button class="qr-btn" onclick="showQR('vmess')">QR</button></div><div class="link-box"><div class="link-type">🔥 VLESS + Reality + Vision</div><div class="link-val" id="lnk-reality">—</div><button class="copy-btn" onclick="copy('lnk-reality')">کپی</button><button class="qr-btn" onclick="showQR('reality')">QR</button></div><div class="link-box"><div class="link-type">🛡️ VLESS + XHTTP + Reality</div><div class="link-val" id="lnk-xhttp-reality">—</div><button class="copy-btn" onclick="copy('lnk-xhttp-reality')">کپی</button><button class="qr-btn" onclick="showQR('xhttp_reality')">QR</button></div><div class="modal-footer"><button class="btn-confirm" onclick="closeLinks()">بستن</button></div></div></div><div class="overlay" id="qr-modal" onclick="if(event.target===this)closeQR()"><div class="modal" style="text-align:center;max-width:300px"><h3>بارکد کانفیگ</h3><img id="qr-img" src="" style="width:100%;border-radius:12px;margin:15px 0"><button class="btn-confirm" onclick="closeQR()" style="width:100%">بستن</button></div></div><script>function showPage(n,e){document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active')});document.querySelectorAll('.nav-item').forEach(function(n){n.classList.remove('active')});document.getElementById('page-'+n).classList.add('active');e.classList.add('active');if(n==='users')loadUsers()}async function logout(){await fetch('/api/logout',{method:'POST'});location.href='/LOGIN_PATH_PLACEHOLDER'}async function loadStats(){try{const r=await fetch('/api/stats');if(r.status===401){location.href='/LOGIN_PATH_PLACEHOLDER';return}const d=await r.json();document.getElementById('s-total').textContent=d.total_users;document.getElementById('s-connected').textContent=d.total_connected;document.getElementById('s-online').textContent=d.active_ips;document.getElementById('s-bytes').textContent=fmtBytes(d.bytes);document.getElementById('s-uptime').textContent=d.uptime}catch(e){}}function fmtBytes(b){if(b<1024)return b+'B';if(b<1024*1024)return(b/1024).toFixed(1)+'KB';if(b<1024**3)return(b/1024/1024).toFixed(2)+'MB';return(b/1024**3).toFixed(2)+'GB'}async function loadUsers(){const r=await fetch('/api/links');if(r.status===401){location.href='/LOGIN_PATH_PLACEHOLDER';return}const d=await r.json();const tb=document.getElementById('users-tbody');if(!d.links.length){tb.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">کاربری وجود ندارد</td></tr>';return}tb.innerHTML=d.links.map(function(u){let status_badge='<span class="badge badge-blue">🟢 '+(u.online_ips>0?(u.online_ips+' اتصال'):'آنلاین')+'</span>';if(u.status==='expired')status_badge='<span class="badge badge-red">منقضی</span>';let limits='';if(u.data_limit>0)limits+='<span class="badge badge-yellow">باقی‌مانده: '+fmtBytes(u.remaining_data)+'</span><br>';if(u.remaining_days>0)limits+='<span class="badge badge-yellow">'+u.remaining_days+' روز</span>';return '<tr><td><span class="badge badge-green">'+u.label+'</span><br>'+limits+'</td><td><span class="tag">'+u.uuid.substring(0,8)+'…</span></td><td>'+u.created_at+'</td><td>'+fmtBytes(u.used_traffic)+'</td><td>'+status_badge+'</td><td><button class="btn-sm" onclick=\'showLinks('+JSON.stringify(u)+')\'>🔗 لینک</button><button class="btn-sm" onclick=\'editUser("'+u.uuid+'","'+u.label.replace(/'/g, '')+'")\'>✏️ ویرایش</button><button class="btn-sm btn-del" onclick="delUser(\''+u.uuid+'\')">حذف</button></td></tr>'}).join('')}function openAdd(){document.getElementById('add-modal').classList.add('show')}function closeAdd(){document.getElementById('add-modal').classList.remove('show')}async function createUser(){const label=document.getElementById('new-label').value||'کاربر';const uuid=document.getElementById('new-uuid').value;const shortid=document.getElementById('new-shortid').value;const sni=document.getElementById('new-sni').value;const cleanip=document.getElementById('new-cleanip').value;const days=document.getElementById('new-days').value;const gb=document.getElementById('new-gb').value;const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,uuid,short_id:shortid,sni,days,gb,clean_ip:cleanip})});const d=await r.json();closeAdd();document.getElementById('new-label').value='';document.getElementById('new-uuid').value='';document.getElementById('new-shortid').value='';document.getElementById('new-cleanip').value='';showLinks(d);loadUsers()}function editUser(uid,label){document.getElementById('edit-uid').value=uid;document.getElementById('edit-label').value=label;document.getElementById('edit-days').value=0;document.getElementById('edit-gb').value=0;document.getElementById('edit-modal').classList.add('show')}function closeEdit(){document.getElementById('edit-modal').classList.remove('show')}async function saveEdit(){const uid=document.getElementById('edit-uid').value;const days=document.getElementById('edit-days').value;const gb=document.getElementById('edit-gb').value;const r=await fetch('/api/links/'+uid+'/edit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days,gb})});if(r.ok){closeEdit();loadUsers();alert('کاربر با موفقیت ویرایش شد ✓')}}async function delUser(uid){if(!confirm('حذف این کاربر؟'))return;await fetch('/api/links/'+uid,{method:'DELETE'});loadUsers()}function showLinks(u){document.getElementById('link-modal-title').textContent='کانفیگ‌های '+u.label;document.getElementById('lnk-sub').textContent=u.sub_link;document.getElementById('lnk-ws').textContent=u.ws;document.getElementById('lnk-xhttp').textContent=u.xhttp;document.getElementById('lnk-grpc').textContent=u.grpc;document.getElementById('lnk-hu').textContent=u.httpupgrade;document.getElementById('lnk-trojan').textContent=u.trojan;document.getElementById('lnk-vmess').textContent=u.vmess;document.getElementById('lnk-reality').textContent=u.reality;document.getElementById('lnk-xhttp-reality').textContent=u.xhttp_reality;document.getElementById('link-modal').classList.add('show')}function closeLinks(){document.getElementById('link-modal').classList.remove('show')}function copy(id){navigator.clipboard.writeText(document.getElementById(id).textContent);alert('کپی شد ✓')}function copyAllLinks(){const ws=document.getElementById('lnk-ws').textContent;const xhttp=document.getElementById('lnk-xhttp').textContent;const grpc=document.getElementById('lnk-grpc').textContent;const hu=document.getElementById('lnk-hu').textContent;const trojan=document.getElementById('lnk-trojan').textContent;const vmess=document.getElementById('lnk-vmess').textContent;const reality=document.getElementById('lnk-reality').textContent;const xhttp_reality=document.getElementById('lnk-xhttp-reality').textContent;navigator.clipboard.writeText(ws+'\\n'+xhttp+'\\n'+grpc+'\\n'+hu+'\\n'+trojan+'\\n'+vmess+'\\n'+reality+'\\n'+xhttp_reality);alert('همه کانفیگ‌ها کپی شدند ✓')}function showQR(type){const link=document.getElementById('lnk-'+type).textContent;const img=document.getElementById('qr-img');img.src='https://api.qrserver.com/v1/create-qr-code/?size=250x250&data='+encodeURIComponent(link);document.getElementById('qr-modal').classList.add('show')}function closeQR(){document.getElementById('qr-modal').classList.remove('show')}async function changePass(){const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current:document.getElementById('cp-old').value,new:document.getElementById('cp-new').value})});const m=document.getElementById('cp-msg');if(r.ok){m.style.color='var(--green)';m.textContent='رمز با موفقیت تغییر کرد ✓'}else{m.style.color='var(--red)';m.textContent='رمز فعلی اشتباه است'}}loadStats();setInterval(loadStats,5000)</script></body></html>"""

@app.get("/" + ADMIN_PATH + "/login", response_class=HTMLResponse)
async def login_page(): return HTMLResponse(LOGIN_HTML.replace("ADMIN_PATH_PLACEHOLDER", ADMIN_PATH))

@app.get("/" + ADMIN_PATH, response_class=HTMLResponse)
async def panel_page(token: Optional[str] = Cookie(None)):
    if not auth_check(token): return RedirectResponse("/" + ADMIN_PATH + "/login")
    return HTMLResponse(PANEL_HTML.replace("LOGIN_PATH_PLACEHOLDER", "/" + ADMIN_PATH + "/login"))

@app.get("/")
async def root(): return Response(content=b"OK", media_type="text/plain")

@app.get("/health")
async def health(): return {"status": "ok", "connections": len(user_last_active)}

if __name__ == "__main__":
    import logging; logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    uvicorn.run("panel:app", host="0.0.0.0", port=PORT, reload=False, log_level="warning")