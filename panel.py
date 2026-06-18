"""
پنل مدیریت XRAY — FastAPI + Nginx + Reality + Multi-Transport (gRPC Reality Added)
"""
import os, json, uuid, asyncio, hashlib, secrets, time, subprocess, re, base64
from datetime import datetime
from collections import deque
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import httpx, uvicorn

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
STATS_FILE   = "/app/stats.json"
XRAY_API_PORT = 10085

# پورت‌های داخلی ترانسپورت‌ها
XRAY_GRPC_PORT = 18083
XRAY_HU_PORT   = 18084
XRAY_TJ_PORT   = 18085
XRAY_VM_PORT   = 18086
XRAY_GRPC_R_PORT = 18087 # پورت داخلی برای gRPC Reality

# تنظیمات Reality
REALITY_PORT = int(os.environ.get("REALITY_PORT", 18443))
REALITY_DOMAIN = os.environ.get("REALITY_DOMAIN", "")
REALITY_PUBLIC_PORT = os.environ.get("REALITY_PUBLIC_PORT", "18443")
REALITY_SNI  = os.environ.get("REALITY_SNI", "www.microsoft.com")
XRAY_XH_INTERNAL_PORT = 18082

PASS_HASH = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()

# ── state ─────────────────────────────────────────────────
SESSIONS: dict[str, float] = {}
LINKS: dict = {}
error_log: deque = deque(maxlen=50)
stats = {"bytes": 0, "start": time.time()}
xray_process = None
xray_log_pos = 0
user_traffic = {}       
user_last_active = {}   
active_connections = {} 
total_unique_users = set()
reality_keys = {"priv": "", "pub": ""}

def log_err(msg):
    error_log.append({"e": msg, "t": datetime.now().isoformat()})

# ── Xray Core Manager ────────────────────────────────────
def load_data():
    global LINKS, total_unique_users, reality_keys, user_traffic
    try:
        if os.path.exists(LINKS_FILE):
            with open(LINKS_FILE, "r") as f: LINKS = json.load(f)
    except: LINKS = {}
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, "r") as f:
                data = json.load(f)
                total_unique_users = set(data.get("total_unique", []))
                stats["bytes"] = data.get("bytes", 0)
                user_traffic = data.get("user_traffic", {})
                if "reality_priv" in data:
                    reality_keys["priv"] = data["reality_priv"]
                    reality_keys["pub"] = data["reality_pub"]
    except: pass

def save_links():
    with open(LINKS_FILE, "w") as f: json.dump(LINKS, f)

def save_stats():
    with open(STATS_FILE, "w") as f:
        json.dump({
            "total_unique": list(total_unique_users), "bytes": stats["bytes"],
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
            else: log_err(f"Failed to parse keys from output: {out}")
        except Exception as e: log_err(f"Failed to generate Reality keys: {str(e)}")

def sync_xray_config():
    global xray_process
    generate_reality_keys()
    
    ws_xh_clients = [{"id": uid, "level": 0, "email": uid} for uid in LINKS.keys()]
    reality_clients = [{"id": uid, "level": 0, "email": uid, "flow": "xtls-rprx-vision"} for uid in LINKS.keys()]
    trojan_clients = [{"password": uid, "email": uid} for uid in LINKS.keys()]
    vmess_clients = [{"id": uid, "level": 0, "email": uid, "alterId": 0} for uid in LINKS.keys()]
    
    inbounds = [
        {"port": XRAY_WS_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}}},
        {"port": XRAY_XH_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/xh", "mode": "auto"}}},
        {"port": XRAY_GRPC_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "grpc"}}},
        {"port": XRAY_HU_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "httpupgrade", "httpupgradeSettings": {"path": "/hu"}}},
        {"port": XRAY_TJ_PORT, "listen": "127.0.0.1", "protocol": "trojan", "settings": {"clients": trojan_clients}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/tj"}}},
        {"port": XRAY_VM_PORT, "listen": "127.0.0.1", "protocol": "vmess", "settings": {"clients": vmess_clients}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/vm"}}},
        {"port": XRAY_XH_INTERNAL_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/xh", "mode": "auto"}}},
        # پورت داخلی برای gRPC Reality
        {"port": XRAY_GRPC_R_PORT, "listen": "127.0.0.1", "protocol": "vless", "settings": {"clients": ws_xh_clients, "decryption": "none"}, "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "grpc"}}}
    ]
    
    if reality_keys["priv"]:
        inbounds.append({
            "port": REALITY_PORT, "listen": "0.0.0.0", "protocol": "vless",
            "settings": {
                "clients": reality_clients, "decryption": "none", 
                "fallbacks": [
                    # اگر ترافیک gRPC بود (ALPN:h2) آن را به پورت داخلی gRPC بفرست
                    {"alpn": "h2", "dest": f"127.0.0.1:{XRAY_GRPC_R_PORT}"},
                    # در غیر این صورت به XHTTP بفرست
                    {"dest": f"127.0.0.1:{XRAY_XH_INTERNAL_PORT}"}
                ]
            },
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": False, "dest": f"{REALITY_SNI}:443", "xver": 0, "serverNames": [REALITY_SNI], "privateKey": reality_keys["priv"], "shortIds": ["", "0123456789abcdef"]}}
        })
    
    cfg = {
        "log": {"loglevel": "info", "access": XRAY_LOG}, 
        "stats": {},
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
    except Exception as e: log_err(f"Xray restart failed: {e}")

# ── Stats & Online Tracker ───────────────────────────────
async def stats_updater():
    global xray_log_pos
    await asyncio.sleep(3)
    while True:
        try:
            result = subprocess.run(["/usr/local/bin/xray", "api", "statsquery", f"--server=127.0.0.1:{XRAY_API_PORT}", "-reset"], capture_output=True, text=True, timeout=3)
            out = result.stdout
            if out:
                data = json.loads(out)
                for stat in data.get("stat", []):
                    name = stat.get("name", ""); value = int(stat.get("value", "0")); parts = name.split(">>>")
                    if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                        uid = parts[1]
                        if uid not in user_traffic: user_traffic[uid] = 0
                        user_traffic[uid] += value; stats["bytes"] += value
                        if value > 0:
                            user_last_active[uid] = time.time(); total_unique_users.add(uid)
            save_stats()
        except: pass

        try:
            if os.path.exists(XRAY_LOG):
                if os.path.getsize(XRAY_LOG) > 5 * 1024 * 1024: open(XRAY_LOG, 'w').close(); xray_log_pos = 0
                current_size = os.path.getsize(XRAY_LOG)
                if current_size < xray_log_pos: xray_log_pos = 0
                with open(XRAY_LOG, "r") as f:
                    f.seek(xray_log_pos); new_data = f.read(); xray_log_pos = f.tell()
                    
                    matches = re.findall(r'((?:\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F:]+\]?):\d+\s+accepted.*?email:\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', new_data, re.IGNORECASE)
                    for ip, uid in matches:
                        ip = ip.strip('[]')
                        if uid not in active_connections: active_connections[uid] = {}
                        active_connections[uid][ip] = time.time()
                        user_last_active[uid] = time.time(); total_unique_users.add(uid)
        except: pass

        now = time.time()
        for uid in list(user_last_active.keys()):
            if now - user_last_active[uid] > 60: del user_last_active[uid]
        for uid in list(active_connections.keys()):
            for ip in list(active_connections[uid].keys()):
                if now - active_connections[uid][ip] > 60: del active_connections[uid][ip]
            if not active_connections[uid]: del active_connections[uid]
        await asyncio.sleep(5)

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_data()
    if MASTER_UUID not in LINKS:
        LINKS[MASTER_UUID] = {"label": "Master", "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")}; save_links()
    sync_xray_config(); asyncio.create_task(stats_updater())
    yield
    if xray_process: xray_process.terminate()

app = FastAPI(docs_url=None, redoc_url=None, lifespan=lifespan)

# ── helpers ───────────────────────────────────────────────
def get_domain(request: Request) -> str:
    h = (PUBLIC_HOST or os.environ.get("RENDER_EXTERNAL_URL","") or os.environ.get("RAILWAY_PUBLIC_DOMAIN","") or request.headers.get("host","localhost"))
    return h.replace("https://","").replace("http://","").strip("/")

def make_links(uid: str, domain: str, label: str) -> dict:
    ws   = (f"vless://{uid}@{domain}:443?encryption=none&security=tls&type=ws&host={domain}&path=%2Fws&sni={domain}&fp=chrome#{label}-WS")
    xhttp = (f"vless://{uid}@{domain}:443?encryption=none&security=tls&type=xhttp&host={domain}&path=%2Fxh&sni={domain}&fp=chrome&mode=auto#{label}-XHTTP")
    grpc = (f"vless://{uid}@{domain}:443?encryption=none&security=tls&type=grpc&host={domain}&serviceName=grpc&sni={domain}&fp=chrome&mode=gun#{label}-gRPC")
    httpupgrade = (f"vless://{uid}@{domain}:443?encryption=none&security=tls&type=httpupgrade&host={domain}&path=%2Fhu&sni={domain}&fp=chrome#{label}-HTTPUpgrade")
    
    trojan = (f"trojan://{uid}@{domain}:443?security=tls&type=ws&host={domain}&path=%2Ftj&sni={domain}&fp=chrome#{label}-Trojan")
    
    vmess_json = json.dumps({"v":"2","ps":f"{label}-VMess","add":domain,"port":"443","id":uid,"aid":"0","scy":"auto","net":"ws","type":"none","host":domain,"path":"/vm","tls":"tls","sni":domain})
    vmess = "vmess://" + base64.b64encode(vmess_json.encode()).decode()
    
    if not REALITY_DOMAIN: 
        reality = "خطا: REALITY_DOMAIN ست نشده"
        xhttp_reality = "خطا: REALITY_DOMAIN ست نشده"
        grpc_reality = "خطا: REALITY_DOMAIN ست نشده"
    elif not reality_keys["pub"]: 
        reality = "خطا: کلیدهای Reality ساخته نشدند"
        xhttp_reality = "خطا: کلیدهای Reality ساخته نشدند"
        grpc_reality = "خطا: کلیدهای Reality ساخته نشدند"
    else: 
        reality = (f"vless://{uid}@{REALITY_DOMAIN}:{REALITY_PUBLIC_PORT}?encryption=none&security=reality&sni={REALITY_SNI}&fp=chrome&pbk={reality_keys['pub']}&sid=0123456789abcdef&type=tcp&flow=xtls-rprx-vision#{label}-Reality")
        xhttp_reality = (f"vless://{uid}@{REALITY_DOMAIN}:{REALITY_PUBLIC_PORT}?encryption=none&security=reality&sni={REALITY_SNI}&fp=chrome&pbk={reality_keys['pub']}&sid=0123456789abcdef&type=xhttp&path=%2Fxh&mode=auto#{label}-XHTTP-Reality")
        # اضافه شدن لینک gRPC Reality
        grpc_reality = (f"vless://{uid}@{REALITY_DOMAIN}:{REALITY_PUBLIC_PORT}?encryption=none&security=reality&sni={REALITY_SNI}&fp=chrome&pbk={reality_keys['pub']}&sid=0123456789abcdef&type=grpc&serviceName=grpc&mode=gun#{label}-gRPC-Reality")
        
    return {"ws": ws, "xhttp": xhttp, "grpc": grpc, "httpupgrade": httpupgrade, "trojan": trojan, "vmess": vmess, "reality": reality, "xhttp_reality": xhttp_reality, "grpc_reality": grpc_reality}

def auth_check(token: Optional[str] = Cookie(None)) -> bool:
    if not token: return False
    return time.time() < SESSIONS.get(token, 0)

def uptime_str() -> str:
    s = int(time.time() - stats["start"]); h, r = divmod(s, 3600); m, sc = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{sc:02d}"

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
    return {"total_users": len(LINKS), "total_connected": len(total_unique_users), "active_uuids": len(user_last_active), "active_ips": len(user_last_active), "bytes": stats["bytes"], "uptime": uptime_str()}

@app.get("/api/links")
async def api_links(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    domain = get_domain(request); out = []
    for uid, info in LINKS.items():
        is_online = uid in user_last_active
        ip_count = len(active_connections.get(uid, {}))
        online_count = ip_count if ip_count > 0 else (1 if is_online else 0)
        out.append({"uuid": uid, "label": info["label"], "created_at": info["created_at"], "online_ips": online_count, "used_traffic": user_traffic.get(uid, 0), **make_links(uid, domain, info["label"])})
    return {"links": out}

@app.post("/api/links")
async def create_link(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    d = await request.json(); uid = d.get("uuid") or str(uuid.uuid4()); label = d.get("label", "کاربر")
    LINKS[uid] = {"label": label, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")}
    save_links(); sync_xray_config(); domain = get_domain(request)
    return {"ok": True, "uuid": uid, **make_links(uid, domain, label)}

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

# ── صفحات HTML ──────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود — پنل XRAY</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Vazirmatn',sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:rgba(255,255,255,0.05);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.1);border-radius:24px;padding:48px 40px;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,0.4)}.logo{text-align:center;margin-bottom:32px}.logo-icon{width:64px;height:64px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:28px;margin-bottom:12px}.logo h1{color:#fff;font-size:22px;font-weight:700}.logo p{color:rgba(255,255,255,0.5);font-size:13px;margin-top:4px}label{display:block;color:rgba(255,255,255,0.7);font-size:13px;margin-bottom:6px}input{width:100%;padding:12px 16px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);border-radius:12px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:15px;outline:none;transition:.2s}input:focus{border-color:#6366f1;background:rgba(99,102,241,0.1)}.btn{width:100%;padding:13px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;border-radius:12px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:16px;font-weight:600;cursor:pointer;margin-top:24px;transition:.2s}.btn:hover{transform:translateY(-1px);box-shadow:0 8px 25px rgba(99,102,241,0.4)}.err{color:#f87171;font-size:13px;text-align:center;margin-top:12px;min-height:20px}</style></head><body><div class="card"><div class="logo"><div class="logo-icon">⚡</div><h1>پنل XRAY</h1><p>مدیریت کانفیگ‌های پروکسی</p></div><div><label>رمز عبور</label><input type="password" id="pass" placeholder="رمز عبور خود را وارد کنید" onkeydown="if(event.key==='Enter')login()"></div><button class="btn" onclick="login()">ورود به پنل</button><div class="err" id="err"></div></div><script>async function login(){const p=document.getElementById('pass').value;const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});if(r.ok)location.href='/ADMIN_PATH_PLACEHOLDER';else document.getElementById('err').textContent='رمز عبور اشتباه است'}</script></body></html>"""

PANEL_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل XRAY</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#f0f4ff;--card:#fff;--accent:#6366f1;--accent2:#8b5cf6;--text:#1e293b;--muted:#64748b;--border:#e2e8f0;--green:#10b981;--red:#ef4444}body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex}.sidebar{width:220px;min-height:100vh;background:var(--card);border-left:1px solid var(--border);display:flex;flex-direction:column;padding:24px 0;position:fixed;right:0;top:0;bottom:0;z-index:10}.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}.sidebar-logo h2{font-size:18px;font-weight:700;color:var(--accent)}.sidebar-logo p{font-size:11px;color:var(--muted);margin-top:2px}.nav-item{display:flex;align-items:center;gap:10px;padding:11px 20px;cursor:pointer;color:var(--muted);font-size:14px;font-weight:500;transition:.15s;border-radius:0}.nav-item:hover,.nav-item.active{color:var(--accent);background:rgba(99,102,241,0.08)}.nav-item.active{border-right:3px solid var(--accent)}.nav-icon{font-size:18px;width:22px;text-align:center}.sidebar-bottom{margin-top:auto;padding:16px 20px;border-top:1px solid var(--border)}.logout-btn{width:100%;padding:9px;background:none;border:1px solid var(--border);border-radius:10px;color:var(--muted);font-family:'Vazirmatn',sans-serif;font-size:13px;cursor:pointer;transition:.15s}.logout-btn:hover{border-color:var(--red);color:var(--red)}.main{margin-right:220px;flex:1;padding:28px;min-height:100vh}.page{display:none}.page.active{display:block}.page-title{font-size:22px;font-weight:700;margin-bottom:24px;color:var(--text)}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}.stat-card{background:var(--card);border-radius:16px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border)}.stat-icon{font-size:24px;margin-bottom:10px}.stat-val{font-size:26px;font-weight:700;color:var(--text)}.stat-label{font-size:12px;color:var(--muted);margin-top:2px}.card{background:var(--card);border-radius:16px;box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border);overflow:hidden}.card-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}.card-header h3{font-size:15px;font-weight:600}.btn-add{padding:8px 16px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:10px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:13px;font-weight:600;cursor:pointer;transition:.2s}.btn-add:hover{opacity:.9;transform:translateY(-1px)}table{width:100%;border-collapse:collapse}th{padding:11px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);background:#f8fafc;border-bottom:1px solid var(--border)}td{padding:13px 16px;font-size:13px;border-bottom:1px solid var(--border)}tr:last-child td{border-bottom:none}tr:hover td{background:#f8fafc}.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:600}.badge-green{background:#d1fae5;color:#065f46}.badge-blue{background:#dbeafe;color:#1e40af}.badge-red{background:#fee2e2;color:#991b1b}.tag{display:inline-block;padding:2px 8px;background:rgba(99,102,241,0.1);color:var(--accent);border-radius:6px;font-size:11px}.btn-sm{padding:5px 11px;border:1px solid var(--border);background:none;border-radius:8px;font-family:'Vazirmatn',sans-serif;font-size:12px;cursor:pointer;transition:.15s;color:var(--muted)}.btn-sm:hover{border-color:var(--accent);color:var(--accent)}.btn-del{color:var(--red)}.btn-del:hover{border-color:var(--red);color:var(--red)}.overlay{position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:100;display:none;align-items:center;justify-content:center}.overlay.show{display:flex}.modal{background:#fff;border-radius:20px;padding:28px;width:100%;max-width:480px;box-shadow:0 20px 60px rgba(0,0,0,0.2);max-height:90vh;overflow-y:auto}.modal h3{font-size:17px;font-weight:700;margin-bottom:20px}.form-group{margin-bottom:16px}.form-group label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}.form-group input{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:10px;font-family:'Vazirmatn',sans-serif;font-size:14px;outline:none;transition:.2s}.form-group input:focus{border-color:var(--accent)}.modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}.btn-cancel{padding:9px 18px;border:1px solid var(--border);background:none;border-radius:10px;font-family:'Vazirmatn',sans-serif;cursor:pointer;font-size:13px}.btn-confirm{padding:9px 18px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:10px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:13px;font-weight:600;cursor:pointer}.link-box{background:#f8fafc;border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:12px}.link-type{font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px}.link-val{font-size:11px;color:var(--muted);word-break:break-all;direction:ltr;text-align:left;line-height:1.6}.copy-btn{margin-top:8px;padding:5px 12px;background:var(--accent);border:none;border-radius:7px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:11px;cursor:pointer}.settings-card{background:var(--card);border-radius:16px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border);max-width:480px}.settings-card h3{font-size:15px;font-weight:600;margin-bottom:20px}@media(max-width:768px){.sidebar{width:100%;min-height:auto;position:fixed;bottom:0;top:auto;flex-direction:row;padding:0;border-left:none;border-top:1px solid var(--border)}.sidebar-logo,.sidebar-bottom{display:none}.nav-item{flex-direction:column;gap:3px;padding:8px 0;flex:1;justify-content:center;font-size:10px;border-right:none!important}.nav-item.active{border-top:2px solid var(--accent);border-right:none}.nav-icon{font-size:20px}.main{margin-right:0;margin-bottom:65px;padding:16px}}</style></head><body><div class="sidebar"><div class="sidebar-logo"><h2>⚡ پنل XRAY</h2><p>مدیریت پروکسی</p></div><div class="nav-item active" onclick="showPage('dashboard',this)"><span class="nav-icon">📊</span><span>داشبورد</span></div><div class="nav-item" onclick="showPage('users',this)"><span class="nav-icon">👥</span><span>کاربران</span></div><div class="nav-item" onclick="showPage('settings',this)"><span class="nav-icon">⚙️</span><span>تنظیمات</span></div><div class="sidebar-bottom"><button class="logout-btn" onclick="logout()">خروج</button></div></div><div class="main"><div class="page active" id="page-dashboard"><div class="page-title">داشبورد</div><div class="stats-grid"><div class="stat-card"><div class="stat-icon">👤</div><div class="stat-val" id="s-total">—</div><div class="stat-label">کل کاربران ساخته شده</div></div><div class="stat-card"><div class="stat-icon">🌐</div><div class="stat-val" id="s-connected">—</div><div class="stat-label">کل کاربران وصل شده (تا الان)</div></div><div class="stat-card"><div class="stat-icon">🟢</div><div class="stat-val" id="s-online">—</div><div class="stat-label">کاربران آنلاین هم‌اکنون</div></div><div class="stat-card"><div class="stat-icon">📦</div><div class="stat-val" id="s-bytes">—</div><div class="stat-label">ترافیک کل</div></div><div class="stat-card"><div class="stat-icon">⏱️</div><div class="stat-val" id="s-uptime">—</div><div class="stat-label">آپتایم</div></div></div><div class="card"><div class="card-header"><h3>راهنما</h3></div><div style="padding:20px;color:var(--muted);font-size:13px;text-align:center">برای دیدن تعداد افراد متصل به هر کانفیگ، به بخش «کاربران» مراجعه کنید.</div></div></div><div class="page" id="page-users"><div class="page-title">کاربران</div><div class="card"><div class="card-header"><h3>لیست کاربران</h3><button class="btn-add" onclick="openAdd()">+ کاربر جدید</button></div><table><thead><tr><th>نام</th><th>UUID</th><th>تاریخ ساخت</th><th>حجم مصرف شده</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody id="users-tbody"><tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">در حال بارگذاری...</td></tr></tbody></table></div></div><div class="page" id="page-settings"><div class="page-title">تنظیمات</div><div class="settings-card"><h3>تغییر رمز عبور</h3><div class="form-group"><label>رمز فعلی</label><input type="password" id="cp-old" placeholder="رمز عبور فعلی"></div><div class="form-group"><label>رمز جدید</label><input type="password" id="cp-new" placeholder="رمز عبور جدید"></div><button class="btn-confirm" onclick="changePass()" style="width:100%;padding:11px">تغییر رمز عبور</button><div id="cp-msg" style="margin-top:10px;font-size:13px;text-align:center"></div></div></div></div><div class="overlay" id="add-modal"><div class="modal"><h3>کاربر جدید</h3><div class="form-group"><label>نام کاربر</label><input id="new-label" placeholder="مثلاً: علی"></div><div class="form-group"><label>UUID (اختیاری — خودکار تولید می‌شود)</label><input id="new-uuid" placeholder="خالی بگذارید"></div><div class="modal-footer"><button class="btn-cancel" onclick="closeAdd()">انصراف</button><button class="btn-confirm" onclick="createUser()">ساخت کاربر</button></div></div></div><div class="overlay" id="link-modal"><div class="modal"><h3 id="link-modal-title">کانفیگ‌ها</h3><div style="text-align:center;margin-bottom:15px"><button class="btn-confirm" onclick="copyAllLinks()">📋 کپی همه کانفیگ‌ها</button></div><div class="link-box"><div class="link-type">🔗 VLESS + WebSocket + TLS</div><div class="link-val" id="lnk-ws">—</div><button class="copy-btn" onclick="copy('lnk-ws')">کپی</button></div><div class="link-box"><div class="link-type">⚡ VLESS + XHTTP + TLS</div><div class="link-val" id="lnk-xhttp">—</div><button class="copy-btn" onclick="copy('lnk-xhttp')">کپی</button></div><div class="link-box"><div class="link-type">🚀 VLESS + gRPC + TLS</div><div class="link-val" id="lnk-grpc">—</div><button class="copy-btn" onclick="copy('lnk-grpc')">کپی</button></div><div class="link-box"><div class="link-type">🛡️ VLESS + HTTPUpgrade + TLS</div><div class="link-val" id="lnk-hu">—</div><button class="copy-btn" onclick="copy('lnk-hu')">کپی</button></div><div class="link-box"><div class="link-type">👻 Trojan + WebSocket + TLS</div><div class="link-val" id="lnk-trojan">—</div><button class="copy-btn" onclick="copy('lnk-trojan')">کپی</button></div><div class="link-box"><div class="link-type">🌀 VMess + WebSocket + TLS</div><div class="link-val" id="lnk-vmess">—</div><button class="copy-btn" onclick="copy('lnk-vmess')">کپی</button></div><div class="link-box"><div class="link-type">🔥 VLESS + Reality + Vision</div><div class="link-val" id="lnk-reality">—</div><button class="copy-btn" onclick="copy('lnk-reality')">کپی</button></div><div class="link-box"><div class="link-type">🛡️ VLESS + XHTTP + Reality</div><div class="link-val" id="lnk-xhttp-reality">—</div><button class="copy-btn" onclick="copy('lnk-xhttp-reality')">کپی</button></div><div class="link-box"><div class="link-type">🚀 VLESS + gRPC + Reality</div><div class="link-val" id="lnk-grpc-reality">—</div><button class="copy-btn" onclick="copy('lnk-grpc-reality')">کپی</button></div><div class="modal-footer"><button class="btn-confirm" onclick="closeLinks()">بستن</button></div></div></div><script>function showPage(n,e){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));document.getElementById('page-'+n).classList.add('active');e.classList.add('active');if(n==='users')loadUsers()}async function logout(){await fetch('/api/logout',{method:'POST'});location.href='/LOGIN_PATH_PLACEHOLDER'}async function loadStats(){try{const r=await fetch('/api/stats');if(r.status===401){location.href='/LOGIN_PATH_PLACEHOLDER';return}const d=await r.json();document.getElementById('s-total').textContent=d.total_users;document.getElementById('s-connected').textContent=d.total_connected;document.getElementById('s-online').textContent=d.active_ips;document.getElementById('s-bytes').textContent=fmtBytes(d.bytes);document.getElementById('s-uptime').textContent=d.uptime}catch(e){}}function fmtBytes(b){if(b<1024)return b+'B';if(b<1024*1024)return(b/1024).toFixed(1)+'KB';if(b<1024**3)return(b/1024/1024).toFixed(2)+'MB';return(b/1024**3).toFixed(2)+'GB'}async function loadUsers(){const r=await fetch('/api/links');if(r.status===401){location.href='/LOGIN_PATH_PLACEHOLDER';return}const d=await r.json();const tb=document.getElementById('users-tbody');if(!d.links.length){tb.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">کاربری وجود ندارد</td></tr>';return}tb.innerHTML=d.links.map(u=>`<tr><td><span class="badge badge-green">${u.label}</span></td><td><span class="tag">${u.uuid.substring(0,8)}…</span></td><td>${u.created_at}</td><td>${fmtBytes(u.used_traffic)}</td><td>${u.online_ips>0?`<span class="badge badge-blue">🟢 ${u.online_ips} اتصال</span>`:'<span class="badge badge-red">آفلاین</span>'}</td><td style="display:flex;gap:6px"><button class="btn-sm" onclick='showLinks(${JSON.stringify(u)})'>🔗 لینک</button><button class="btn-sm btn-del" onclick="delUser('${u.uuid}')">حذف</button></td></tr>`).join('')}function openAdd(){document.getElementById('add-modal').classList.add('show')}function closeAdd(){document.getElementById('add-modal').classList.remove('show')}async function createUser(){const label=document.getElementById('new-label').value||'کاربر';const uid=document.getElementById('new-uuid').value||null;const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,uuid:uid})});const d=await r.json();closeAdd();document.getElementById('new-label').value='';document.getElementById('new-uuid').value='';showLinks(d);loadUsers()}async function delUser(uid){if(!confirm('حذف این کاربر؟'))return;await fetch('/api/links/'+uid,{method:'DELETE'});loadUsers()}function showLinks(u){document.getElementById('link-modal-title').textContent='کانفیگ‌های '+u.label;document.getElementById('lnk-ws').textContent=u.ws;document.getElementById('lnk-xhttp').textContent=u.xhttp;document.getElementById('lnk-grpc').textContent=u.grpc;document.getElementById('lnk-hu').textContent=u.httpupgrade;document.getElementById('lnk-trojan').textContent=u.trojan;document.getElementById('lnk-vmess').textContent=u.vmess;document.getElementById('lnk-reality').textContent=u.reality;document.getElementById('lnk-xhttp-reality').textContent=u.xhttp_reality;document.getElementById('lnk-grpc-reality').textContent=u.grpc_reality;document.getElementById('link-modal').classList.add('show')}function closeLinks(){document.getElementById('link-modal').classList.remove('show')}function copy(id){navigator.clipboard.writeText(document.getElementById(id).textContent);alert('کپی شد ✓')}function copyAllLinks(){const ws=document.getElementById('lnk-ws').textContent;const xhttp=document.getElementById('lnk-xhttp').textContent;const grpc=document.getElementById('lnk-grpc').textContent;const hu=document.getElementById('lnk-hu').textContent;const trojan=document.getElementById('lnk-trojan').textContent;const vmess=document.getElementById('lnk-vmess').textContent;const reality=document.getElementById('lnk-reality').textContent;const xhttp_reality=document.getElementById('lnk-xhttp-reality').textContent;const grpc_reality=document.getElementById('lnk-grpc-reality').textContent;navigator.clipboard.writeText(ws+'\\n'+xhttp+'\\n'+grpc+'\\n'+hu+'\\n'+trojan+'\\n'+vmess+'\\n'+reality+'\\n'+xhttp_reality+'\\n'+grpc_reality);alert('همه کانفیگ‌ها کپی شدند ✓')}async function changePass(){const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current:document.getElementById('cp-old').value,new:document.getElementById('cp-new').value})});const m=document.getElementById('cp-msg');if(r.ok){m.style.color='var(--green)';m.textContent='رمز با موفقیت تغییر کرد ✓'}else{m.style.color='var(--red)';m.textContent='رمز فعلی اشتباه است'}}loadStats();setInterval(loadStats,5000)</script></body></html>"""

@app.get(f"/{ADMIN_PATH}/login", response_class=HTMLResponse)
async def login_page(): return HTMLResponse(LOGIN_HTML.replace("ADMIN_PATH_PLACEHOLDER", ADMIN_PATH))

@app.get(f"/{ADMIN_PATH}", response_class=HTMLResponse)
async def panel_page(token: Optional[str] = Cookie(None)):
    if not auth_check(token): return RedirectResponse(f"/{ADMIN_PATH}/login")
    return HTMLResponse(PANEL_HTML.replace("LOGIN_PATH_PLACEHOLDER", f"/{ADMIN_PATH}/login"))

@app.get("/")
async def root(): return Response(content=b"OK", media_type="text/plain")

@app.get("/health")
async def health(): return {"status": "ok", "connections": len(user_last_active)}

if __name__ == "__main__":
    import logging; logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    uvicorn.run("panel:app", host="0.0.0.0", port=PORT, reload=False, log_level="warning")