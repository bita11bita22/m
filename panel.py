"""
پنل مدیریت XRAY — Ultra Light Edition (Reality Only + No Nginx)
"""
import os, json, uuid, asyncio, hashlib, secrets, time, subprocess, base64
from datetime import datetime
from collections import deque
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, HTTPException, Cookie, APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
import httpx, uvicorn

# ── تنظیمات ──────────────────────────────────────────────
PORT         = int(os.environ.get("PORT", 8000) or 8000)
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "admin1234")
ADMIN_PATH   = os.environ.get("ADMIN_PATH", "panel").strip("/")
PUBLIC_HOST  = os.environ.get("PUBLIC_HOST", "")
MASTER_UUID  = os.environ.get("UUID", "90cd4a77-141a-43c9-991b-08263cfe9c10")
LINKS_FILE   = "/app/links.json"
CFG_FILE     = "/app/cfg.json"
XRAY_LOG     = "/tmp/xray_access.log"
STATS_FILE   = "/app/stats.json"
XRAY_API_PORT = 10085
PANEL_PORT   = 5000 # پورت داخلی پایتون

REALITY_DOMAIN = os.environ.get("REALITY_DOMAIN", "")
REALITY_PUBLIC_PORT = os.environ.get("REALITY_PUBLIC_PORT", str(PORT))
REALITY_SNI  = os.environ.get("REALITY_SNI", "yahoo.com")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID", "")

PASS_HASH = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()

# ── state ─────────────────────────────────────────────────
SESSIONS = {}
LINKS = {}
stats = {"bytes": 0, "start": time.time()}
sys_info = {"ram": 0, "cpu": 0}
prev_cpu = None
xray_process = None
xray_log_pos = 0
user_traffic = {}       
user_last_active = {}   
active_connections = {} 
reality_keys = {"priv": "", "pub": ""}
tg_client = None

# ── System Info & Log Reader ─────────────────────────────
def get_sys_info():
    global prev_cpu
    try:
        with open('/proc/meminfo', 'r') as f:
            mem = {}
            for l in f:
                p = l.split(':')
                if len(p)==2:
                    try: mem[p[0].strip()] = int(p[1].strip().split(' ')[0])
                    except: pass
        t, a = mem.get('MemTotal',0), mem.get('MemAvailable',0)
        if t>0: sys_info["ram"] = int(((t-a)/t)*100)
            
        with open('/proc/stat', 'r') as f:
            p = [int(x) for x in f.readline().split()[1:]]
            idle = p[3] + (p[4] if len(p)>4 else 0)
            tot = sum(p)
            if prev_cpu is None: prev_cpu = (idle, tot)
            else:
                di, dt = idle-prev_cpu[0], tot-prev_cpu[1]
                if dt>0: sys_info["cpu"] = max(0, int(100-(100*di/dt)))
                prev_cpu = (idle, tot)
    except: pass

def read_connections():
    global xray_log_pos
    if not os.path.exists(XRAY_LOG): return
    try:
        curr_size = os.path.getsize(XRAY_LOG)
        if curr_size < xray_log_pos: xray_log_pos = 0
        if curr_size > 10 * 1024 * 1024:
            open(XRAY_LOG, 'w').close()
            xray_log_pos = 0
            
        with open(XRAY_LOG, "r") as f:
            f.seek(xray_log_pos)
            for line in f:
                if "accepted" not in line or "email:" not in line: continue
                try:
                    parts = line.split()
                    ip = parts[2].split(":")[0] 
                    uid_idx = line.find("email: ") + 7
                    uid = line[uid_idx:uid_idx+36]
                    if uid in LINKS:
                        if uid not in active_connections: active_connections[uid] = {}
                        active_connections[uid][ip] = time.time()
                        user_last_active[uid] = time.time()
                except: pass
            xray_log_pos = f.tell()
            
        now = time.time()
        for uid in list(active_connections.keys()):
            for ip in list(active_connections[uid].keys()):
                if now - active_connections[uid][ip] > 60: del active_connections[uid][ip]
            if not active_connections[uid]: del active_connections[uid]
        for uid in list(user_last_active.keys()):
            if now - user_last_active[uid] > 60: del user_last_active[uid]
    except: pass

# ── Xray Core Manager ────────────────────────────────────
def load_data():
    global LINKS, reality_keys, user_traffic, stats
    try:
        if os.path.exists(LINKS_FILE):
            with open(LINKS_FILE, "r") as f: LINKS = json.load(f)
    except: LINKS = {}
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, "r") as f:
                d = json.load(f)
                stats["bytes"] = d.get("bytes", 0)
                stats["start"] = d.get("start", time.time())
                user_traffic = d.get("user_traffic", {})
                if "reality_priv" in d: reality_keys["priv"], reality_keys["pub"] = d["reality_priv"], d["reality_pub"]
    except: pass
    updated = False
    for uid, info in LINKS.items():
        if "short_id" not in info: info["short_id"] = secrets.token_hex(4)[:7]; updated = True
        if "ip_limit" not in info: info["ip_limit"] = 0; updated = True
    if updated: save_links()

def save_links():
    with open(LINKS_FILE, "w") as f: json.dump(LINKS, f)

def save_stats():
    with open(STATS_FILE, "w") as f: json.dump({"bytes": stats["bytes"], "start": stats["start"], "user_traffic": user_traffic, "reality_priv": reality_keys["priv"], "reality_pub": reality_keys["pub"]}, f)

def generate_reality_keys():
    global reality_keys
    if not reality_keys["priv"]:
        try:
            out = subprocess.run(["/usr/local/bin/xray", "x25519"], capture_output=True, text=True, timeout=5).stdout
            if "PrivateKey:" in out: reality_keys["priv"] = out.split("PrivateKey:")[1].split("\n")[0].strip()
            if "Password (PublicKey):" in out: reality_keys["pub"] = out.split("Password (PublicKey):")[1].split("\n")[0].strip()
            elif "PublicKey:" in out: reality_keys["pub"] = out.split("PublicKey:")[1].split("\n")[0].strip()
            if reality_keys["priv"] and reality_keys["pub"]: save_stats()
        except: pass

def sync_xray_config():
    global xray_process
    generate_reality_keys()
    active = {uid: i for uid, i in LINKS.items() if i.get("status")=="active" and not (i.get("expiry_time") and time.time()>i["expiry_time"]) and not (i.get("data_limit") and user_traffic.get(uid,0)>=i["data_limit"])}
    save_links()
    clients = [{"id": uid, "level": 0, "email": uid, "flow": "xtls-rprx-vision"} for uid in active.keys()]
    
    cfg = {
        "log": {"loglevel": "info", "access": XRAY_LOG}, 
        "stats": {}, "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
        "inbounds": [
            {"listen": "127.0.0.1", "port": XRAY_API_PORT, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}, "tag": "api_in"},
            {
                "port": PORT, "listen": "0.0.0.0", "protocol": "vless",
                "settings": {"clients": clients, "decryption": "none"},
                # استفاده از dest در Reality برای فوروارد کردن ترافیک وب به پایتون
                "streamSettings": {
                    "network": "tcp", "security": "reality", 
                    "realitySettings": {
                        "show": False, 
                        "dest": f"127.0.0.1:{PANEL_PORT}", 
                        "xver": 0, 
                        "serverNames": [REALITY_SNI], 
                        "privateKey": reality_keys["priv"], 
                        "shortIds": ["", "0123456789abcdef"]
                    }
                }
            }
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}, {"protocol": "freedom", "tag": "api"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api_in"], "outboundTag": "api"}]}
    }
    with open(CFG_FILE, "w") as f: json.dump(cfg, f)
    try:
        if xray_process: xray_process.terminate(); xray_process.wait(timeout=2)
    except: pass
    try:
        if os.path.exists(XRAY_LOG): os.remove(XRAY_LOG)
        xray_process = subprocess.Popen(["/usr/local/bin/xray", "-config", CFG_FILE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

async def stats_updater():
    global xray_log_pos
    await asyncio.sleep(5)
    while True:
        get_sys_info()
        read_connections()
        if xray_process and xray_process.poll() is not None: sync_xray_config()
        try:
            r = subprocess.run(["/usr/local/bin/xray", "api", "statsquery", f"--server=127.0.0.1:{XRAY_API_PORT}", "-reset"], capture_output=True, text=True, timeout=3)
            if r.stdout:
                for s in json.loads(r.stdout).get("stat", []):
                    n, v = s.get("name",""), int(s.get("value","0") or 0)
                    p = n.split(">>>")
                    if len(p)==4 and p[0]=="user" and p[2]=="traffic":
                        if p[1] not in user_traffic: user_traffic[p[1]] = 0
                        user_traffic[p[1]] += v; stats["bytes"] += v
                        if v > 0: user_last_active[p[1]] = time.time()
            save_stats()
        except: pass
        await asyncio.sleep(30)

async def telegram_notifier():
    if not BOT_TOKEN or not ADMIN_CHAT_ID: return
    await asyncio.sleep(10)
    while True:
        for uid, info in LINKS.items():
            if info.get("status")!="active": continue
            msg = ""
            if info.get("expiry_time"):
                dl = (info["expiry_time"]-time.time())/86400
                if 0 < dl <= 3: msg = f"⚠️ کاربر {info['label']} کمتر از ۳ روز تا انقضا دارد."
            if info.get("data_limit"):
                if user_traffic.get(uid,0) >= info["data_limit"]*0.9: msg = f"⚠️ کاربر {info['label']} ۹۰٪ حجم خود را مصرف کرده است."
            if msg and not info.get("notified"):
                try: await tg_request("sendMessage", {"chat_id": ADMIN_CHAT_ID, "text": msg}); LINKS[uid]["notified"]=True; save_links()
                except: pass
            elif not msg and info.get("notified"): LINKS[uid]["notified"]=False; save_links()
        await asyncio.sleep(3600)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global tg_client
    load_data()
    if MASTER_UUID not in LINKS:
        LINKS[MASTER_UUID] = {"label":"Master","created_at":datetime.now().strftime("%Y-%m-%d %H:%M"),"sni":REALITY_SNI,"status":"active","short_id":secrets.token_hex(4)[:7],"ip_limit":0}
        save_links()
    sync_xray_config()
    asyncio.create_task(stats_updater())
    asyncio.create_task(telegram_notifier())
    if BOT_TOKEN:
        tg_client = httpx.AsyncClient()
        domain = PUBLIC_HOST or os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
        if domain: asyncio.create_task(set_telegram_webhook(domain))
    yield
    if tg_client: await tg_client.aclose()
    if xray_process: xray_process.terminate()

app = FastAPI(docs_url=None, redoc_url=None, lifespan=lifespan)

# ── helpers ───────────────────────────────────────────────
def get_domain(request: Request) -> str:
    h = (PUBLIC_HOST or os.environ.get("RAILWAY_PUBLIC_DOMAIN","") or request.headers.get("host","localhost"))
    return h.replace("https://","").replace("http://","").strip("/")

def make_links(uid, domain, label, sni, short_id):
    addr = REALITY_DOMAIN if REALITY_DOMAIN else domain
    port = REALITY_PUBLIC_PORT if REALITY_DOMAIN else "443"
    sni = sni or REALITY_SNI
    if not reality_keys["pub"]: return {"reality": "خطا: کلیدهای Reality ساخته نشده", "sub_link": "", "sub_base64": ""}
    link = f"vless://{uid}@{addr}:{port}?encryption=none&security=reality&sni={sni}&fp=chrome&pbk={reality_keys['pub']}&sid=0123456789abcdef&type=tcp&flow=xtls-rprx-vision#{label}-Reality"
    sub_link = f"https://{domain}/sub/{short_id}"
    return {"reality": link, "sub_link": sub_link, "sub_base64": base64.b64encode(link.encode()).decode()}

def auth_check(token: Optional[str] = Cookie(None)) -> bool:
    return bool(token) and time.time() < SESSIONS.get(token, 0)

def uptime_str() -> str:
    s = int(time.time()-stats["start"]); h,r=divmod(s,3600); m,sc=divmod(r,60)
    return f"{h:02d}:{m:02d}:{sc:02d}"

def fmt_bytes(b):
    if b<1024: return f"{b} B"
    if b<1024**2: return f"{b/1024:.1f} KB"
    if b<1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

# ── auth & api ───────────────────────────────────────────
@app.post("/api/login")
async def login(request: Request):
    d = await request.json()
    if hashlib.sha256(d.get("password","").encode()).hexdigest() != PASS_HASH: raise HTTPException(403, "رمز اشتباه است")
    t = secrets.token_urlsafe(32); SESSIONS[t] = time.time()+86400
    r = JSONResponse({"ok": True}); r.set_cookie("token", t, httponly=True, samesite="lax", max_age=86400); return r

@app.post("/api/logout")
async def logout(token: Optional[str] = Cookie(None)):
    SESSIONS.pop(token, None); return JSONResponse({"ok": True})

@app.get("/api/stats")
async def api_stats(token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    return {"total_users": len(LINKS), "active_uuids": len(user_last_active), "active_ips": sum(len(i) for i in active_connections.values()), "bytes": stats["bytes"], "uptime": uptime_str(), "ram": sys_info["ram"], "cpu": sys_info["cpu"]}

@app.get("/api/links")
async def api_links(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    dom = get_domain(request); out = []
    for uid, info in LINKS.items():
        out.append({"uuid":uid, "label":info["label"], "created_at":info["created_at"], "online_ips":len(active_connections.get(uid,{})), "used_traffic":user_traffic.get(uid,0), "status":info.get("status","active"), "ip_limit":info.get("ip_limit",0), "data_limit":info.get("data_limit",0), "remaining_data":(info.get("data_limit",0)-user_traffic.get(uid,0)) if info.get("data_limit") else 0, "remaining_days":max(0,int((info.get("expiry_time",0)-time.time())/86400)) if info.get("expiry_time") else 0, "short_id":info.get("short_id",""), **make_links(uid, dom, info["label"], info.get("sni",REALITY_SNI), info.get("short_id",""))})
    return {"links": out}

@app.post("/api/links")
async def create_link(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    d = await request.json()
    uid = d.get("uuid") or str(uuid.uuid4())
    LINKS[uid] = {"label":d.get("label","کاربر")[:30], "created_at":datetime.now().strftime("%Y-%m-%d %H:%M"), "sni":d.get("sni",REALITY_SNI), "status":"active", "short_id":d.get("short_id") or secrets.token_hex(4)[:7], "ip_limit":int(d.get("ip_limit",0) or 0)}
    if int(d.get("days",0) or 0)>0: LINKS[uid]["expiry_time"]=time.time()+(int(d["days"])*86400)
    if float(d.get("gb",0) or 0)>0: LINKS[uid]["data_limit"]=int(float(d["gb"])*1024**3)
    save_links(); sync_xray_config()
    return {"ok": True, "uuid": uid, **make_links(uid, get_domain(request), LINKS[uid]["label"], LINKS[uid]["sni"], LINKS[uid]["short_id"])}

@app.post("/api/links/{uid}/edit")
async def edit_link(uid: str, request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid not in LINKS: raise HTTPException(404)
    d = await request.json()
    LINKS[uid]["ip_limit"]=int(d.get("ip_limit",0) or 0)
    if int(d.get("days",0) or 0)>0: LINKS[uid]["expiry_time"]=time.time()+(int(d["days"])*86400)
    if float(d.get("gb",0) or 0)>0: LINKS[uid]["data_limit"]=int(float(d["gb"])*1024**3)
    LINKS[uid]["status"]="active"; save_links(); sync_xray_config(); return {"ok": True}

@app.post("/api/links/{uid}/extend")
async def extend_link(uid: str, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid not in LINKS: raise HTTPException(404)
    if "expiry_time" in LINKS[uid] and LINKS[uid]["expiry_time"]>time.time(): LINKS[uid]["expiry_time"]+=30*86400
    else: LINKS[uid]["expiry_time"]=time.time()+30*86400
    LINKS[uid]["status"]="active"; save_links(); sync_xray_config(); return {"ok": True}

@app.post("/api/links/{uid}/reset")
async def reset_traffic(uid: str, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid not in LINKS: raise HTTPException(404)
    user_traffic[uid]=0; LINKS[uid]["status"]="active"; save_stats(); save_links(); sync_xray_config(); return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid == MASTER_UUID: raise HTTPException(403)
    LINKS.pop(uid, None); save_links(); sync_xray_config(); return {"ok": True}

# ── Health Check (بسیار مهم برای Railway) ──────────────
@app.get("/health")
async def health(): return {"status": "ok"}

# ── Subscription & HTML ──────────────────────────────────
@app.get("/sub/{sid}")
async def subscription(sid: str, request: Request):
    user_uid, user_info = next(((u,i) for u,i in LINKS.items() if i.get("short_id")==sid), (None,None))
    if not user_info: return HTMLResponse("<h1>404 Not Found</h1>", status_code=404)
    dom = get_domain(request)
    links = make_links(user_uid, dom, user_info["label"], user_info.get("sni",REALITY_SNI), sid)
    if "v2ray" in request.headers.get("user-agent","").lower() or "mozilla" not in request.headers.get("user-agent","").lower():
        used = user_traffic.get(user_uid,0); dl = user_info.get("data_limit",0); et = user_info.get("expiry_time",0)
        rd = (dl-used) if dl else 0; rdays = max(0,int((et-time.time())/86400)) if et else 0
        dummy = f"vless://00000000-0000-0000-0000-000000000000@1.1.1.1:1#📊 حجم: {fmt_bytes(rd) if dl else 'نامحدود'} | ⏳ زمان: {rdays} روز"
        return PlainTextResponse(base64.b64encode((links['reality']+'\n'+dummy).encode()).decode(), headers={"Subscription-Userinfo": f"upload=0; download={used}; total={dl}; expire={et}"})
    return HTMLResponse(f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل کاربری</title><style>*{{font-family:system-ui;text-align:center;background:#f0f4f0;color:#333;margin:20px}}button{{padding:10px;background:#6366f1;color:#fff;border:none;border-radius:8px;cursor:pointer}}img{{width:180px;border-radius:12px}}div{{background:#fff;padding:15px;border-radius:12px;margin-bottom:15px;box-shadow:0 2px 5px rgba(0,0,0,.1)}}</style></head><body><h1>⚡ {user_info['label']}</h1><div><img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={links['sub_link']}"></div><div><b>لینک کانفیگ Reality:</b><br><textarea readonly style="width:100%;height:60px">{links['reality']}</textarea><br><button onclick="navigator.clipboard.writeText('{links['reality']}');alert('کپی شد')">کپی لینک</button></div></body></html>""")

# ── Telegram Bot (Webhook) ───────────────────────────────
bot_router = APIRouter()
bot_state = {}
async def tg_request(method, payload):
    if not BOT_TOKEN or not tg_client: return None
    try: return (await tg_client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/{method}", json=payload, timeout=5.0)).json()
    except: return None
async def send_message(chat_id, text, reply_markup=None):
    p = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup: p["reply_markup"] = reply_markup
    await tg_request("sendMessage", p)
def main_menu():
    return {"inline_keyboard": [[{"text":"📊 آمار","callback_data":"stats"},{"text":"👥 لیست کاربران","callback_data":"users"}],[{"text":"➕ کاربر جدید","callback_data":"new_user"}]]}
@bot_router.post("/bot_webhook")
async def bot_webhook(req: Request):
    if not BOT_TOKEN: return {"ok": False}
    d = await req.json()
    if "callback_query" in d:
        cq=d["callback_query"]; cid=cq["message"]["chat"]["id"]; mid=cq["message"]["message_id"]; ds=cq["data"]
        if str(cq["from"]["id"])!=ADMIN_CHAT_ID: return {"ok":False}
        await tg_request("answerCallbackQuery", {"callback_query_id": cq["id"]})
        if ds=="menu": await send_message(cid, "💡 <b>منوی مدیریت</b>", main_menu())
        elif ds=="stats": await tg_request("editMessageText", {"chat_id":cid,"message_id":mid,"text":f"📊 آمار:\n👤 کاربران: {len(LINKS)}\n🟢 آنلاین: {len(user_last_active)}\n📦 ترافیک: {fmt_bytes(stats['bytes'])}","parse_mode":"HTML","reply_markup":main_menu()})
        elif ds=="users":
            txt = "\n".join([f"{'🟢' if u in user_last_active else '⚪️'} {i['label']} | {fmt_bytes(user_traffic.get(u,0))}" for u,i in list(LINKS.items())[-20:]])
            await tg_request("editMessageText", {"chat_id":cid,"message_id":mid,"text":f"👥 کاربران:\n{txt}","parse_mode":"HTML","reply_markup":main_menu()})
        elif ds=="new_user": bot_state[cid]="name"; await send_message(cid, "نام کاربر را بفرست:")
    elif "message" in d:
        m=d["message"]; cid=m["chat"]["id"]; txt=m.get("text","")
        if str(m["from"]["id"])!=ADMIN_CHAT_ID: return {"ok":False}
        if txt=="/start": bot_state.pop(cid,None); await send_message(cid, "💡 به ربات خوش آمدید!", main_menu())
        elif bot_state.get(cid)=="name":
            uid=str(uuid.uuid4()); sid=secrets.token_hex(4)[:7]
            LINKS[uid]={"label":txt[:30],"created_at":datetime.now().strftime("%Y-%m-%d %H:%M"),"sni":REALITY_SNI,"status":"active","short_id":sid,"ip_limit":0}
            save_links(); sync_xray_config()
            dom = PUBLIC_HOST or "your-domain"
            await send_message(cid, f"✅ ساخته شد!\n👤 {txt}\n🔗 https://{dom}/sub/{sid}", main_menu())
    return {"ok": True}
async def set_telegram_webhook(domain):
    await tg_request("setWebhook", {"url": f"https://{domain}/bot_webhook"})
    await send_message(ADMIN_CHAT_ID, "🤖 ربات فعال شد!", main_menu())
app.include_router(bot_router)

# ── Admin Panel HTML ─────────────────────────────────────
LOGIN_HTML = r"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود</title><style>*{box-sizing:border-box;margin:0;padding:0;font-family:sans-serif}body{background:#1a1a2e;display:flex;justify-content:center;align-items:center;height:100vh}input,button{width:100%;padding:12px;margin:8px 0;border-radius:8px;border:1px solid #444;background:#333;color:#fff}button{background:#6366f1;border:none;cursor:pointer}.card{background:#16213e;padding:40px;border-radius:16px;width:320px}h1{color:#fff;text-align:center;margin-bottom:20px}</style></head><body><div class="card"><h1>⚡ پنل XRAY</h1><input type="password" id="p" placeholder="رمز عبور" onkeydown="if(event.key==='Enter')login()"><button onclick="login()">ورود</button><div id="e" style="color:#f87171;text-align:center;margin-top:10px"></div></div><script>async function login(){const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})});if(r.ok)location.href='__URL__';else document.getElementById('e').textContent='رمز اشتباه'}</script></body></html>"""
PANEL_HTML = r"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل</title><style>*{box-sizing:border-box;margin:0;padding:0;font-family:sans-serif}:root{--bg:#f0f4ff;--card:#fff;--a:#6366f1;--t:#1e293b;--m:#64748b;--b:#e2e8f0;--g:#10b981;--r:#ef4444;--y:#f59e0b}.dark{--bg:#1e293b;--card:#334155;--a:#818cf8;--t:#f1f5f9;--m:#cbd5e1;--b:#475569}body{background:var(--bg);color:var(--t);font-family:sans-serif;display:flex}.sb{width:220px;background:var(--card);height:100vh;position:fixed;right:0;padding:20px 0;border-left:1px solid var(--b)}.ni{padding:10px 20px;cursor:pointer;color:var(--m)}.ni:hover,.ni.act{color:var(--a);border-right:3px solid var(--a)}.mn{margin-right:220px;padding:20px;flex:1}.pg{display:none}.pg.act{display:block}.st{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:20px}.sc{background:var(--card);padding:15px;border-radius:12px;border:1px solid var(--b)}.sv{font-size:24px;font-weight:bold}.sl{font-size:12px;color:var(--m)}.tb{width:100%;background:var(--card);border-collapse:collapse;border-radius:12px;overflow:hidden}.th,.td{padding:10px;text-align:right;border-bottom:1px solid var(--b)}.th{background:var(--bg);font-size:12px;color:var(--m)}.bd{padding:3px 6px;border-radius:4px;font-size:11px}.bg{background:#d1fae5;color:#065f46}.bb{background:#dbeafe;color:#1e40af}.br{background:#fee2e2;color:#991b1b}.by{background:#fef3c7;color:#92400e}.bt{padding:4px 8px;border:1px solid var(--b);background:none;border-radius:6px;cursor:pointer;color:var(--m)}.bt:hover{border-color:var(--a);color:var(--a)}.ov{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;justify-content:center;align-items:center}.ov.sh{display:flex}.md{background:var(--card);padding:20px;border-radius:16px;width:90%;max-width:400px}.lb{display:block;font-size:12px;color:var(--m);margin:5px 0}.ip{width:100%;padding:8px;border:1px solid var(--b);border-radius:8px;background:var(--bg);color:var(--t)}.mh{display:none;justify-content:space-between;padding:10px 20px;background:var(--card);position:fixed;top:0;left:0;right:0}@media(max-width:768px){.sb,.sb-bottom{display:none}.sb{position:fixed;bottom:0;flex-direction:row;width:100%;height:50px;padding:0}.mn{margin-right:0;margin-bottom:60px}.ni{flex:1;text-align:center;border-right:0}.mh{display:flex}}</style></head><body><div class="mh"><button onclick="document.body.classList.toggle('dark')">🌙</button><button onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/__URL__/login')" style="color:var(--r)">خروج</button></div><div class="sb"><div style="padding:0 20px 20px;border-bottom:1px solid var(--b);margin-bottom:10px"><h2>⚡ XRAY</h2></div><div class="ni act" onclick="sh('d',this)">📊 داشبورد</div><div class="ni" onclick="sh('u',this)">👥 کاربران</div></div><div class="mn"><div class="pg act" id="p-d"><h2>داشبورد</h2><div class="st"><div class="sc"><div class="sl">کاربران</div><div class="sv" id="st-u">-</div></div><div class="sc"><div class="sl">آنلاین</div><div class="sv" id="st-o">-</div></div><div class="sc"><div class="sl">ترافیک</div><div class="sv" id="st-b">-</div></div><div class="sc"><div class="sl">RAM</div><div class="sv" id="st-r">-</div></div><div class="sc"><div class="sl">CPU</div><div class="sv" id="st-c">-</div></div></div></div><div class="pg" id="p-u"><h2>کاربران <button class="bt" style="float:left" onclick="document.getElementById('add').classList.add('sh')">+ جدید</button></h2><table class="tb"><tr class="th"><td>نام</td><td>UUID</td><td>آنلاین</td><td>حجم</td><td>عملیات</td></tr><tbody id="ut"></tbody></table></div></div><div class="ov" id="add"><div class="md"><h3>کاربر جدید</h3><label class="lb">نام</label><input class="ip" id="nl" placeholder="علی"><label class="lb">محدودیت حجم (GB) - 0 یعنی نامحدود</label><input class="ip" type="number" id="ng" value="0"><label class="lb">مدت زمان (روز) - 0 یعنی نامحدود</label><input class="ip" type="number" id="nd" value="0"><label class="lb">حداکثر دستگاه (0=نامحدود)</label><input class="ip" type="number" id="ni" value="0"><div style="text-align:left;margin-top:15px"><button class="bt" onclick="document.getElementById('add').classList.remove('sh')">انصراف</button> <button class="bt" style="background:var(--a);color:#fff;border:none" onclick="cu()">ساخت</button></div></div></div><script>function sh(n,e){document.querySelectorAll('.pg').forEach(p=>p.classList.remove('act'));document.querySelectorAll('.ni').forEach(i=>i.classList.remove('act'));document.getElementById('p-'+n).classList.add('act');e.classList.add('act');if(n=='u')lu()}async function ls(){try{const r=await fetch('/api/stats');const d=await r.json();document.getElementById('st-u').textContent=d.total_users;document.getElementById('st-o').textContent=d.active_ips;document.getElementById('st-b').textContent=fb(d.bytes);document.getElementById('st-r').textContent=d.ram+'%';document.getElementById('st-c').textContent=d.cpu+'%'}catch(e){}}function fb(b){if(b<1024)return b+'B';if(b<1024**2)return(b/1024).toFixed(1)+'K';if(b<1024**3)return(b/1024**2).toFixed(2)+'M';return(b/1024**3).toFixed(2)+'G'}async function lu(){const r=await fetch('/api/links');const d=await r.json();document.getElementById('ut').innerHTML=d.links.map(u=>`<tr><td><span class="bd bg">${u.label}</span></td><td>${u.uuid.substr(0,8)}</td><td>${u.online_ips>0?`<span class="bd bb">${u.online_ips} دستگاه</span>`:'<span class="bd br">آفلاین</span>'}</td><td>${fb(u.used_traffic)}</td><td><button class="bt" onclick="window.open('/sub/${u.short_id}','_blank')">🔗 لینک</button> <button class="bt" onclick="fetch('/api/links/${u.uuid}/extend',{method:'POST'}).then(lu)">➕ ۳۰ روز</button> <button class="bt" style="color:var(--r)" onclick="fetch('/api/links/${u.uuid}',{method:'DELETE'}).then(lu)">حذف</button></td></tr>`).join('')}async function cu(){const l=nl.value||'کاربر';const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:l,gb:ng.value,days:nd.value,ip_limit:ni.value})});const d=await r.json();document.getElementById('add').classList.remove('sh');window.open('/sub/'+d.uuid,'_blank');lu()}ls();setInterval(ls,5000)</script></body></html>"""

@app.get("/__URL__", response_class=HTMLResponse)
async def panel_page(token: Optional[str] = Cookie(None)):
    if not auth_check(token): return RedirectResponse("/__URL__/login")
    return HTMLResponse(PANEL_HTML.replace("__URL__", ADMIN_PATH))

@app.get("/__URL__/login", response_class=HTMLResponse)
async def login_page(): return HTMLResponse(LOGIN_HTML.replace("__URL__", ADMIN_PATH))

@app.get("/")
async def root(): return Response(content=b"OK", media_type="text/plain")

if __name__ == "__main__":
    import logging; logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    # پایتون روی پورت داخلی 5000 اجرا می‌شود، Xray روی پورت اصلی (PORT) است
    uvicorn.run("panel:app", host="127.0.0.1", port=PANEL_PORT, reload=False, log_level="warning")