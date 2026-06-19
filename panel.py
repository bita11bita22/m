"""
پنل مدیریت XRAY — Beautiful UI + Reality Only + Telegram Bot
"""
import os, json, uuid, asyncio, hashlib, secrets, time, subprocess, base64
from datetime import datetime
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
STATS_FILE   = "/app/stats.json"
XRAY_API_PORT = 10085
PANEL_PORT   = 5000 # پورت داخلی پایتون

REALITY_DOMAIN = os.environ.get("REALITY_DOMAIN", "")
REALITY_PUBLIC_PORT = os.environ.get("REALITY_PUBLIC_PORT", "443")
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
user_traffic = {}       
user_last_active = {}   
reality_keys = {"priv": "", "pub": ""}
tg_client = None

# ── System Info & Stats ──────────────────────────────────
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
        "log": {"loglevel": "warning"}, 
        "stats": {}, "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
        "inbounds": [
            {"listen": "127.0.0.1", "port": XRAY_API_PORT, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}, "tag": "api_in"},
            {
                "port": PORT, "listen": "0.0.0.0", "protocol": "vless",
                "settings": {"clients": clients, "decryption": "none"},
                "streamSettings": {
                    "network": "tcp", "security": "reality", 
                    "realitySettings": {
                        "show": False, "dest": f"127.0.0.1:{PANEL_PORT}", "xver": 0, 
                        "serverNames": [REALITY_SNI], "privateKey": reality_keys["priv"], 
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
        xray_process = subprocess.Popen(["/usr/local/bin/xray", "-config", CFG_FILE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

async def stats_updater():
    await asyncio.sleep(5)
    while True:
        get_sys_info()
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
        now = time.time()
        for uid in list(user_last_active.keys()):
            if now - user_last_active[uid] > 60: del user_last_active[uid]
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
        LINKS[MASTER_UUID] = {"label":"Master","created_at":datetime.now().strftime("%Y-%m-%d %H:%M"),"sni":REALITY_SNI,"status":"active","short_id":secrets.token_hex(4)[:7]}
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
    return {"total_users": len(LINKS), "active_uuids": len(user_last_active), "bytes": stats["bytes"], "uptime": uptime_str(), "ram": sys_info["ram"], "cpu": sys_info["cpu"]}

@app.get("/api/links")
async def api_links(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    dom = get_domain(request); out = []
    for uid, info in LINKS.items():
        out.append({"uuid":uid, "label":info["label"], "created_at":info["created_at"], "used_traffic":user_traffic.get(uid,0), "status":info.get("status","active"), "data_limit":info.get("data_limit",0), "remaining_data":(info.get("data_limit",0)-user_traffic.get(uid,0)) if info.get("data_limit") else 0, "remaining_days":max(0,int((info.get("expiry_time",0)-time.time())/86400)) if info.get("expiry_time") else 0, "short_id":info.get("short_id",""), **make_links(uid, dom, info["label"], info.get("sni",REALITY_SNI), info.get("short_id",""))})
    return {"links": out}

@app.post("/api/links")
async def create_link(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    d = await request.json()
    uid = d.get("uuid") or str(uuid.uuid4())
    LINKS[uid] = {"label":d.get("label","کاربر")[:30], "created_at":datetime.now().strftime("%Y-%m-%d %H:%M"), "sni":d.get("sni",REALITY_SNI), "status":"active", "short_id":d.get("short_id") or secrets.token_hex(4)[:7]}
    if int(d.get("days",0) or 0)>0: LINKS[uid]["expiry_time"]=time.time()+(int(d["days"])*86400)
    if float(d.get("gb",0) or 0)>0: LINKS[uid]["data_limit"]=int(float(d["gb"])*1024**3)
    save_links(); sync_xray_config()
    return {"ok": True, "uuid": uid, **make_links(uid, get_domain(request), LINKS[uid]["label"], LINKS[uid]["sni"], LINKS[uid]["short_id"])}

@app.post("/api/links/{uid}/edit")
async def edit_link(uid: str, request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    if uid not in LINKS: raise HTTPException(404)
    d = await request.json()
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

# ── Health Check & Sub ───────────────────────────────────
@app.get("/health")
async def health(): return {"status": "ok"}

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
    return HTMLResponse(f"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل کاربری</title><style>*{{box-sizing:border-box;margin:0;padding:0;font-family:system-ui}}body{{background:#f0f4ff;color:#1e293b;display:flex;justify-content:center;padding:20px}}.c{{max-width:600px;width:100%}}.h{{text-align:center;margin-bottom:30px}}.h h1{{color:#6366f1;font-size:24px}}.qr{{background:#fff;padding:15px;border-radius:16px;text-align:center;border:1px solid #e2e8f0;margin-bottom:30px}}.qr img{{width:200px;border-radius:12px}}.cfg{{background:#fff;border-radius:12px;padding:15px;margin-bottom:12px;border:1px solid #e2e8f0;display:flex;justify-content:space-between;align-items:center;gap:10px;overflow:hidden}}.ci{{flex:1;overflow:hidden}}.ct{{font-size:13px;font-weight:600;color:#6366f1;margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}.cl{{font-size:10px;color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;direction:ltr;text-align:left}}.cb{{padding:8px 15px;background:#6366f1;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:12px;font-weight:600;white-space:nowrap}}</style></head><body><div class="c"><div class="h"><h1>⚡ {user_info['label']}</h1></div><div class="qr"><img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={links['sub_link']}"></div><div class="cfg"><div class="ci"><div class="ct">🔥 VLESS + Reality + Vision</div><div class="cl">{links['reality']}</div></div><button class="cb" onclick="navigator.clipboard.writeText('{links['reality']}');this.textContent='کپی شد ✓'">کپی</button></div></div></body></html>""")

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
        if ds=="menu": await tg_request("editMessageText", {"chat_id":cid,"message_id":mid,"text":"💡 <b>منوی مدیریت</b>","parse_mode":"HTML","reply_markup":main_menu()})
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
            LINKS[uid]={"label":txt[:30],"created_at":datetime.now().strftime("%Y-%m-%d %H:%M"),"sni":REALITY_SNI,"status":"active","short_id":sid}
            save_links(); sync_xray_config()
            dom = PUBLIC_HOST or "your-domain"
            await send_message(cid, f"✅ ساخته شد!\n👤 {txt}\n🔗 https://{dom}/sub/{sid}", main_menu())
    return {"ok": True}
async def set_telegram_webhook(domain):
    await tg_request("setWebhook", {"url": f"https://{domain}/bot_webhook"})
    await send_message(ADMIN_CHAT_ID, "🤖 ربات فعال شد!", main_menu())
app.include_router(bot_router)

# ── Admin Panel HTML ─────────────────────────────────────
LOGIN_HTML = r"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود — پنل XRAY</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Vazirmatn',sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}.card{background:rgba(255,255,255,0.05);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.1);border-radius:24px;padding:48px 40px;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,0.4)}.logo{text-align:center;margin-bottom:32px}.logo-icon{width:64px;height:64px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:28px;margin-bottom:12px}.logo h1{color:#fff;font-size:22px;font-weight:700}label{display:block;color:rgba(255,255,255,0.7);font-size:13px;margin-bottom:6px}input{width:100%;padding:12px 16px;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);border-radius:12px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:15px;outline:none;transition:.2s}input:focus{border-color:#6366f1;background:rgba(99,102,241,0.1)}.btn{width:100%;padding:13px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;border-radius:12px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:16px;font-weight:600;cursor:pointer;margin-top:24px;transition:.2s}.btn:hover{transform:translateY(-1px);box-shadow:0 8px 25px rgba(99,102,241,0.4)}.err{color:#f87171;font-size:13px;text-align:center;margin-top:12px;min-height:20px}</style></head><body><div class="card"><div class="logo"><div class="logo-icon">⚡</div><h1>پنل XRAY</h1></div><div><label>رمز عبور</label><input type="password" id="p" placeholder="رمز عبور خود را وارد کنید" onkeydown="if(event.key==='Enter')login()"></div><button class="btn" onclick="login()">ورود به پنل</button><div class="err" id="e"></div></div><script>async function login(){const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})});if(r.ok)location.href='/__URL__';else document.getElementById('e').textContent='رمز اشتباه است'}</script></body></html>"""
PANEL_HTML = r"""<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>پنل XRAY</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#f0f4ff;--card:#fff;--accent:#6366f1;--accent2:#8b5cf6;--text:#1e293b;--muted:#64748b;--border:#e2e8f0;--green:#10b981;--red:#ef4444;--yellow:#f59e0b}.dark{--bg:#1e293b;--card:#334155;--accent:#818cf8;--accent2:#a78bfa;--text:#f1f5f9;--muted:#cbd5e1;--border:#475569}body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex}.sidebar{width:220px;min-height:100vh;background:var(--card);border-left:1px solid var(--border);display:flex;flex-direction:column;padding:24px 0;position:fixed;right:0;top:0;bottom:0;z-index:10}.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}.sidebar-logo h2{font-size:18px;font-weight:700;color:var(--accent)}.nav-item{display:flex;align-items:center;gap:10px;padding:11px 20px;cursor:pointer;color:var(--muted);font-size:14px;font-weight:500;transition:.15s;border-radius:0}.nav-item:hover,.nav-item.active{color:var(--accent);background:rgba(99,102,241,0.08)}.nav-item.active{border-right:3px solid var(--accent)}.logout-btn{width:100%;padding:9px;background:none;border:1px solid var(--border);border-radius:10px;color:var(--muted);font-family:'Vazirmatn',sans-serif;font-size:13px;cursor:pointer;transition:.15s}.logout-btn:hover{border-color:var(--red);color:var(--red)}.main{margin-right:220px;flex:1;padding:28px;min-height:100vh}.page{display:none}.page.active{display:block}.page-title{font-size:22px;font-weight:700;margin-bottom:24px;color:var(--text)}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}.stat-card{background:var(--card);border-radius:16px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border)}.stat-val{font-size:26px;font-weight:700;color:var(--text)}.card{background:var(--card);border-radius:16px;box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border);overflow:hidden}.card-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}.btn-add{padding:8px 16px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:10px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:13px;font-weight:600;cursor:pointer;transition:.2s}.btn-add:hover{opacity:.9;transform:translateY(-1px)}table{width:100%;border-collapse:collapse}th{padding:11px 16px;text-align:right;font-size:12px;font-weight:600;color:var(--muted);background:var(--bg);border-bottom:1px solid var(--border)}td{padding:13px 16px;font-size:13px;border-bottom:1px solid var(--border)}.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:600}.badge-green{background:#d1fae5;color:#065f46}.badge-blue{background:#dbeafe;color:#1e40af}.badge-red{background:#fee2e2;color:#991b1b}.btn-sm{padding:5px 11px;border:1px solid var(--border);background:none;border-radius:8px;font-family:'Vazirmatn',sans-serif;font-size:12px;cursor:pointer;transition:.15s;color:var(--muted);margin-right:4px;margin-bottom:4px}.btn-sm:hover{border-color:var(--accent);color:var(--accent)}.overlay{position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:100;display:none;align-items:center;justify-content:center}.overlay.show{display:flex}.modal{background:var(--card);border-radius:20px;padding:28px;width:100%;max-width:480px;box-shadow:0 20px 60px rgba(0,0,0,0.2);max-height:90vh;overflow-y:auto}.modal h3{font-size:17px;font-weight:700;margin-bottom:20px;color:var(--text)}.form-group{margin-bottom:16px}.form-group label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}.form-group input{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:10px;background:var(--bg);color:var(--text);font-family:'Vazirmatn',sans-serif;font-size:14px;outline:none;transition:.2s}.modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}.btn-confirm{padding:9px 18px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:10px;color:#fff;font-family:'Vazirmatn',sans-serif;font-size:13px;font-weight:600;cursor:pointer}.link-box{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:12px}.link-val{font-size:11px;color:var(--muted);word-break:break-all;direction:ltr;text-align:left;line-height:1.6}.mobile-header{display:none}.sidebar-bottom{margin-top:auto;padding:16px 20px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:10px}@media(max-width:768px){.sidebar{width:100%;min-height:auto;position:fixed;bottom:0;top:auto;flex-direction:row;padding:0;border-left:none;border-top:1px solid var(--border)}.sidebar-logo,.sidebar-bottom{display:none}.nav-item{flex-direction:column;gap:3px;padding:8px 0;flex:1;justify-content:center;font-size:10px;border-right:none!important}.nav-item.active{border-top:2px solid var(--accent);border-right:none}.main{margin-right:0;margin-bottom:65px;padding:16px;padding-top:70px}.mobile-header{display:flex;justify-content:space-between;align-items:center;padding:10px 20px;background:var(--card);border-bottom:1px solid var(--border);position:fixed;top:0;left:0;right:0;z-index:20}.mobile-header button{padding:8px 16px;background:none;border:1px solid var(--border);border-radius:10px;color:var(--muted);font-family:'Vazirmatn',sans-serif;font-size:13px;cursor:pointer}}</style></head><body><div class="mobile-header"><button onclick="document.body.classList.toggle('dark')">🌙</button><button onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/__URL__/login')" style="color:var(--red); border-color:var(--red)">خروج</button></div><div class="sidebar"><div class="sidebar-logo"><h2>⚡ پنل XRAY</h2><p>Reality Edition</p></div><div class="nav-item active" onclick="showPage('dashboard',this)"><span>📊</span><span>داشبورد</span></div><div class="nav-item" onclick="showPage('users',this)"><span>👥</span><span>کاربران</span></div><div class="sidebar-bottom"><button class="logout-btn" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/__URL__/login')">خروج</button><button class="logout-btn" onclick="document.body.classList.toggle('dark')">🌙 تم تاریک</button></div></div><div class="main"><div class="page active" id="page-dashboard"><div class="page-title">داشبورد</div><div class="stats-grid"><div class="stat-card"><div class="stat-val" id="s-total">—</div><div style="font-size:12px;color:var(--muted)">کل کاربران</div></div><div class="stat-card"><div class="stat-val" id="s-online">—</div><div style="font-size:12px;color:var(--muted)">آنلاین هم‌اکنون</div></div><div class="stat-card"><div class="stat-val" id="s-bytes">—</div><div style="font-size:12px;color:var(--muted)">ترافیک کل</div></div><div class="stat-card"><div class="stat-val" id="s-ram">—</div><div style="font-size:12px;color:var(--muted)">رم (%)</div></div><div class="stat-card"><div class="stat-val" id="s-cpu">—</div><div style="font-size:12px;color:var(--muted)">پردازنده (%)</div></div></div></div><div class="page" id="page-users"><div class="page-title">کاربران</div><div class="card"><div class="card-header"><h3>لیست کاربران</h3><button class="btn-add" onclick="document.getElementById('add-modal').classList.add('show')">+ کاربر جدید</button></div><table><thead><tr><th>نام</th><th>UUID</th><th>حجم</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody id="ut"></tbody></table></div></div></div><div class="overlay" id="add-modal"><div class="modal"><h3>کاربر جدید</h3><div class="form-group"><label>نام کاربر</label><input id="nl" placeholder="مثلاً: علی"></div><div class="form-group"><label>محدودیت حجم (GB) - 0 یعنی نامحدود</label><input type="number" id="ng" value="0"></div><div class="form-group"><label>انقضا (روز) - 0 یعنی نامحدود</label><input type="number" id="nd" value="0"></div><div class="modal-footer"><button class="btn-sm" onclick="document.getElementById('add-modal').classList.remove('show')">انصراف</button><button class="btn-confirm" onclick="cu()">ساخت کاربر</button></div></div></div><div class="overlay" id="link-modal"><div class="modal"><h3 id="lt">کانفیگ‌ها</h3><div class="link-box" style="text-align:center"><div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px">🚀 لینک اشتراک (Sub Link)</div><div class="link-val" id="ls">—</div><button class="btn-sm" style="background:var(--accent);color:#fff;border:none" onclick="navigator.clipboard.writeText(document.getElementById('ls').textContent);alert('کپی شد')">کپی Sub Link</button></div><div style="text-align:center;margin-bottom:15px"><button class="btn-confirm" onclick="copyAll()">📋 کپی کانفیگ</button></div><div class="link-box"><div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px">🔥 VLESS + Reality + Vision</div><div class="link-val" id="lr">—</div><button class="btn-sm" onclick="navigator.clipboard.writeText(document.getElementById('lr').textContent);alert('کپی شد')">کپی</button></div><div class="modal-footer"><button class="btn-confirm" onclick="document.getElementById('link-modal').classList.remove('show')">بستن</button></div></div></div><script>var au={};function showPage(n,e){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.nav-item').forEach(i=>i.classList.remove('active'));document.getElementById('p-'+n).classList.add('active');e.classList.add('active');if(n=='users')lu()}async function ls(){try{const r=await fetch('/api/stats');const d=await r.json();document.getElementById('s-total').textContent=d.total_users;document.getElementById('s-online').textContent=d.active_uuids;document.getElementById('s-bytes').textContent=fb(d.bytes);document.getElementById('s-ram').textContent=d.ram+'%';document.getElementById('s-cpu').textContent=d.cpu+'%'}catch(e){}}function fb(b){if(b<1024)return b+'B';if(b<1024**2)return(b/1024).toFixed(1)+'K';if(b<1024**3)return(b/1024**2).toFixed(2)+'M';return(b/1024**3).toFixed(2)+'G'}async function lu(){const r=await fetch('/api/links');const d=await r.json();document.getElementById('ut').innerHTML=d.links.map(u=>{au[u.uuid]=u;let s='<span class="badge badge-blue">🟢 آنلاین</span>';if(u.status=='expired')s='<span class="badge badge-red">منقضی</span>';return `<tr><td><span class="badge badge-green">${u.label}</span></td><td>${u.uuid.substr(0,8)}…</td><td>${fb(u.used_traffic)}</td><td>${s}</td><td><button class="btn-sm" onclick='sl(${JSON.stringify(u)})'>🔗 لینک</button> <button class="btn-sm" onclick="fetch('/api/links/${u.uuid}/extend',{method:'POST'}).then(lu)">➕ ۳۰ روز</button> <button class="btn-sm" style="color:var(--red)" onclick="fetch('/api/links/${u.uuid}',{method:'DELETE'}).then(lu)">حذف</button></td></tr>`}).join('')}async function cu(){const l=nl.value||'کاربر';const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:l,gb:ng.value,days:nd.value})});const d=await r.json();document.getElementById('add-modal').classList.remove('show');nl.value='';sl(d);lu()}function sl(u){document.getElementById('lt').textContent='کانفیگ‌های '+u.label;document.getElementById('ls').textContent=u.sub_link;document.getElementById('lr').textContent=u.reality;document.getElementById('link-modal').classList.add('show')}function copyAll(){navigator.clipboard.writeText(document.getElementById('lr').textContent);alert('کانفیگ کپی شد ✓')}ls();setInterval(ls,5000)</script></body></html>"""

@app.get("/" + ADMIN_PATH, response_class=HTMLResponse)
async def panel_page(token: Optional[str] = Cookie(None)):
    if not auth_check(token): return RedirectResponse("/" + ADMIN_PATH + "/login")
    return HTMLResponse(PANEL_HTML.replace("__URL__", ADMIN_PATH))

@app.get("/" + ADMIN_PATH + "/login", response_class=HTMLResponse)
async def login_page(): return HTMLResponse(LOGIN_HTML.replace("__URL__", ADMIN_PATH))

@app.get("/")
async def root(): return Response(content=b"OK", media_type="text/plain")

if __name__ == "__main__":
    import logging; logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    # پایتون روی پورت داخلی 5000 اجرا می‌شود، Xray روی پورت اصلی (PORT) است
    uvicorn.run("panel:app", host="127.0.0.1", port=PANEL_PORT, reload=False, log_level="warning")