"""
پنل مدیریت XRAY — FastAPI
کار می‌کند روی Railway / Render
Xray روی پورت داخلی 8080 (WS) و 8081 (XHTTP)
پنل روی پورت اصلی PORT
"""
import os, json, uuid, asyncio, hashlib, secrets, time
from datetime import datetime
from collections import deque
from typing import Optional
from fastapi import FastAPI, Request, Response, HTTPException, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.websockets import WebSocket, WebSocketDisconnect
import httpx, uvicorn
import websockets as _ws

# ── تنظیمات ──────────────────────────────────────────────
PORT         = int(os.environ.get("PORT", 8000))
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "admin1234")
ADMIN_PATH   = os.environ.get("ADMIN_PATH", "panel").strip("/")
PUBLIC_HOST  = os.environ.get("PUBLIC_HOST", "")
XRAY_WS_PORT = 18080
XRAY_XH_PORT = 18081

PASS_HASH = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()

# ── state ─────────────────────────────────────────────────
SESSIONS: dict[str, float] = {}   # token → expire
LINKS: dict = {}                   # uuid → {label, created_at}
error_log: deque = deque(maxlen=50)
stats = {"connections": 0, "bytes": 0, "start": time.time()}

app = FastAPI(docs_url=None, redoc_url=None)

# ── helpers ───────────────────────────────────────────────
def get_domain(request: Request) -> str:
    h = (PUBLIC_HOST or
         os.environ.get("RENDER_EXTERNAL_URL","") or
         os.environ.get("RAILWAY_PUBLIC_DOMAIN","") or
         request.headers.get("host","localhost"))
    return h.replace("https://","").replace("http://","").strip("/")

def make_links(uid: str, domain: str, label: str) -> dict:
    ws   = (f"vless://{uid}@{domain}:443?"
            f"encryption=none&security=tls&type=ws"
            f"&host={domain}&path=%2Fws%2F{uid}"
            f"&sni={domain}&fp=chrome#{label}-WS")
    xhttp = (f"vless://{uid}@{domain}:443?"
             f"encryption=none&security=tls&type=xhttp"
             f"&host={domain}&path=%2Fxh%2F{uid}"
             f"&sni={domain}&fp=chrome&mode=auto#{label}-XHTTP")
    return {"ws": ws, "xhttp": xhttp}

def auth_check(token: Optional[str] = Cookie(None)) -> bool:
    if not token:
        return False
    exp = SESSIONS.get(token, 0)
    return time.time() < exp

def uptime_str() -> str:
    s = int(time.time() - stats["start"])
    h, r = divmod(s, 3600); m, sc = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{sc:02d}"

# ── auth ──────────────────────────────────────────────────
@app.post("/api/login")
async def login(request: Request):
    d = await request.json()
    if hashlib.sha256(d.get("password","").encode()).hexdigest() != PASS_HASH:
        raise HTTPException(403, "رمز اشتباه است")
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = time.time() + 86400
    r = JSONResponse({"ok": True})
    r.set_cookie("token", token, httponly=True, samesite="lax", max_age=86400)
    return r

@app.post("/api/logout")
async def logout(token: Optional[str] = Cookie(None)):
    SESSIONS.pop(token, None)
    r = JSONResponse({"ok": True})
    r.delete_cookie("token")
    return r

# ── API ───────────────────────────────────────────────────
@app.get("/api/stats")
async def api_stats(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    return {
        "connections": stats["connections"],
        "bytes":       stats["bytes"],
        "uptime":      uptime_str(),
        "users":       len(LINKS),
    }

@app.get("/api/links")
async def api_links(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    domain = get_domain(request)
    out = []
    for uid, info in LINKS.items():
        lnk = make_links(uid, domain, info["label"])
        out.append({"uuid": uid, "label": info["label"],
                    "created_at": info["created_at"], **lnk})
    return {"links": out}

@app.post("/api/links")
async def create_link(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    d = await request.json()
    uid = d.get("uuid") or str(uuid.uuid4())
    label = d.get("label", "کاربر")
    LINKS[uid] = {"label": label, "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")}
    domain = get_domain(request)
    return {"ok": True, "uuid": uid, **make_links(uid, domain, label)}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    LINKS.pop(uid, None)
    return {"ok": True}

@app.post("/api/change-password")
async def change_pass(request: Request, token: Optional[str] = Cookie(None)):
    if not auth_check(token): raise HTTPException(401)
    global PASS_HASH
    d = await request.json()
    if hashlib.sha256(d.get("current","").encode()).hexdigest() != PASS_HASH:
        raise HTTPException(403, "رمز فعلی اشتباه است")
    PASS_HASH = hashlib.sha256(d.get("new","").encode()).hexdigest()
    return {"ok": True}

# ── Proxy WS → Xray (مشکل ۳ رفع شد) ──────────────────────────────
@app.websocket("/ws/{uid}")
async def ws_proxy(websocket: WebSocket, uid: str):
    if uid not in LINKS:
        await websocket.close(1008); return
    await websocket.accept()
    stats["connections"] += 1
    
    # ساخت تارگت با احتمال وجود Query String
    target = f"ws://127.0.0.1:{XRAY_WS_PORT}/ws/{uid}"
    if websocket.url.query:
        target += f"?{websocket.url.query}"
        
    try:
        # کانکشن به Xray
        async with _ws.connect(target) as xray_ws:
            
            async def c2x():
                try:
                    while True:
                        # استفاده از receive به جای receive_bytes تا هم دیتای متنی و هم باینری هندل شود
                        msg = await websocket.receive()
                        if msg["type"] == "websocket.disconnect":
                            break
                        if "text" in msg:
                            await xray_ws.send(msg["text"])
                        elif "bytes" in msg:
                            await xray_ws.send(msg["bytes"])
                            stats["bytes"] += len(msg["bytes"])
                except WebSocketDisconnect:
                    pass
                except Exception:
                    pass

            async def x2c():
                try:
                    async for msg in xray_ws:
                        if isinstance(msg, str):
                            await websocket.send_text(msg)
                        else:
                            await websocket.send_bytes(msg)
                            stats["bytes"] += len(msg)
                except Exception:
                    pass

            t1 = asyncio.create_task(c2x())
            t2 = asyncio.create_task(x2c())
            await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            t1.cancel(); t2.cancel()
    except Exception as e:
        error_log.append({"e": str(e), "t": datetime.now().isoformat()})
    finally:
        stats["connections"] = max(0, stats["connections"] - 1)
        try: await websocket.close()
        except: pass

# ── Proxy XHTTP → Xray (مشکل ۱ و ۲ رفع شد) ───────────────────────────
@app.api_route("/xh/{path:path}", methods=["GET","POST"])
async def xhttp_proxy(path: str, request: Request):
    # استخراج UUID از ابتدای مسیر (مثلا uuid/0 -> uuid)
    parts = path.split('/', 1)
    uid = parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    
    if uid not in LINKS:
        raise HTTPException(404)
        
    # ساخت URL هدف برای Xray
    target = f"http://127.0.0.1:{XRAY_XH_PORT}/xh/{uid}"
    if rest:
        target += f"/{rest}"
        
    # فیلتر کردن هدرها برای جلوگیری از تداخل پروکسی
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ['host', 'content-length', 'connection']}
    
    if request.method == "POST":
        # مشکل ۲: هندل صحیح درخواست‌های POST (آپلود در XHTTP)
        body = await request.body()
        stats["bytes"] += len(body)
        
        # حل مشکل ۱: کلاینت httpx باید در همین بلوک باز و بسته شود
        async with httpx.AsyncClient(timeout=120) as c:
            try:
                r = await c.post(target, content=body, headers=headers)
                # حذف هدرهای تداخل‌زا از پاسخ Xray
                resp_headers = {k: v for k, v in r.headers.items() if k.lower() not in ['content-encoding', 'transfer-encoding', 'connection']}
                return Response(content=r.content, status_code=r.status_code, headers=resp_headers)
            except Exception:
                return Response(status_code=502)
    else:
        # مشکل ۱: برای استریم، کلاینت باید داخل جنریتور ساخته شود تا تا پایان استریم زنده بماند
        async def gen():
            async with httpx.AsyncClient(timeout=120) as c:
                try:
                    async with c.stream("GET", target, headers=headers) as r:
                        async for chunk in r.aiter_raw():
                            stats["bytes"] += len(chunk)
                            yield chunk
                except Exception:
                    pass # در صورت بسته شدن کانکشن توسط کلاینت، خطا ندهد
                    
        return StreamingResponse(gen(), media_type="application/octet-stream",
            headers={"Cache-Control":"no-store","X-Accel-Buffering":"no"})

# ── صفحه لاگین ───────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ورود — پنل XRAY</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Vazirmatn',sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);
  min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:rgba(255,255,255,0.05);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.1);
  border-radius:24px;padding:48px 40px;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,0.4)}
.logo{text-align:center;margin-bottom:32px}
.logo-icon{width:64px;height:64px;background:linear-gradient(135deg,#6366f1,#8b5cf6);
  border-radius:16px;display:inline-flex;align-items:center;justify-content:center;
  font-size:28px;margin-bottom:12px}
.logo h1{color:#fff;font-size:22px;font-weight:700}
.logo p{color:rgba(255,255,255,0.5);font-size:13px;margin-top:4px}
label{display:block;color:rgba(255,255,255,0.7);font-size:13px;margin-bottom:6px}
input{width:100%;padding:12px 16px;background:rgba(255,255,255,0.08);
  border:1px solid rgba(255,255,255,0.15);border-radius:12px;color:#fff;
  font-family:'Vazirmatn',sans-serif;font-size:15px;outline:none;transition:.2s}
input:focus{border-color:#6366f1;background:rgba(99,102,241,0.1)}
.btn{width:100%;padding:13px;background:linear-gradient(135deg,#6366f1,#8b5cf6);
  border:none;border-radius:12px;color:#fff;font-family:'Vazirmatn',sans-serif;
  font-size:16px;font-weight:600;cursor:pointer;margin-top:24px;transition:.2s}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 25px rgba(99,102,241,0.4)}
.err{color:#f87171;font-size:13px;text-align:center;margin-top:12px;min-height:20px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">⚡</div>
    <h1>پنل XRAY</h1>
    <p>مدیریت کانفیگ‌های پروکسی</p>
  </div>
  <div>
    <label>رمز عبور</label>
    <input type="password" id="pass" placeholder="رمز عبور خود را وارد کنید"
           onkeydown="if(event.key==='Enter')login()">
  </div>
  <button class="btn" onclick="login()">ورود به پنل</button>
  <div class="err" id="err"></div>
</div>
<script>
async function login(){
  const p=document.getElementById('pass').value;
  const r=await fetch('/api/login',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});
  if(r.ok) location.href='/ADMIN_PATH_PLACEHOLDER';
  else document.getElementById('err').textContent='رمز عبور اشتباه است';
}
</script>
</body></html>"""

# ── داشبورد اصلی ─────────────────────────────────────────
PANEL_HTML = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>پنل XRAY</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f0f4ff;--card:#fff;--accent:#6366f1;--accent2:#8b5cf6;
  --text:#1e293b;--muted:#64748b;--border:#e2e8f0;--green:#10b981;--red:#ef4444}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex}

/* Sidebar */
.sidebar{width:220px;min-height:100vh;background:var(--card);border-left:1px solid var(--border);
  display:flex;flex-direction:column;padding:24px 0;position:fixed;right:0;top:0;bottom:0;z-index:10}
.sidebar-logo{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}
.sidebar-logo h2{font-size:18px;font-weight:700;color:var(--accent)}
.sidebar-logo p{font-size:11px;color:var(--muted);margin-top:2px}
.nav-item{display:flex;align-items:center;gap:10px;padding:11px 20px;cursor:pointer;
  color:var(--muted);font-size:14px;font-weight:500;transition:.15s;border-radius:0}
.nav-item:hover,.nav-item.active{color:var(--accent);background:rgba(99,102,241,0.08)}
.nav-item.active{border-right:3px solid var(--accent)}
.nav-icon{font-size:18px;width:22px;text-align:center}
.sidebar-bottom{margin-top:auto;padding:16px 20px;border-top:1px solid var(--border)}
.logout-btn{width:100%;padding:9px;background:none;border:1px solid var(--border);
  border-radius:10px;color:var(--muted);font-family:'Vazirmatn',sans-serif;
  font-size:13px;cursor:pointer;transition:.15s}
.logout-btn:hover{border-color:var(--red);color:var(--red)}

/* Main */
.main{margin-right:220px;flex:1;padding:28px;min-height:100vh}
.page{display:none}.page.active{display:block}
.page-title{font-size:22px;font-weight:700;margin-bottom:24px;color:var(--text)}

/* Stats cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}
.stat-card{background:var(--card);border-radius:16px;padding:20px;
  box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border)}
.stat-icon{font-size:24px;margin-bottom:10px}
.stat-val{font-size:26px;font-weight:700;color:var(--text)}
.stat-label{font-size:12px;color:var(--muted);margin-top:2px}

/* Table */
.card{background:var(--card);border-radius:16px;box-shadow:0 1px 3px rgba(0,0,0,0.06);
  border:1px solid var(--border);overflow:hidden}
.card-header{padding:18px 20px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between}
.card-header h3{font-size:15px;font-weight:600}
.btn-add{padding:8px 16px;background:linear-gradient(135deg,var(--accent),var(--accent2));
  border:none;border-radius:10px;color:#fff;font-family:'Vazirmatn',sans-serif;
  font-size:13px;font-weight:600;cursor:pointer;transition:.2s}
.btn-add:hover{opacity:.9;transform:translateY(-1px)}
table{width:100%;border-collapse:collapse}
th{padding:11px 16px;text-align:right;font-size:12px;font-weight:600;
  color:var(--muted);background:#f8fafc;border-bottom:1px solid var(--border)}
td{padding:13px 16px;font-size:13px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafc}
.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:600}
.badge-green{background:#d1fae5;color:#065f46}
.tag{display:inline-block;padding:2px 8px;background:rgba(99,102,241,0.1);
  color:var(--accent);border-radius:6px;font-size:11px}
.btn-sm{padding:5px 11px;border:1px solid var(--border);background:none;
  border-radius:8px;font-family:'Vazirmatn',sans-serif;font-size:12px;
  cursor:pointer;transition:.15s;color:var(--muted)}
.btn-sm:hover{border-color:var(--accent);color:var(--accent)}
.btn-del{color:var(--red)}.btn-del:hover{border-color:var(--red);color:var(--red)}

/* Modal */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:100;
  display:none;align-items:center;justify-content:center}
.overlay.show{display:flex}
.modal{background:#fff;border-radius:20px;padding:28px;width:100%;max-width:480px;
  box-shadow:0 20px 60px rgba(0,0,0,0.2)}
.modal h3{font-size:17px;font-weight:700;margin-bottom:20px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
.form-group input{width:100%;padding:10px 14px;border:1px solid var(--border);
  border-radius:10px;font-family:'Vazirmatn',sans-serif;font-size:14px;
  outline:none;transition:.2s}
.form-group input:focus{border-color:var(--accent)}
.modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}
.btn-cancel{padding:9px 18px;border:1px solid var(--border);background:none;
  border-radius:10px;font-family:'Vazirmatn',sans-serif;cursor:pointer;font-size:13px}
.btn-confirm{padding:9px 18px;background:linear-gradient(135deg,var(--accent),var(--accent2));
  border:none;border-radius:10px;color:#fff;font-family:'Vazirmatn',sans-serif;
  font-size:13px;font-weight:600;cursor:pointer}

/* Links modal */
.link-box{background:#f8fafc;border:1px solid var(--border);border-radius:10px;
  padding:12px;margin-bottom:12px}
.link-type{font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px}
.link-val{font-size:11px;color:var(--muted);word-break:break-all;direction:ltr;
  text-align:left;line-height:1.6}
.copy-btn{margin-top:8px;padding:5px 12px;background:var(--accent);border:none;
  border-radius:7px;color:#fff;font-family:'Vazirmatn',sans-serif;
  font-size:11px;cursor:pointer}

/* Settings */
.settings-card{background:var(--card);border-radius:16px;padding:24px;
  box-shadow:0 1px 3px rgba(0,0,0,0.06);border:1px solid var(--border);max-width:480px}
.settings-card h3{font-size:15px;font-weight:600;margin-bottom:20px}

/* Responsive */
@media(max-width:768px){
  .sidebar{width:100%;min-height:auto;position:fixed;bottom:0;top:auto;
    flex-direction:row;padding:0;border-left:none;border-top:1px solid var(--border)}
  .sidebar-logo,.sidebar-bottom{display:none}
  .nav-item{flex-direction:column;gap:3px;padding:8px 0;flex:1;justify-content:center;
    font-size:10px;border-right:none!important}
  .nav-item.active{border-top:2px solid var(--accent);border-right:none}
  .nav-icon{font-size:20px}
  .main{margin-right:0;margin-bottom:65px;padding:16px}
}
</style>
</head>
<body>

<div class="sidebar">
  <div class="sidebar-logo">
    <h2>⚡ پنل XRAY</h2>
    <p>مدیریت پروکسی</p>
  </div>
  <div class="nav-item active" onclick="showPage('dashboard',this)">
    <span class="nav-icon">📊</span><span>داشبورد</span>
  </div>
  <div class="nav-item" onclick="showPage('users',this)">
    <span class="nav-icon">👥</span><span>کاربران</span>
  </div>
  <div class="nav-item" onclick="showPage('settings',this)">
    <span class="nav-icon">⚙️</span><span>تنظیمات</span>
  </div>
  <div class="sidebar-bottom">
    <button class="logout-btn" onclick="logout()">خروج</button>
  </div>
</div>

<div class="main">

  <!-- داشبورد -->
  <div class="page active" id="page-dashboard">
    <div class="page-title">داشبورد</div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon">👥</div>
        <div class="stat-val" id="s-users">—</div>
        <div class="stat-label">کاربران</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">🔌</div>
        <div class="stat-val" id="s-conn">—</div>
        <div class="stat-label">اتصال فعال</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">📦</div>
        <div class="stat-val" id="s-bytes">—</div>
        <div class="stat-label">ترافیک کل</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">⏱️</div>
        <div class="stat-val" id="s-uptime">—</div>
        <div class="stat-label">آپتایم</div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><h3>اتصال‌های فعال</h3></div>
      <div style="padding:20px;color:var(--muted);font-size:13px;text-align:center" id="conn-info">
        در حال بارگذاری...
      </div>
    </div>
  </div>

  <!-- کاربران -->
  <div class="page" id="page-users">
    <div class="page-title">کاربران</div>
    <div class="card">
      <div class="card-header">
        <h3>لیست کاربران</h3>
        <button class="btn-add" onclick="openAdd()">+ کاربر جدید</button>
      </div>
      <table>
        <thead>
          <tr><th>نام</th><th>UUID</th><th>تاریخ ساخت</th><th>عملیات</th></tr>
        </thead>
        <tbody id="users-tbody">
          <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:24px">
            در حال بارگذاری...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- تنظیمات -->
  <div class="page" id="page-settings">
    <div class="page-title">تنظیمات</div>
    <div class="settings-card">
      <h3>تغییر رمز عبور</h3>
      <div class="form-group">
        <label>رمز فعلی</label>
        <input type="password" id="cp-old" placeholder="رمز عبور فعلی">
      </div>
      <div class="form-group">
        <label>رمز جدید</label>
        <input type="password" id="cp-new" placeholder="رمز عبور جدید">
      </div>
      <button class="btn-confirm" onclick="changePass()" style="width:100%;padding:11px">
        تغییر رمز عبور
      </button>
      <div id="cp-msg" style="margin-top:10px;font-size:13px;text-align:center"></div>
    </div>
  </div>

</div>

<!-- Modal ساخت کاربر -->
<div class="overlay" id="add-modal">
  <div class="modal">
    <h3>کاربر جدید</h3>
    <div class="form-group">
      <label>نام کاربر</label>
      <input id="new-label" placeholder="مثلاً: علی">
    </div>
    <div class="form-group">
      <label>UUID (اختیاری — خودکار تولید می‌شود)</label>
      <input id="new-uuid" placeholder="خالی بگذارید">
    </div>
    <div class="modal-footer">
      <button class="btn-cancel" onclick="closeAdd()">انصراف</button>
      <button class="btn-confirm" onclick="createUser()">ساخت کاربر</button>
    </div>
  </div>
</div>

<!-- Modal لینک‌ها -->
<div class="overlay" id="link-modal">
  <div class="modal">
    <h3 id="link-modal-title">کانفیگ‌ها</h3>
    <div class="link-box">
      <div class="link-type">🔗 VLESS + WebSocket + TLS</div>
      <div class="link-val" id="lnk-ws">—</div>
      <button class="copy-btn" onclick="copy('lnk-ws')">کپی</button>
    </div>
    <div class="link-box">
      <div class="link-type">⚡ VLESS + XHTTP + TLS</div>
      <div class="link-val" id="lnk-xhttp">—</div>
      <button class="copy-btn" onclick="copy('lnk-xhttp')">کپی</button>
    </div>
    <div class="modal-footer">
      <button class="btn-confirm" onclick="closeLinks()">بستن</button>
    </div>
  </div>
</div>

<script>
function showPage(name, el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  el.classList.add('active');
  if(name==='users') loadUsers();
}

async function logout(){
  await fetch('/api/logout',{method:'POST'});
  location.href='/LOGIN_PATH_PLACEHOLDER';
}

// آمار
async function loadStats(){
  try{
    const r=await fetch('/api/stats');
    if(r.status===401){location.href='/LOGIN_PATH_PLACEHOLDER';return}
    const d=await r.json();
    document.getElementById('s-users').textContent=d.users;
    document.getElementById('s-conn').textContent=d.connections;
    document.getElementById('s-bytes').textContent=fmtBytes(d.bytes);
    document.getElementById('s-uptime').textContent=d.uptime;
    document.getElementById('conn-info').textContent=
      d.connections>0?`${d.connections} اتصال فعال`:'هیچ اتصالی فعال نیست';
  }catch(e){}
}

function fmtBytes(b){
  if(b<1024)return b+'B';
  if(b<1024*1024)return (b/1024).toFixed(1)+'KB';
  if(b<1024**3)return (b/1024/1024).toFixed(2)+'MB';
  return (b/1024**3).toFixed(2)+'GB';
}

// کاربران
async function loadUsers(){
  const r=await fetch('/api/links');
  if(r.status===401){location.href='/LOGIN_PATH_PLACEHOLDER';return}
  const d=await r.json();
  const tb=document.getElementById('users-tbody');
  if(!d.links.length){
    tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:24px">کاربری وجود ندارد</td></tr>';
    return;
  }
  tb.innerHTML=d.links.map(u=>`
    <tr>
      <td><span class="badge badge-green">${u.label}</span></td>
      <td><span class="tag">${u.uuid.substring(0,8)}…</span></td>
      <td>${u.created_at}</td>
      <td style="display:flex;gap:6px">
        <button class="btn-sm" onclick='showLinks(${JSON.stringify(u)})'>🔗 لینک</button>
        <button class="btn-sm btn-del" onclick="delUser('${u.uuid}')">حذف</button>
      </td>
    </tr>`).join('');
}

// ساخت
function openAdd(){document.getElementById('add-modal').classList.add('show')}
function closeAdd(){document.getElementById('add-modal').classList.remove('show')}

async function createUser(){
  const label=document.getElementById('new-label').value||'کاربر';
  const uid=document.getElementById('new-uuid').value||null;
  const r=await fetch('/api/links',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({label,uuid:uid})});
  const d=await r.json();
  closeAdd();
  document.getElementById('new-label').value='';
  document.getElementById('new-uuid').value='';
  showLinks(d);
  loadUsers();
}

async function delUser(uid){
  if(!confirm('حذف این کاربر؟'))return;
  await fetch('/api/links/'+uid,{method:'DELETE'});
  loadUsers();
}

// لینک‌ها
function showLinks(u){
  document.getElementById('link-modal-title').textContent='کانفیگ‌های '+u.label;
  document.getElementById('lnk-ws').textContent=u.ws;
  document.getElementById('lnk-xhttp').textContent=u.xhttp;
  document.getElementById('link-modal').classList.add('show');
}
function closeLinks(){document.getElementById('link-modal').classList.remove('show')}

function copy(id){
  navigator.clipboard.writeText(document.getElementById(id).textContent);
  alert('کپی شد ✓');
}

// تغییر رمز
async function changePass(){
  const r=await fetch('/api/change-password',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({current:document.getElementById('cp-old').value,
                         new:document.getElementById('cp-new').value})});
  const m=document.getElementById('cp-msg');
  if(r.ok){m.style.color='var(--green)';m.textContent='رمز با موفقیت تغییر کرد ✓'}
  else{m.style.color='var(--red)';m.textContent='رمز فعلی اشتباه است'}
}

loadStats();
setInterval(loadStats, 5000);
</script>
</body></html>"""

# ── Routes پنل ───────────────────────────────────────────
@app.get(f"/{ADMIN_PATH}/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(LOGIN_HTML.replace("ADMIN_PATH_PLACEHOLDER", ADMIN_PATH))

@app.get(f"/{ADMIN_PATH}", response_class=HTMLResponse)
async def panel_page(token: Optional[str] = Cookie(None)):
    if not auth_check(token):
        return RedirectResponse(f"/{ADMIN_PATH}/login")
    html = PANEL_HTML.replace("LOGIN_PATH_PLACEHOLDER", f"/{ADMIN_PATH}/login")
    return HTMLResponse(html)

@app.get("/")
async def root():
    return Response(content=b"OK", media_type="text/plain")

@app.get("/health")
async def health():
    return {"status": "ok", "connections": stats["connections"]}

if __name__ == "__main__":
    uvicorn.run("panel:app", host="0.0.0.0", port=PORT, reload=False)