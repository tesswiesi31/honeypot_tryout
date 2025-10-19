import os, json, requests
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter, defaultdict

from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

# --- Config ---
APP_ENV = os.getenv("APP_ENV", "dev")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "admin123")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
EVENT_LOG = os.getenv("EVENT_LOG", "events.jsonl")

# Telegram
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT = os.getenv("TELEGRAM_CHAT", "")

# --- App setup ---
Path(EVENT_LOG).touch(exist_ok=True)
app = FastAPI(title="tryout")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if APP_ENV=="dev" else [],
    allow_methods=["*"],
    allow_headers=["*"]
)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", session_cookie="hp_admin")

# --- Honey routes ---
HONEY_ROUTES = {"/Jack","/Emi","/Noah","/Lexi","/John","/Mark","/Noelle"}

# --- Utility functions ---
def now(): return datetime.now(tz=timezone.utc).isoformat()
def sid(req: Request): return req.cookies.get("hp_sid") or str(uuid4())
def ip(req: Request): return req.headers.get("x-forwarded-for","").split(",")[0].strip() or (req.client.host if req.client else "0.0.0.0")
def log(event: dict): open(EVENT_LOG,"a",encoding="utf-8").write(json.dumps(event,ensure_ascii=False)+"\n")
def is_logged_in(req: Request): return req.session.get("user") == ADMIN_USER

def notify_telegram(msg: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT: return
    try:
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                      json={"chat_id": TELEGRAM_CHAT, "text": msg}, timeout=3)
    except Exception as e:
        print("Telegram notify failed:", e)

# --- Middleware for logging ---
@app.middleware("http")
async def logger(req: Request, call_next):
    s = sid(req)
    route = req.url.path
    log({"ts": now(), "kind": "request", "sid": s, "ip": ip(req), "route": route, "method": req.method})
    res = await call_next(req)
    log({"ts": now(), "kind": "response", "sid": s, "ip": ip(req), "route": route, "status": res.status_code, "is_honey": route in HONEY_ROUTES})
    if "hp_sid" not in req.cookies:
        res.set_cookie("hp_sid", s, httponly=True, samesite="lax")
    return res

# --- Serve HTML files from root ---
def serve_html(filename: str, replacements: dict = None):
    path = Path(filename)
    if path.exists():
        content = path.read_text(encoding="utf-8")
        if replacements:
            for k, v in replacements.items():
                content = content.replace(k, v)
        return HTMLResponse(content)
    return HTMLResponse("<h1>File not found</h1>", status_code=404)

# --- Index & profiles ---
@app.get("/", response_class=HTMLResponse)
def index(): return serve_html("index.html")

PROFILES = ["Jack","Emi","Noah","Lexi","John","Mark","Noelle"]

for p in PROFILES:
    def make_profile_route(profile_name):
        async def profile(request: Request):
            notify_telegram(f"🚨 ALERT: Someone accessed profile {profile_name}! IP: {ip(request)}")
            return serve_html(f"{profile_name.lower()}.html")
        return profile
    app.get(f"/{p}")(make_profile_route(p))

# --- Event tracking ---
@app.post("/event")
async def track_event(request: Request):
    try: data = await request.json()
    except: data = {}
    s = sid(request)
    e = {"ts": now(), "kind":"client", "sid": s, "ip": ip(request),
         "action": str(data.get("action")), "label": str(data.get("label"))}
    log(e)
    if e["action"]=="click" and e["label"] in PROFILES:
        notify_telegram(f"👆 Click detected: {e['label']} | IP: {e['ip']}")
    return {"ok": True}

# --- Login / Logout ---
@app.get("/login", response_class=HTMLResponse)
def login_form(): return serve_html("login.html", {"{error_msg}": ""})

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), request: Request = None):
    if username == ADMIN_USER and password == ADMIN_PASS:
        request.session["user"] = ADMIN_USER
        return RedirectResponse("/_admin/logs", status_code=status.HTTP_303_SEE_OTHER)
    return serve_html("login.html", {"{error_msg}": "<p style='color:red'>Login failed</p>"})

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

# --- Admin utilities ---
def _parse_ts(s: str):
    try: return datetime.fromisoformat(s.replace("Z","+00:00"))
    except: return None

@app.get("/_admin/logs", response_class=HTMLResponse)
def admin_logs(request: Request, tail: int = 200):
    if not is_logged_in(request): return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    p = Path(EVENT_LOG)
    lines = p.read_text(encoding="utf-8").splitlines()[-tail:] if p.exists() else []
    return serve_html("logs.html", {"{events}": "".join(f"<div><code>{ln}</code></div>" for ln in lines)})

@app.get("/_admin/stats", response_class=HTMLResponse)
def admin_stats(request: Request):
    if not is_logged_in(request): return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    p = Path(EVENT_LOG)
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=168)

    per_ip = Counter()
    per_route = Counter()
    click_labels = Counter()
    last_seen = {}
    sessions_per_ip = defaultdict(set)

    for ln in p.read_text(encoding="utf-8").splitlines():
        try: obj = json.loads(ln)
        except: continue
        t = _parse_ts(obj.get("ts",""))
        if t and t < cutoff: continue
        k = obj.get("kind")
        ipp = obj.get("ip","-")
        s = obj.get("sid","-")
        r = obj.get("route","-")
        if k in ("request","response"): per_ip[ipp]+=1; per_route[r]+=1
        if k=="client" and obj.get("action")=="click": click_labels[obj.get("label","(unlabeled)")] += 1
        last_seen[ipp] = max(last_seen.get(ipp, t or datetime.min.replace(tzinfo=timezone.utc)), t or datetime.min.replace(tzinfo=timezone.utc))
        sessions_per_ip[ipp].add(s)

    def table(title, pairs, limit=10):
        rows = "".join(f"<tr><td>{i+1}</td><td>{k}</td><td>{v}</td></tr>" for i,(k,v) in enumerate(pairs[:limit]))
        return f"<h3>{title}</h3><table border='1' cellpadding='6'><tr><th>#</th><th>Value</th><th>Count</th></tr>{rows}</table>"

    per_ip_sorted = sorted(per_ip.items(), key=lambda kv: kv[1], reverse=True)
    per_route_sorted = sorted(per_route.items(), key=lambda kv: kv[1], reverse=True)
    clicks_sorted = sorted(click_labels.items(), key=lambda kv: kv[1], reverse=True)

    ip_details = "".join(f"<tr><td>{ip}</td><td>{len(sessions_per_ip[ip])}</td><td>{last_seen[ip]}</td></tr>" for ip,_ in per_ip_sorted[:20])
    ip_details_html = f"<h3>Top IPs – Details</h3><table border='1' cellpadding='6'><tr><th>IP</th><th>Sessions</th><th>Last Seen (UTC)</th></tr>{ip_details}</table>"

    return serve_html("stats.html", {"{tables}": table('Top IPs (Event Count)', per_ip_sorted)+table('Top Routes', per_route_sorted)+table('Top Click Labels', clicks_sorted)+ip_details_html})

@app.get("/_admin/export")
def admin_export(request: Request, limit: int = 10000):
    if not is_logged_in(request): return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    p = Path(EVENT_LOG)
    lines = p.read_text(encoding="utf-8").splitlines()[-limit:] if p.exists() else []
    csv_data = "\n".join(lines)
    return PlainTextResponse(csv_data, media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="events_export.csv"'})
