import os
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from collections import Counter, defaultdict
from typing import Optional

import requests
from fastapi import FastAPI, Request, Response, Form, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

load_dotenv()

# Config
APP_ENV = os.getenv("APP_ENV", "dev")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "admin123")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
EVENT_LOG = os.getenv("EVENT_LOG", "data/events.jsonl")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT = os.getenv("TELEGRAM_CHAT", "")

# ensure data dir
Path(EVENT_LOG).parent.mkdir(parents=True, exist_ok=True)
Path(EVENT_LOG).touch(exist_ok=True)

app = FastAPI(title="honeypot")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if APP_ENV == "dev" else [],
    allow_methods=["*"],
    allow_headers=["*"]
)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", session_cookie="hp_admin")

PROFILE_NAMES = ["Jack","Emi","Noah","Lexi","John","Mark","Noelle"]
HONEY_ROUTES = {f"/{p}" for p in PROFILE_NAMES}

def now_iso():
    return datetime.now(tz=timezone.utc).isoformat()

def sid_from_req(req: Request):
    return req.cookies.get("hp_sid") or str(uuid4())

def ip_from_req(req: Request):
    forwarded = req.headers.get("x-forwarded-for","")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if req.client:
        return req.client.host
    return "0.0.0.0"

def log_event(obj: dict):
    with open(EVENT_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")

def notify_telegram(msg: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        # no-op when not configured
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": TELEGRAM_CHAT, "text": msg}, timeout=3)
    except Exception as e:
        print("Telegram notify failed:", e)

@app.middleware("http")
async def logger(req: Request, call_next):
    s = sid_from_req(req)
    route = req.url.path
    log_event({"ts": now_iso(), "kind":"request", "sid": s, "ip": ip_from_req(req), "route": route, "method": req.method})
    res: Response = await call_next(req)
    log_event({"ts": now_iso(), "kind":"response", "sid": s, "ip": ip_from_req(req), "route": route, "status": res.status_code, "is_honey": route in HONEY_ROUTES})
    if "hp_sid" not in req.cookies:
        res.set_cookie("hp_sid", s, httponly=True, samesite="lax")
    return res

# Index
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    # brief meta per profile for index cards
    meta = {
        "Jack": {"age": 6, "meta":"Playful young boy"},
        "Emi": {"age": 5, "meta":"loves to draw"},
        "Noah": {"age": 7, "meta":"loves playing soccer"},
        "Lexi": {"age": 4, "meta":"likes horses"},
        "John": {"age": 9, "meta":"likes to play video games"},
        "Mark": {"age": 10, "meta":"likes to play football"},
        "Noelle": {"age": 7, "meta":"loves nature"}
    }
    return templates.TemplateResponse("index.html", {"request": request, "profiles": meta})

# Dynamic profile routes (one template for all)
@app.get("/{name}", response_class=HTMLResponse)
def show_profile(request: Request, name: str):
    if name not in PROFILE_NAMES:
        return HTMLResponse("<h1>Profile not found</h1>", status_code=404)
    # log + notify
    visitor_ip = ip_from_req(request)
    log_event({"ts": now_iso(), "kind":"profile_view", "profile": name, "ip": visitor_ip, "sid": sid_from_req(request)})
    notify_telegram(f"🚨 ALERT: Someone accessed profile {name}! IP: {visitor_ip}")
    # basic age/bio from index mapping
    ages = {"Jack":6,"Emi":5,"Noah":7,"Lexi":4,"John":9,"Mark":10,"Noelle":7}
    bio = f"{name} is a cool hacker-style profile with a dark touch. Fun and adventurous."
    return templates.TemplateResponse("profile.html", {"request": request, "name": name, "age": ages.get(name, 6), "bio": bio})

# Client-side event tracker
@app.post("/event")
async def track_event(request: Request):
    try:
        data = await request.json()
    except:
        data = {}
    s = sid_from_req(request)
    e = {"ts": now_iso(), "kind":"client", "sid": s, "ip": ip_from_req(request), "action": str(data.get("action")), "label": str(data.get("label"))}
    log_event(e)
    if e["action"] == "click" and e["label"] in PROFILE_NAMES:
        notify_telegram(f"👆 Click detected: {e['label']} | IP: {e['ip']}")
    return {"ok": True}

# Auth helpers
def is_logged_in(request: Request) -> bool:
    return request.session.get("user") == ADMIN_USER

# Login/logout
@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login", response_class=HTMLResponse)
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        request.session["user"] = ADMIN_USER
        return RedirectResponse("/_admin/logs", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request, "error": "Login failed"})

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

# Admin logs
@app.get("/_admin/logs", response_class=HTMLResponse)
def admin_logs(request: Request, tail: int = 200):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    p = Path(EVENT_LOG)
    if not p.exists():
        return PlainTextResponse("(no events yet)")
    lines = p.read_text(encoding="utf-8").splitlines()[-int(tail):]
    events = []
    for ln in lines:
        try:
            events.append(json.loads(ln))
        except:
            events.append({"raw": ln})
    return templates.TemplateResponse("admin_logs.html", {"request": request, "events": list(reversed(events)), "tail": tail})

# Admin stats
@app.get("/_admin/stats", response_class=HTMLResponse)
def admin_stats(request: Request, hours: int = 168):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
    per_ip = Counter()
    per_route = Counter()
    click_labels = Counter()
    last_seen = {}
    sessions_per_ip = defaultdict(set)
    for ln in Path(EVENT_LOG).read_text(encoding="utf-8").splitlines():
        try:
            obj = json.loads(ln)
        except:
            continue
        t = None
        try:
            t = datetime.fromisoformat(obj.get("ts","").replace("Z","+00:00"))
        except:
            t = None
        if t and t < cutoff:
            continue
        k = obj.get("kind")
        ipp = obj.get("ip","-")
        s = obj.get("sid","-")
        r = obj.get("route","-")
        if k in ("request","response"):
            per_ip[ipp] += 1
            per_route[r] += 1
        if k == "client" and obj.get("action") == "click":
            click_labels[obj.get("label","(unlabeled)")] += 1
        last_seen[ipp] = max(last_seen.get(ipp, t or datetime.min.replace(tzinfo=timezone.utc)), t or datetime.min.replace(tzinfo=timezone.utc))
        sessions_per_ip[ipp].add(s)
    # prepare small dicts for template
    top_ips = per_ip.most_common(20)
    top_routes = per_route.most_common(20)
    top_clicks = click_labels.most_common(20)
    ip_details = [{"ip": ip, "sessions": len(sessions_per_ip[ip]), "last_seen": str(last_seen.get(ip))} for ip,_ in top_ips]
    return templates.TemplateResponse("admin_stats.html", {"request": request, "hours": hours, "top_ips": top_ips, "top_routes": top_routes, "top_clicks": top_clicks, "ip_details": ip_details})

# CSV export
@app.get("/_admin/export")
def export_csv(request: Request, limit: int = 10000):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    p = Path(EVENT_LOG)
    if not p.exists():
        return PlainTextResponse("", media_type="text/csv")
    lines = p.read_text(encoding="utf-8").splitlines()[-int(limit):]
    cols = ["ts","kind","ip","sid","route","method","status","action","label","ua","accept_language","referrer","is_honey"]
    out = [",".join(cols)]
    for ln in lines:
        try:
            obj = json.loads(ln)
        except:
            continue
        row = [str(obj.get(c,"")).replace(",",";") for c in cols]
        out.append(",".join(row))
    csv_data = "\n".join(out)
    headers = {"Content-Disposition": 'attachment; filename="events_export.csv"'}
    return PlainTextResponse(csv_data, media_type="text/csv", headers=headers)
