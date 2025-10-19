import os, json, requests
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

# --- Config ---
APP_ENV = os.getenv("APP_ENV", "dev")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
EVENT_LOG = os.getenv("EVENT_LOG", "events.jsonl")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT = os.getenv("TELEGRAM_CHAT", "")

# ensure log file exists
if not os.path.exists(EVENT_LOG):
    with open(EVENT_LOG, "w", encoding="utf-8") as f: f.write("")

# --- FastAPI ---
app = FastAPI(title="honeypot")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if APP_ENV=="dev" else [],
    allow_methods=["*"],
    allow_headers=["*"]
)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", session_cookie="hp_admin")


# --- Helpers ---
def now_iso(): return datetime.now(tz=timezone.utc).isoformat()
def sid_from_req(req): return req.cookies.get("hp_sid") or str(uuid4())
def ip_from_req(req):
    xff = req.headers.get("x-forwarded-for","")
    if xff: return xff.split(",")[0].strip()
    if req.client: return req.client.host
    return "0.0.0.0"
def log_event(obj):
    with open(EVENT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False)+"\n")
def notify_telegram(msg):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT: return
    try: requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id":TELEGRAM_CHAT,"text":msg}, timeout=3)
    except: pass

# --- Middleware ---
@app.middleware("http")
async def logger(req: Request, call_next):
    s = sid_from_req(req)
    route = req.url.path
    log_event({"ts": now_iso(),"kind":"request","sid": s,"ip": ip_from_req(req),"route": route,"method": req.method})
    res: Response = await call_next(req)
    log_event({"ts": now_iso(),"kind":"response","sid": s,"ip": ip_from_req(req),"route": route,"status": res.status_code})
    if "hp_sid" not in req.cookies: res.set_cookie("hp_sid", s, httponly=True, samesite="lax")
    return res

# --- Routes ---
@app.get("/", response_class=HTMLResponse)
def index():
    cards = "".join([f"<a href='/{name}'>{name} - {AGES[name]} - {BIOS[name][:30]}...</a><br>" for name in PROFILE_NAMES])
    return HTMLResponse(f"<html><body><h1>Honeypot Profiles</h1>{cards}</body></html>")

@app.get("/{name}", response_class=HTMLResponse)
def profile(request: Request, name: str):
    if name not in PROFILE_NAMES:
        return HTMLResponse("<h1>Profile not found</h1>", status_code=404)
    visitor_ip = ip_from_req(request)
    log_event({"ts": now_iso(), "kind":"profile_view","profile":name,"ip":visitor_ip,"sid":sid_from_req(request)})
    notify_telegram(f"🚨 Profile {name} accessed! IP: {visitor_ip}")
    return HTMLResponse(f"<html><body><h1>{name}</h1><p>Age: {AGES[name]}</p><p>{BIOS[name]}</p><a href='/'>Back</a></body></html>")
