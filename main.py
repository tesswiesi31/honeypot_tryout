import os, json, requests
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, Optional
from collections import Counter, defaultdict

from fastapi import FastAPI, Request, Response, Form, status
from fastapi.responses import RedirectResponse, PlainTextResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles

# --- Load .env ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

# --- Config ---
APP_ENV    = os.getenv("APP_ENV", "dev")
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "admin123")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
EVENT_LOG  = os.getenv("EVENT_LOG", "events.jsonl")

# Telegram notifications
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT  = os.getenv("TELEGRAM_CHAT", "")

# --- Setup ---
Path("data").mkdir(exist_ok=True, parents=True)
Path(EVENT_LOG).touch(exist_ok=True)

app = FastAPI(title="Honeypot Backend")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if APP_ENV=="dev" else [],
    allow_methods=["*"],
    allow_headers=["*"]
)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", session_cookie="hp_admin")

# --- Helper functions ---
def now(): return datetime.now(tz=timezone.utc).isoformat()
def sid(req: Request): return req.cookies.get("hp_sid") or str(uuid4())
def ip(req: Request): return (req.headers.get("x-forwarded-for","").split(",")[0].strip() or (req.client.host if req.client else "0.0.0.0"))
def log(event: Dict[str,Any]): open(EVENT_LOG,"a",encoding="utf-8").write(json.dumps(event,ensure_ascii=False)+"\n")
def is_logged_in(req: Request): return req.session.get("user")==ADMIN_USER

def notify_telegram(msg: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT: return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": TELEGRAM_CHAT, "text": msg}, timeout=3)
    except Exception as e:
        print("Telegram notify failed:", e)

# --- Middleware for logging requests ---
@app.middleware("http")
async def logger(req: Request, call_next):
    s = sid(req)
    route = req.url.path
    log({"ts": now(), "kind": "request", "sid": s, "ip": ip(req), "route": route, "method": req.method})
    res: Response = await call_next(req)
    log({"ts": now(), "kind": "response", "sid": s, "ip": ip(req), "route": route, "status": res.status_code})
    if "hp_sid" not in req.cookies:
        res.set_cookie("hp_sid", s, httponly=True, samesite="lax")
    return res

# --- Login / Logout ---
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...), request: Request = None):
    if username == ADMIN_USER and password == ADMIN_PASS:
        request.session["user"] = ADMIN_USER
        return RedirectResponse("/_admin/logs", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/login?error=1", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

# --- Admin pages ---
def _parse_ts(s: str) -> Optional[datetime]:
    try: return datetime.fromisoformat(s.replace("Z","+00:00"))
    except: return None

@app.get("/_admin/logs", response_class=HTMLResponse)
async def admin_logs(request: Request, tail: int = 200):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    
    p = Path(EVENT_LOG)
    if not p.exists(): return "<pre>(no events yet)</pre>"
    
    lines = p.read_text(encoding="utf-8").splitlines()[-tail:]
    out = [f"<div><code>{json.dumps(json.loads(ln), ensure_ascii=False)}</code></div>" for ln in lines]
    
    return f"<html><body style='font-family:monospace;max-width:980px;margin:20px auto;background:#121212;color:#0f0'>" \
           f"<p><a href='/_admin/stats'>Stats</a> · <a href='/_admin/export'>CSV Export</a> · <a href='/logout'>Logout</a></p>" \
           f"<h2>Last {tail} events</h2>{''.join(out)}</body></html>"

@app.get("/_admin/stats", response_class=HTMLResponse)
async def admin_stats(request: Request, hours: int = 168):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    
    p = Path(EVENT_LOG)
    if not p.exists(): return "<pre>(no events yet)</pre>"
    
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
    per_ip, per_route, click_labels = Counter(), Counter(), Counter()
    last_seen, sessions_per_ip = {}, defaultdict(set)

    for ln in p.read_text(encoding="utf-8").splitlines():
        try: obj = json.loads(ln)
        except: continue
        t = _parse_ts(obj.get("ts",""))
        if t and t < cutoff: continue
        k, ipp, s, r = obj.get("kind"), obj.get("ip","-"), obj.get("sid","-"), obj.get("route","-")
        if k in ("request","response"): per_ip[ipp] += 1; per_route[r] += 1
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

    body = "<p><a href='/_admin/logs'>Logs</a> · <a href='/_admin/export'>CSV Export</a> · <a href='/logout'>Logout</a></p>"
    body += f"<p>Period: last {hours} hours</p>"
    body += table('Top IPs (Event Count)', per_ip_sorted)
    body += table('Top Routes', per_route_sorted)
    body += table('Top Click Labels', clicks_sorted)
    body += ip_details_html

    return f"<html><body style='font-family:monospace;max-width:980px;margin:20px auto;background:#121212;color:#0f0'>{body}</body></html>"

@app.get("/_admin/export")
async def admin_export(request: Request, limit: int = 10000):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    
    p = Path(EVENT_LOG)
    if not p.exists(): return PlainTextResponse("", media_type="text/csv")
    
    lines = p.read_text(encoding="utf-8").splitlines()[-limit:]
    cols = ["ts","kind","ip","sid","route","method","status","action","label","ua","accept_language","referrer"]
    out = [",".join(cols)]
    for ln in lines:
        try: obj = json.loads(ln)
        except: continue
        row = [str(obj.get(c,"")).replace(",",";") for c in cols]
        out.append(",".join(row))
    
    csv_data = "\n".join(out)
    headers = {"Content-Disposition": 'attachment; filename="events_export.csv"'}
    return PlainTextResponse(csv_data, media_type="text/csv", headers=headers)
