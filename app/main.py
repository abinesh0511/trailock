"""Trailock - suspicious login detection. Run:  python -m uvicorn app.main:app --port 8000"""
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import geo as geo_mod
from . import risk
from .database import connect, init_db

STATIC = Path(__file__).resolve().parent.parent / "static"

# ---- settings (change with environment variables) ----
SIMULATE = os.getenv("TRAILOCK_SIMULATE", "1") == "1"         # allow "test as IP" box (turn OFF in production)
TRUST_PROXY = os.getenv("TRAILOCK_TRUST_PROXY", "0") == "1"   # set 1 when behind Nginx / load balancer
BRUTE_FORCE_LIMIT = int(os.getenv("TRAILOCK_BRUTE_FORCE_LIMIT", 10))  # fails per IP in 15 min -> auto block
BLOCK_MINUTES = int(os.getenv("TRAILOCK_BLOCK_MINUTES", 30))
SESSION_HOURS = 12
COOKIE = "tl_session"

app = FastAPI(title="Trailock")
app.mount("/static", StaticFiles(directory=STATIC), name="static")
init_db()


# ---------------- helpers ----------------
def hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()


def client_ip(request: Request) -> str:
    if SIMULATE:
        sim = request.headers.get("x-sim-ip", "").strip()
        if sim:
            return sim
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def current_user(request: Request):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    with connect() as conn:
        return conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ? AND s.expires_at > ?", (token, time.time())).fetchone()


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Please log in")
    return user


def record_event(conn, *, now, email, user, ip, geo, ua, device_id, success, score, action, reasons):
    cur = conn.execute(
        "INSERT INTO login_events (ts, email, user_id, ip, country, country_code, city, lat, lon, isp, "
        "risky_network, user_agent, device_id, success, score, action, reasons) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (now, email, user["id"] if user else None, ip, geo.get("country"), geo.get("country_code"),
         geo.get("city"), geo.get("lat"), geo.get("lon"), geo.get("isp"), int(bool(geo.get("risky_network"))),
         ua[:300], device_id, int(success), score, action, json.dumps(reasons)))
    return cur.lastrowid


def start_session(conn, user_id: int, ip: str) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute("INSERT INTO sessions VALUES (?,?,?,?,?)",
                 (token, user_id, ip, now, now + SESSION_HOURS * 3600))
    return token


def where(geo: dict) -> str:
    return ', '.join(x for x in (geo.get('city'), geo.get('country')) if x) or 'Unknown'


def alert(title: str, lines: list[str]):
    """Prints a security alert to the terminal. Swap this for email / Slack later."""
    bar = "=" * 60
    print(f"\n{bar}\n  TRAILOCK  {title}\n{bar}")
    for line in lines:
        print("  " + line)
    print(bar + "\n", flush=True)


# ---------------- pages ----------------
@app.get("/")
def landing():
    return FileResponse(STATIC / "index.html")


@app.get("/login")
def login_page():
    return FileResponse(STATIC / "login.html")


@app.get("/register")
def register_page():
    return FileResponse(STATIC / "register.html")


@app.get("/dashboard")
def dashboard_page():
    return FileResponse(STATIC / "dashboard.html")


# ---------------- API ----------------
class RegisterIn(BaseModel):
    name: str
    email: str
    password: str


class LoginIn(BaseModel):
    email: str
    password: str
    device_id: str = ""


class VerifyIn(BaseModel):
    challenge_id: str
    code: str


@app.get("/api/config")
def config():
    return {"simulate": SIMULATE, "allow_below": risk.ALLOW_BELOW, "block_from": risk.BLOCK_FROM}


@app.get("/api/my-ip")
def my_ip(request: Request):
    ip = client_ip(request)
    with connect() as conn:
        g = geo_mod.lookup(conn, ip)
    return {"ip": ip, **g}


@app.post("/api/register")
def register(body: RegisterIn):
    email = body.email.strip().lower()
    if "@" not in email or len(body.password) < 8 or not body.name.strip():
        raise HTTPException(400, "Enter your name, a valid email and a password of 8+ characters")
    salt = secrets.token_hex(16)
    with connect() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(409, "An account with this email already exists")
        first = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        conn.execute("INSERT INTO users (name, email, pw_hash, salt, is_admin, created_at) VALUES (?,?,?,?,?,?)",
                     (body.name.strip(), email, hash_pw(body.password, salt), salt, int(first), time.time()))
    return {"ok": True, "admin": first}


@app.post("/api/login")
def login(body: LoginIn, request: Request):
    now = time.time()
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "")
    email = body.email.strip().lower()

    with connect() as conn:
        geo = geo_mod.lookup(conn, ip)
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        # 0. IP already blocked?
        blocked = conn.execute("SELECT * FROM blocked_ips WHERE ip = ? AND until > ?", (ip, now)).fetchone()
        if blocked:
            reasons = [{"code": "ip_blocked", "points": 100, "detail": blocked["reason"]}]
            record_event(conn, now=now, email=email, user=user, ip=ip, geo=geo, ua=ua, device_id=body.device_id,
                         success=False, score=100, action="block", reasons=reasons)
            mins = int((blocked["until"] - now) / 60) + 1
            return {"status": "blocked", "message": f"This IP is blocked for {mins} more minute(s).",
                    "score": 100, "reasons": reasons, "ip": ip, "geo": geo}

        password_ok = bool(user) and hmac.compare_digest(user["pw_hash"], hash_pw(body.password, user["salt"]))
        score, action, reasons = risk.assess(conn, user=user, ip=ip, geo=geo, device_id=body.device_id,
                                             password_ok=password_ok, now=now)
        info = {"score": score, "reasons": reasons, "ip": ip, "geo": geo}

        # 1. Wrong email or password
        if not password_ok:
            record_event(conn, now=now, email=email, user=user, ip=ip, geo=geo, ua=ua, device_id=body.device_id,
                         success=False, score=score, action="deny", reasons=reasons)
            fails = conn.execute("SELECT COUNT(*) FROM login_events WHERE ip = ? AND success = 0 AND ts > ?",
                                 (ip, now - risk.WINDOW)).fetchone()[0]
            if fails >= BRUTE_FORCE_LIMIT:
                conn.execute("INSERT OR REPLACE INTO blocked_ips VALUES (?,?,?,?)",
                             (ip, f"Brute force: {fails} failed logins in 15 min", now, now + BLOCK_MINUTES * 60))
                alert("IP AUTO-BLOCKED", [f"IP: {ip} ({where(geo)})",
                                          f"{fails} failed logins in 15 minutes",
                                          f"Blocked for {BLOCK_MINUTES} minutes"])
            return {"status": "invalid", "message": "Incorrect email or password.", **info}

        # 2. Correct password but high risk -> block
        if action == "block":
            record_event(conn, now=now, email=email, user=user, ip=ip, geo=geo, ua=ua, device_id=body.device_id,
                         success=False, score=score, action="block", reasons=reasons)
            alert("SUSPICIOUS LOGIN BLOCKED", [f"User: {email}", f"IP: {ip} ({where(geo)})",
                                               f"Risk score: {score}"] + [f"- {r['detail']}" for r in reasons])
            return {"status": "blocked", "message": "This login looks suspicious and was blocked. "
                                                    "The account owner has been alerted.", **info}

        # 3. Medium risk -> one-time code
        if action == "challenge":
            event_id = record_event(conn, now=now, email=email, user=user, ip=ip, geo=geo, ua=ua,
                                    device_id=body.device_id, success=False, score=score, action="challenge",
                                    reasons=reasons)
            cid = secrets.token_urlsafe(16)
            code = f"{secrets.randbelow(1_000_000):06d}"
            conn.execute("INSERT INTO otp_challenges (id, user_id, event_id, code, ip, expires_at) VALUES (?,?,?,?,?,?)",
                         (cid, user["id"], event_id, code, ip, now + 300))
            alert("VERIFICATION CODE (email simulation)", [f"To: {email}", f"Code: {code}",
                                                           f"Login from {ip} ({where(geo)})",
                                                           "Valid for 5 minutes"])
            return {"status": "challenge", "challenge_id": cid,
                    "message": "Unusual login. Enter the 6-digit code sent to your email "
                               "(for now it is printed in the server terminal).", **info}

        # 4. Low risk -> allow
        record_event(conn, now=now, email=email, user=user, ip=ip, geo=geo, ua=ua, device_id=body.device_id,
                     success=True, score=score, action="allow", reasons=reasons)
        token = start_session(conn, user["id"], ip)

    resp = JSONResponse({"status": "ok", "message": "Login successful.", **info})
    resp.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_HOURS * 3600)
    return resp


@app.post("/api/verify")
def verify(body: VerifyIn, request: Request):
    now = time.time()
    with connect() as conn:
        ch = conn.execute("SELECT * FROM otp_challenges WHERE id = ?", (body.challenge_id,)).fetchone()
        if not ch or ch["used"] or ch["expires_at"] < now or ch["attempts"] >= 5:
            raise HTTPException(400, "This code has expired. Please log in again.")
        if not hmac.compare_digest(ch["code"], body.code.strip()):
            conn.execute("UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?", (ch["id"],))
            raise HTTPException(400, f"Wrong code. {4 - ch['attempts']} attempt(s) left.")
        conn.execute("UPDATE otp_challenges SET used = 1 WHERE id = ?", (ch["id"],))
        # mark the original login event as a verified success (it becomes part of the user's baseline)
        conn.execute("UPDATE login_events SET success = 1, action = 'verified' WHERE id = ?", (ch["event_id"],))
        token = start_session(conn, ch["user_id"], ch["ip"])
    resp = JSONResponse({"status": "ok", "message": "Verified. Login successful."})
    resp.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_HOURS * 3600)
    return resp


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get(COOKIE)
    if token:
        with connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/api/me")
def me(request: Request):
    u = require_user(request)
    return {"id": u["id"], "name": u["name"], "email": u["email"], "is_admin": bool(u["is_admin"])}


@app.get("/api/events")
def events(request: Request, limit: int = 100):
    u = require_user(request)
    limit = max(1, min(limit, 500))
    with connect() as conn:
        if u["is_admin"]:
            rows = conn.execute("SELECT * FROM login_events ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM login_events WHERE user_id = ? ORDER BY ts DESC LIMIT ?",
                                (u["id"], limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"])
        out.append(d)
    return out


@app.get("/api/stats")
def stats(request: Request):
    u = require_user(request)
    where, args = ("", ()) if u["is_admin"] else ("WHERE user_id = ?", (u["id"],))
    with connect() as conn:
        row = conn.execute(
            f"SELECT COUNT(*) total, "
            f"SUM(action IN ('allow','verified')) allowed, SUM(action = 'challenge') challenged, "
            f"SUM(action = 'block') blocked, SUM(action = 'deny') failed, "
            f"ROUND(AVG(score), 1) avg_score, COUNT(DISTINCT ip) unique_ips "
            f"FROM login_events {where}", args).fetchone()
        blocked_ips = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE until > ?", (time.time(),)).fetchone()[0]
    return {**{k: (row[k] or 0) for k in row.keys()}, "blocked_ips": blocked_ips}


@app.get("/api/blocked")
def blocked_list(request: Request):
    require_user(request)
    with connect() as conn:
        rows = conn.execute("SELECT * FROM blocked_ips WHERE until > ? ORDER BY created_at DESC",
                            (time.time(),)).fetchall()
    return [dict(r) for r in rows]


class IpIn(BaseModel):
    ip: str
    minutes: int = 60


@app.post("/api/block")
def block_ip(body: IpIn, request: Request):
    u = require_user(request)
    if not u["is_admin"]:
        raise HTTPException(403, "Admins only")
    now = time.time()
    with connect() as conn:
        conn.execute("INSERT OR REPLACE INTO blocked_ips VALUES (?,?,?,?)",
                     (body.ip.strip(), f"Blocked manually by {u['email']}", now, now + body.minutes * 60))
    return {"ok": True}


@app.post("/api/unblock")
def unblock_ip(body: IpIn, request: Request):
    u = require_user(request)
    if not u["is_admin"]:
        raise HTTPException(403, "Admins only")
    with connect() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (body.ip.strip(),))
    return {"ok": True}
