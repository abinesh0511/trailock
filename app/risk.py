"""Trailock risk engine: turns a login attempt into a 0-100 score and an action."""
import math
import os
import time

ALLOW_BELOW = int(os.getenv("TRAILOCK_ALLOW_BELOW", 35))   # score < 35  -> allow
BLOCK_FROM = int(os.getenv("TRAILOCK_BLOCK_FROM", 70))     # score >= 70 -> block
WINDOW = 15 * 60                                           # 15 minutes


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def decide(score: int) -> str:
    if score >= BLOCK_FROM:
        return "block"
    if score >= ALLOW_BELOW:
        return "challenge"
    return "allow"


def assess(conn, *, user, ip: str, geo: dict, device_id: str, password_ok: bool, now: float):
    """Return (score, action, reasons). reasons = list of {code, points, detail}."""
    reasons = []

    def add(code, points, detail):
        reasons.append({"code": code, "points": points, "detail": detail})

    since = now - WINDOW

    # 1. Brute force / credential stuffing from this IP
    ip_fails = conn.execute(
        "SELECT COUNT(*) FROM login_events WHERE ip = ? AND success = 0 AND ts > ?",
        (ip, since)).fetchone()[0]
    if ip_fails:
        add("failed_attempts_ip", min(30, ip_fails * 5),
            f"{ip_fails} failed login(s) from this IP in the last 15 min")

    # 2. Risky network (VPN / proxy / Tor / datacenter)
    if geo.get("risky_network"):
        add("risky_network", 18, f"IP belongs to a proxy/VPN/hosting network ({geo.get('isp') or 'unknown ISP'})")

    if not password_ok:
        add("wrong_password", 10, "Incorrect password")

    if user:
        # 3. Many failures on this account (from any IP)
        acct_fails = conn.execute(
            "SELECT COUNT(*) FROM login_events WHERE user_id = ? AND success = 0 AND ts > ?",
            (user["id"], since)).fetchone()[0]
        if acct_fails >= 3:
            add("account_under_attack", 15, f"{acct_fails} failed logins on this account in 15 min")

        history = conn.execute(
            "SELECT ip, country_code, lat, lon, device_id, ts FROM login_events "
            "WHERE user_id = ? AND success = 1 ORDER BY ts DESC LIMIT 200", (user["id"],)).fetchall()

        if history:  # no history = first login, that becomes the baseline
            if ip not in {h["ip"] for h in history}:
                add("new_ip", 15, f"First time this account logs in from {ip}")

            if device_id and device_id not in {h["device_id"] for h in history}:
                add("new_device", 20, "Unrecognised browser / device fingerprint")

            cc = geo.get("country_code")
            if cc and cc != "LAN" and cc not in {h["country_code"] for h in history}:
                add("new_country", 25, f"First login from {geo.get('country')}")

            # 4. Impossible travel
            last = next((h for h in history if h["lat"] is not None), None)
            if last and geo.get("lat") is not None:
                km = haversine_km(last["lat"], last["lon"], geo["lat"], geo["lon"])
                hours = max((now - last["ts"]) / 3600, 1 / 60)
                speed = km / hours
                if km > 500 and speed > 900:
                    add("impossible_travel", 35,
                        f"{km:,.0f} km from last login in {hours * 60:,.0f} min ({speed:,.0f} km/h)")

            # 5. Unusual login hour (needs a baseline of 5+ logins)
            if len(history) >= 5:
                usual = {time.localtime(h["ts"]).tm_hour for h in history}
                cur = time.localtime(now).tm_hour
                if not any(min(abs(cur - u), 24 - abs(cur - u)) <= 1 for u in usual):
                    add("unusual_hour", 10, f"Login at {cur:02d}:00 is outside this user's normal hours")

    score = min(100, sum(r["points"] for r in reasons))
    return score, decide(score), reasons
