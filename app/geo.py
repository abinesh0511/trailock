"""IP address -> location / network lookup (free ip-api.com service, cached 24h)."""
import ipaddress
import json
import time
import urllib.request

UNKNOWN = {"country": "Unknown", "country_code": None, "city": "", "lat": None, "lon": None,
           "isp": "", "risky_network": False, "private": False}


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_reserved or a.is_link_local
    except ValueError:
        return True


def lookup(conn, ip: str) -> dict:
    if is_private(ip):
        return {**UNKNOWN, "country": "Local network", "country_code": "LAN", "private": True}

    row = conn.execute("SELECT data, ts FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
    if row and time.time() - row["ts"] < 86400:
        return json.loads(row["data"])

    url = (f"http://ip-api.com/json/{ip}"
           "?fields=status,country,countryCode,city,lat,lon,isp,proxy,hosting")
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            d = json.load(r)
    except Exception:
        return dict(UNKNOWN)  # offline / rate-limited: carry on without geo

    if d.get("status") != "success":
        return dict(UNKNOWN)

    geo = {
        "country": d.get("country") or "Unknown",
        "country_code": d.get("countryCode"),
        "city": d.get("city") or "",
        "lat": d.get("lat"),
        "lon": d.get("lon"),
        "isp": d.get("isp") or "",
        # proxy = VPN / Tor / open proxy, hosting = datacenter IP (AWS, DigitalOcean...)
        "risky_network": bool(d.get("proxy") or d.get("hosting")),
        "private": False,
    }
    conn.execute("INSERT OR REPLACE INTO geo_cache (ip, data, ts) VALUES (?, ?, ?)",
                 (ip, json.dumps(geo), time.time()))
    return geo
