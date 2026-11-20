# Trailock: suspicious login detection

Trailock is a website with real login. Every login attempt is checked using the
visitor's **IP address, location, ISP, device and login history**, and then gets a risk score from 0 to 100.

| Score   | What happens                                           |
|---------|--------------------------------------------------------|
| 0–34    | Allowed, the user logs in straight away               |
| 35–69   | A 6-digit code is required (printed in the terminal)  |
| 70–100  | Blocked, and an alert is printed in the terminal      |
| 10 wrong passwords from one IP in 15 min | That IP is blocked for 30 minutes |

## Risk signals

| Signal | Points |
|---|---|
| Impossible travel (more than 900 km/h between two logins) | +35 |
| First login from a new country | +25 |
| New device / browser fingerprint | +20 |
| VPN / proxy / Tor / datacenter IP | +18 |
| New IP address for this account | +15 |
| 3+ failed logins on the account in 15 min | +15 |
| Login outside the user's normal hours | +10 |
| Each failed login from the same IP in 15 min | +5 (max 30) |
| Wrong password | +10 |

IP location comes from the free ip-api.com service, so it needs internet.

---

## Run on Windows (easy way)

1. Install **Python 3.10 or newer** from https://www.python.org/downloads/
   and **tick "Add python.exe to PATH"** in the installer.
2. Unzip `trailock.zip` (for example to `C:\Users\<you>\trailock`).
3. Double-click **`run.bat`**.
4. Your browser opens **http://localhost:8000**. Keep the black window open.

## Run on Windows (manual way, PowerShell)

```powershell
cd $HOME\trailock
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000
```

If PowerShell says "running scripts is disabled", run this once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

---

## How to test it

1. Go to **/register** and create an account. The first account is the **admin**.
2. Go to **/login** and log in. This first login becomes your **baseline**.
3. On your own computer your IP is `127.0.0.1`, so there is no location. To test, open
   **"Test mode: log in as another IP"** on the login page and pick an IP:
   - Log in with **India 117.192.10.5** → allowed (baseline)
   - Then log in with **Germany 85.214.132.117** → **blocked** (impossible travel + new country + datacenter)
   - Log in with **India 49.207.48.10** and tick **"Pretend this is a new device"** → **verification code**.
     The code shows up in the `run.bat` window.
   - Type a wrong password 10 times with **Brazil 200.160.2.3** → that IP gets **auto-blocked**
4. Open **/dashboard** to see every attempt, the IP, location, ISP, score and why.
   Click a row to see the reasons. Admins can block or unblock IPs.

---

## Put it on AWS EC2 (real IPs)

```bash
# on the EC2 instance (Ubuntu)
sudo apt update && sudo apt install -y python3-venv unzip
unzip trailock.zip && cd trailock
TRAILOCK_SIMULATE=0 HOST=0.0.0.0 ./run.sh
```

Open port 8000 in the instance's Security Group, then visit `http://<EC2-public-IP>:8000`.

If you put **Nginx** in front, also set `TRAILOCK_TRUST_PROXY=1` so Trailock reads the
real visitor IP from the `X-Forwarded-For` header.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `TRAILOCK_SIMULATE` | `1` | Show the "test as another IP" box. **Set to 0 on a real server**, otherwise anyone can fake their IP. |
| `TRAILOCK_TRUST_PROXY` | `0` | Set `1` behind Nginx / a load balancer |
| `TRAILOCK_ALLOW_BELOW` | `35` | Scores below this are allowed |
| `TRAILOCK_BLOCK_FROM` | `70` | Scores from this are blocked |
| `TRAILOCK_BRUTE_FORCE_LIMIT` | `10` | Failed logins per IP in 15 min before auto-block |
| `TRAILOCK_BLOCK_MINUTES` | `30` | How long an auto-block lasts |
| `TRAILOCK_DB` | `trailock.db` | SQLite file location |

## Files

```
trailock/
├── app/
│   ├── main.py      # web server, login, OTP, dashboard API
│   ├── risk.py      # risk engine (all scoring rules)
│   ├── geo.py       # IP -> country, city, ISP, VPN check
│   └── database.py  # SQLite tables
├── static/          # index, login, register, dashboard pages
├── requirements.txt
├── run.bat          # Windows one-click start
└── run.sh           # Linux / EC2 start
```

## Next steps for production

- Send the verification code by **email** (replace `alert()` in `main.py` with SMTP / AWS SES).
- Run behind **Nginx + HTTPS** (Let's Encrypt) and add `secure=True` to the cookies.
- Replace the free ip-api.com lookup with a paid one (ipinfo, MaxMind) once you go above 45 lookups/minute.
