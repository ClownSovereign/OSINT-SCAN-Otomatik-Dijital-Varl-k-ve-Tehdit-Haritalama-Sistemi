import whois
import requests
import json
import socket
import hashlib
import time
import random
from core.db import get_conn
from core.config import SHODAN_API_KEY, CRITICAL_PORTS, GO_SCANNER_URL

# ─────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────

def collect_whois(scan_id: int, domain: str) -> dict:
    try:
        w = whois.whois(domain)
        is_private = "privacy" in str(w.registrar).lower() if w.registrar else True
        data = {
            "registrar":   str(w.registrar or ""),
            "admin_email": str(w.emails[0] if w.emails else ""),
            "country":     str(w.country or ""),
            "is_private":  is_private
        }
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO whois_results (scan_id, registrar, admin_email, country, is_private)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, data["registrar"], data["admin_email"],
                  data["country"], data["is_private"]))
        return data
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# SIZINTI KONTROLÜ — 3 katmanlı
# ─────────────────────────────────────────────

LEAKCHECK_URL = "https://leakcheck.io/api/public"
EMAILREP_URL  = "https://emailrep.io"
HEADERS       = {"User-Agent": "OSINT-SCAN-TUBITAK/1.0 (research project)"}

KNOWN_BREACHED_DOMAINS = {
    "yahoo.com":    [{"name": "Yahoo 2016",    "date": "2016-12-14", "fields": ["Email", "Passwords", "Names"]}],
    "linkedin.com": [{"name": "LinkedIn 2021", "date": "2021-06-22", "fields": ["Email", "Phone", "Names"]}],
    "adobe.com":    [{"name": "Adobe 2013",    "date": "2013-10-04", "fields": ["Email", "Passwords"]}],
    "hotmail.com":  [{"name": "Collection1",   "date": "2019-01-07", "fields": ["Email", "Passwords"]}],
    "gmail.com":    [{"name": "Collection1",   "date": "2019-01-07", "fields": ["Email"]}],
}

def _leakcheck_query(email: str) -> list:
    try:
        resp = requests.get(LEAKCHECK_URL, params={"check": email},
                            headers=HEADERS, timeout=10)
        if resp.status_code == 429:
            time.sleep(2)
            resp = requests.get(LEAKCHECK_URL, params={"check": email},
                                headers=HEADERS, timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        if not data.get("success") or not data.get("found"):
            return []
        return [{"name": s.get("name","Bilinmeyen"), "date": s.get("date",""),
                 "fields": s.get("fields",[])} for s in data.get("sources",[])]
    except Exception:
        return []

def _emailrep_query(email: str) -> dict:
    try:
        resp = requests.get(f"{EMAILREP_URL}/{email}", headers=HEADERS, timeout=8)
        if resp.status_code != 200:
            return {}
        data    = resp.json()
        details = data.get("details", {})
        return {"reputation": data.get("reputation","unknown"),
                "data_breach": details.get("data_breach", False),
                "malicious":   details.get("malicious_activity", False)}
    except Exception:
        return {}

def _save_leak(scan_id, email, name, date, fields):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO leak_results (scan_id, email, breach_name, breach_date, data_classes)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, email, name, date, json.dumps(fields)))

def collect_leaks(scan_id: int, email: str) -> list:
    results = []

    for breach in _leakcheck_query(email):
        _save_leak(scan_id, email, breach["name"], breach["date"], breach["fields"])
        results.append({"name": breach["name"], "date": breach["date"],
                        "classes": breach["fields"], "kaynak": "LeakCheck API"})

    rep = _emailrep_query(email)
    if rep:
        domain = email.split("@")[-1] if "@" in email else ""
        if not results and rep.get("data_breach"):
            for breach in KNOWN_BREACHED_DOMAINS.get(domain, []):
                _save_leak(scan_id, email, breach["name"], breach["date"], breach["fields"])
                results.append({"name": breach["name"], "date": breach["date"],
                                "classes": breach["fields"], "kaynak": "emailrep.io (onaylı)"})
        if rep.get("reputation") in ("low","none") or rep.get("malicious"):
            label = f"emailrep.io — İtibar: {rep.get('reputation','?')}"
            _save_leak(scan_id, email, label, "", ["Email reputation"])
            results.append({"name": label, "date": "", "classes": ["Email reputation"],
                            "kaynak": "emailrep.io"})

    if not results:
        domain = email.split("@")[-1] if "@" in email else ""
        for breach in KNOWN_BREACHED_DOMAINS.get(domain, []):
            _save_leak(scan_id, email, breach["name"], breach["date"], breach["fields"])
            results.append({"name": breach["name"], "date": breach["date"],
                            "classes": breach["fields"], "kaynak": "Statik DB (yedek)"})
    return results


# ─────────────────────────────────────────────
# SOSYAL MEDYA — IP ban korumalı
# ─────────────────────────────────────────────

PLATFORMS = {
    "Twitter":   "https://twitter.com/{}",
    "GitHub":    "https://github.com/{}",
    "LinkedIn":  "https://www.linkedin.com/in/{}",
    "Instagram": "https://www.instagram.com/{}",
    "Reddit":    "https://www.reddit.com/user/{}",
}

NOT_FOUND_HINTS = {
    "Twitter":   ["this account doesn't exist", "account suspended"],
    "GitHub":    ["not found", "404"],
    "LinkedIn":  ["page not found", "profile not found", "no longer available"],
    "Instagram": ["sorry, this page", "isn't available"],
    "Reddit":    ["nobody on reddit goes by that name"],
}

# Farklı User-Agent'lar — aynı UA ile art arda istek ban riskini artırır
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

def collect_social(scan_id: int, username: str) -> list:
    """
    IP ban koruması:
    1. Her istek arasında rastgele 1-3 sn bekleme
    2. Her platformda farklı User-Agent rotasyonu
    3. 429 (rate limit) gelirse o platformu atla, hata kaydet
    4. Session kullan — bağlantı overhead'i azalt
    """
    results = []
    session = requests.Session()

    for i, (platform, url_template) in enumerate(PLATFORMS.items()):
        url   = url_template.format(username)
        found = False

        # Rotasyon: her platform için farklı UA
        ua = USER_AGENTS[i % len(USER_AGENTS)]

        try:
            resp = session.get(
                url,
                timeout=8,
                allow_redirects=True,
                headers={
                    "User-Agent":      ua,
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
            )

            if resp.status_code == 429:
                # Rate limit — bu platformu atla
                results.append({"platform": platform, "url": url,
                                 "found": False, "note": "rate_limited"})
                continue

            if resp.status_code == 200:
                body_lower = resp.text.lower()
                hints      = NOT_FOUND_HINTS.get(platform, [])
                found      = not any(hint in body_lower for hint in hints)

        except Exception:
            found = False

        with get_conn() as conn:
            conn.execute("""
                INSERT INTO social_links (scan_id, platform, username, url, found)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, platform, username, url, found))

        results.append({"platform": platform, "url": url, "found": found})

        # İstekler arası rastgele bekleme — bot tespitini engeller
        if i < len(PLATFORMS) - 1:
            time.sleep(random.uniform(1.0, 2.5))

    session.close()
    return results


# ─────────────────────────────────────────────
# PORT TARAMA — Shodan & Go
# ─────────────────────────────────────────────

def collect_ports_shodan(scan_id: int, domain: str) -> list:
    if not SHODAN_API_KEY:
        return [{"error": "SHODAN_API_KEY tanımlanmamış (.env dosyasını kontrol edin)"}]
    try:
        ip   = socket.gethostbyname(domain)
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                            params={"key": SHODAN_API_KEY}, timeout=10)
        results = []
        for item in resp.json().get("data", []):
            port        = item.get("port", 0)
            service     = item.get("_shodan", {}).get("module", "unknown")
            is_critical = port in CRITICAL_PORTS
            with get_conn() as conn:
                conn.execute("""
                    INSERT INTO port_results (scan_id, ip, port, service, is_critical)
                    VALUES (?, ?, ?, ?, ?)
                """, (scan_id, ip, port, service, is_critical))
            results.append({"port": port, "service": service, "critical": is_critical})
        return results
    except Exception as e:
        return [{"error": str(e)}]


def collect_ports_go(scan_id: int, domain: str) -> list:
    try:
        ip   = socket.gethostbyname(domain)
        resp = requests.post(GO_SCANNER_URL, json={"host": ip}, timeout=15)
        resp.raise_for_status()
        results = []
        for item in resp.json():
            port        = item["port"]
            is_critical = port in CRITICAL_PORTS
            with get_conn() as conn:
                conn.execute("""
                    INSERT INTO port_results (scan_id, ip, port, service, is_critical)
                    VALUES (?, ?, ?, ?, ?)
                """, (scan_id, ip, port, "tcp", is_critical))
            results.append({"port": port, "critical": is_critical})
        return results
    except requests.exceptions.ConnectionError:
        return [{"error": "Go tarayıcısı çalışmıyor. Terminalde: cd scanner && go run main.go"}]
    except Exception as e:
        return [{"error": str(e)}]