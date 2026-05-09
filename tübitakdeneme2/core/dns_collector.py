"""
DNS Kayıt Tarayıcı
------------------
MX  → mail sunucuları (phishing/spoofing riski)
TXT → SPF, DKIM, DMARC kayıtları (e-posta güvenliği)
NS  → yetkili isim sunucuları
A   → IPv4 adresleri
"""

import socket
import subprocess
import json
from core.db import get_conn


# ─── DB tablosu oluşturma (init_db()'ye ek) ─────────────────────────────────

DNS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS dns_results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER REFERENCES scans(id),
    record_type TEXT,   -- A / MX / TXT / NS
    value       TEXT,
    priority    INTEGER DEFAULT 0,  -- MX için
    risk_note   TEXT,               -- SPF eksik, DMARC yok vs.
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def ensure_dns_table():
    with get_conn() as conn:
        conn.execute(DNS_TABLE_SQL)


# ─── Yardımcı: sistem dig/nslookup ile sorgu ────────────────────────────────

def _query(domain: str, rtype: str) -> list[str]:
    """
    dnspython olmadan sistem araçlarıyla DNS sorgusu yapar.
    Windows'ta nslookup, Linux/Mac'te dig kullanır.
    Her ikisi de yoksa socket ile A kaydı çözer.
    """
    results = []
    try:
        # dig varsa (Linux/Mac)
        out = subprocess.check_output(
            ["dig", "+short", rtype, domain],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()
        results = [line.strip() for line in out.splitlines() if line.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        try:
            # nslookup varsa (Windows)
            out = subprocess.check_output(
                ["nslookup", "-type=" + rtype, domain],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode()
            # nslookup çıktısından değerleri ayıkla
            for line in out.splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("Server"):
                    val = line.split("=")[-1].strip()
                    if val:
                        results.append(val)
        except Exception:
            # Son çare: socket ile sadece A kaydı
            if rtype == "A":
                try:
                    results = [socket.gethostbyname(domain)]
                except Exception:
                    pass
    return results


# ─── Risk analizi ────────────────────────────────────────────────────────────

def _analyze_txt(records: list[str]) -> list[str]:
    """TXT kayıtlarında SPF, DKIM, DMARC eksikliği tespit eder."""
    notes = []
    combined = " ".join(records).lower()

    if "v=spf1" not in combined:
        notes.append("SPF kaydı eksik — e-posta sahtekarlığına açık")
    elif "~all" in combined:
        notes.append("SPF ~all (softfail) — daha güçlü -all önerilir")

    if "v=dkim1" not in combined:
        notes.append("DKIM kaydı bulunamadı — e-posta imzalama eksik")

    if "_dmarc" not in combined and "v=dmarc1" not in combined:
        notes.append("DMARC kaydı eksik — e-posta spoofing riski yüksek")

    return notes


# ─── Ana fonksiyon ───────────────────────────────────────────────────────────

def collect_dns(scan_id: int, domain: str) -> dict:
    """
    Domain'in DNS kayıtlarını toplar, risk notlarıyla birlikte DB'ye yazar.
    Döndürdüğü dict:
        {
            "A":  [...],
            "MX": [...],
            "NS": [...],
            "TXT": [...],
            "risk_notes": [...],
            "risk_score": int   # formüle eklenecek D skoru
        }
    """
    ensure_dns_table()

    all_results = {}
    risk_notes  = []

    for rtype in ("A", "MX", "NS", "TXT"):
        records = _query(domain, rtype)
        all_results[rtype] = records

        for record in records:
            priority = 0
            # MX kaydından öncelik değerini ayıkla (örn: "10 mail.example.com")
            if rtype == "MX":
                parts = record.split()
                if len(parts) == 2 and parts[0].isdigit():
                    priority = int(parts[0])
                    record   = parts[1]

            with get_conn() as conn:
                conn.execute("""
                    INSERT INTO dns_results (scan_id, record_type, value, priority)
                    VALUES (?, ?, ?, ?)
                """, (scan_id, rtype, record, priority))

    # TXT kayıtlarında güvenlik analizi
    txt_notes = _analyze_txt(all_results.get("TXT", []))
    risk_notes.extend(txt_notes)

    # MX yoksa posta alınamaz — bilgi notu
    if not all_results.get("MX"):
        risk_notes.append("MX kaydı yok — domain e-posta almıyor olabilir")

    # Risk notlarını DB'ye yaz
    for note in risk_notes:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO dns_results (scan_id, record_type, value, risk_note)
                VALUES (?, ?, ?, ?)
            """, (scan_id, "RISK", "", note))

    # D skoru: her risk notu +5 puan, max 20
    risk_score = min(len(risk_notes) * 5, 20)

    return {
        "A":          all_results.get("A", []),
        "MX":         all_results.get("MX", []),
        "NS":         all_results.get("NS", []),
        "TXT":        all_results.get("TXT", []),
        "risk_notes": risk_notes,
        "risk_score": risk_score,
    }