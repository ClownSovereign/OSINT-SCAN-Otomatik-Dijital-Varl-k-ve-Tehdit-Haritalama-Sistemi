from core.db import get_conn
from core.config import (
    CRITICAL_PORTS,
    RISK_WEIGHT_WHOIS, RISK_WEIGHT_LEAK, RISK_WEIGHT_PORT, RISK_WEIGHT_SOCIAL,
    RISK_MAX_LEAK, RISK_MAX_PORT, RISK_MAX_SOCIAL,
    RISK_LEVEL_CRITICAL, RISK_LEVEL_HIGH, RISK_LEVEL_MEDIUM,
    RISK_WEIGHT_DNS, RISK_MAX_DNS,
)
import json

# -------------------------------------------------------
# Tehdit Puanı Formülü (TÜBİTAK Bölümü)
# TP = W(10) + S(30×n,max90) + P(20×n,max60) + L(8×n,max40) + D(5×n,max20)
#
# W: WHOIS açıksa +10
# S: Her sızıntı +30 (max 90)
# P: Her kritik port +20 (max 60)
# L: Her sosyal hesap +8 (max 40)
# D: Her DNS risk notu +5 (max 20) ← YENİ
# -------------------------------------------------------

def calculate_risk(scan_id: int) -> dict:
    score = {"W": 0, "S": 0, "P": 0, "L": 0, "D": 0}

    with get_conn() as conn:
        # W — WHOIS
        row = conn.execute(
            "SELECT is_private FROM whois_results WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if row and not row[0]:
            score["W"] = RISK_WEIGHT_WHOIS

        # S — Sızıntı
        leak_count = conn.execute(
            "SELECT COUNT(*) FROM leak_results WHERE scan_id=?", (scan_id,)
        ).fetchone()[0]
        score["S"] = min(leak_count * RISK_WEIGHT_LEAK, RISK_MAX_LEAK)

        # P — Kritik Port
        critical_count = conn.execute("""
            SELECT COUNT(*) FROM port_results
            WHERE scan_id=? AND is_critical=1
        """, (scan_id,)).fetchone()[0]
        score["P"] = min(critical_count * RISK_WEIGHT_PORT, RISK_MAX_PORT)

        # L — Sosyal
        social_found = conn.execute(
            "SELECT COUNT(*) FROM social_links WHERE scan_id=? AND found=1", (scan_id,)
        ).fetchone()[0]
        score["L"] = min(social_found * RISK_WEIGHT_SOCIAL, RISK_MAX_SOCIAL)

        # D — DNS risk notları (tablo yoksa 0)
        try:
            dns_risk_count = conn.execute("""
                SELECT COUNT(*) FROM dns_results
                WHERE scan_id=? AND record_type='RISK'
            """, (scan_id,)).fetchone()[0]
            score["D"] = min(dns_risk_count * RISK_WEIGHT_DNS, RISK_MAX_DNS)
        except Exception:
            score["D"] = 0

        total = sum(score.values())

        if total >= RISK_LEVEL_CRITICAL:
            level = "KRİTİK"
        elif total >= RISK_LEVEL_HIGH:
            level = "YÜKSEK"
        elif total >= RISK_LEVEL_MEDIUM:
            level = "ORTA"
        else:
            level = "DÜŞÜK"

        conn.execute("""
            INSERT INTO risk_scores (scan_id, score_w, score_s, score_p, score_l, total, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, score["W"], score["S"], score["P"], score["L"], total, level))

    return {
        "breakdown": score,
        "total":     total,
        "level":     level,
        "formula":   (
            f"TP = W({score['W']}) + S({score['S']}) + "
            f"P({score['P']}) + L({score['L']}) + D({score['D']}) = {total}"
        )
    }


def build_attack_scenarios(scan_id: int) -> list:
    scenarios = []

    with get_conn() as conn:
        leaks = conn.execute(
            "SELECT breach_name, data_classes FROM leak_results WHERE scan_id=?", (scan_id,)
        ).fetchall()
        for leak in leaks:
            classes = json.loads(leak[1] or "[]")
            if "Passwords" in classes:
                scenarios.append({
                    "tür":      "Kimlik Bilgisi Doldurmak (Credential Stuffing)",
                    "kaynak":   f"{leak[0]} sızıntısı",
                    "açıklama": "Sızdırılan parola diğer servislerde denenebilir."
                })

        critical = conn.execute("""
            SELECT port, service FROM port_results
            WHERE scan_id=? AND is_critical=1
        """, (scan_id,)).fetchall()
        for port_row in critical:
            if port_row[0] in (22, 3389):
                scenarios.append({
                    "tür":      "Brute-Force Saldırısı",
                    "kaynak":   f"Port {port_row[0]} ({port_row[1]}) açık",
                    "açıklama": "Uzaktan erişim portu dışarıya açık; otomatik saldırı riski yüksek."
                })

        # DNS spoofing senaryosu
        try:
            spf_missing = conn.execute("""
                SELECT COUNT(*) FROM dns_results
                WHERE scan_id=? AND record_type='RISK' AND value=''
            """, (scan_id,)).fetchone()[0]
            if spf_missing > 0:
                scenarios.append({
                    "tür":      "E-posta Sahtekarlığı (Spoofing)",
                    "kaynak":   "DNS — SPF/DMARC eksikliği",
                    "açıklama": "Saldırgan bu domain adına sahte e-posta gönderebilir."
                })
        except Exception:
            pass

    return scenarios