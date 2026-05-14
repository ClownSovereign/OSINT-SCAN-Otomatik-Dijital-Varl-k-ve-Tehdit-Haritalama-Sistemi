"""
AI Analist Modülü — Google Gemini 2.5 Flash (ücretsiz tier)
"""

import requests
import json
import os
import re
from core.db import get_conn

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models"
    "/gemini-2.5-flash:generateContent"
)


def _gemini_call(prompt: str, max_tokens: int = 1500, json_mode: bool = False) -> str:
    """Gemini 2.5 Flash API çağrısı."""
    if not GEMINI_API_KEY:
        return "⚠️ GEMINI_API_KEY tanımlanmamış."

    system = (
        "Sen OSINT-SCAN sisteminin siber güvenlik analistiyim. "
        "Türkçe, net ve teknik cevaplar ver. "
        "Sadece verilen tarama verisine dayanan yorumlar yap. "
        "Gereksiz giriş cümleleri kullanma, doğrudan konuya gir."
    )

    try:
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": system + "\n\n" + prompt}]}
            ],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.3,
            }
        }

        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        resp = requests.post(
            GEMINI_URL,
            params={"key": GEMINI_API_KEY},
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()

        candidates = data.get("candidates", [])
        if not candidates:
            return "⚠️ Gemini boş yanıt döndürdü."

        finish = candidates[0].get("finishReason", "")
        if finish == "SAFETY":
            return "⚠️ Gemini güvenlik filtresi nedeniyle yanıt vermedi."

        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            return "⚠️ Gemini içerik döndürmedi."

        return parts[0].get("text", "")

    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response else 0
        if code == 429:
            return "⚠️ Günlük istek limiti aşıldı (1500/gün). Yarın tekrar deneyin."
        if code == 400:
            return "⚠️ API isteği geçersiz. API anahtarını kontrol edin."
        return f"⚠️ API hatası ({code}): {e}"
    except requests.exceptions.Timeout:
        return "⚠️ Gemini yanıt vermedi (timeout). Tekrar deneyin."
    except Exception as e:
        return f"⚠️ Bağlantı hatası: {e}"


def _extract_json(text: str) -> str:
    """Gemini yanıtından JSON bloğunu güvenli şekilde ayıklar."""
    text = text.strip()

    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        return match.group(1).strip()

    if text.startswith("[") or text.startswith("{"):
        return text

    match = re.search(r"(\[[\s\S]*\])", text)
    if match:
        return match.group(1)

    return text


def _get_scan_context(scan_id: int) -> dict:
    """Tarama verilerini DB'den çekip özet sözlük döndürür."""
    with get_conn() as conn:
        scan = conn.execute(
            "SELECT target, scan_type, created_at FROM scans WHERE id=?", (scan_id,)
        ).fetchone()

        risk = conn.execute(
            """SELECT score_w, score_s, score_p, score_l, total, risk_level
               FROM risk_scores WHERE scan_id=? ORDER BY id DESC LIMIT 1""",
            (scan_id,)
        ).fetchone()

        leaks = conn.execute(
            "SELECT breach_name, breach_date, data_classes FROM leak_results WHERE scan_id=?",
            (scan_id,)
        ).fetchall()

        ports = conn.execute(
            "SELECT port, service, is_critical FROM port_results WHERE scan_id=?",
            (scan_id,)
        ).fetchall()

        socials = conn.execute(
            "SELECT platform, url FROM social_links WHERE scan_id=? AND found=1",
            (scan_id,)
        ).fetchall()

        whois = conn.execute(
            "SELECT registrar, is_private FROM whois_results WHERE scan_id=?",
            (scan_id,)
        ).fetchone()

        try:
            dns_risks = conn.execute(
                "SELECT risk_note FROM dns_results WHERE scan_id=? AND record_type='RISK'",
                (scan_id,)
            ).fetchall()
        except Exception:
            dns_risks = []

        try:
            subs = conn.execute(
                "SELECT subdomain, is_sensitive FROM subdomain_results WHERE scan_id=?",
                (scan_id,)
            ).fetchall()
        except Exception:
            subs = []

    return {
        "hedef":          scan[0] if scan else "bilinmiyor",
        "tarama_turu":    scan[1] if scan else "bilinmiyor",
        "tarih":          scan[2] if scan else "bilinmiyor",
        "risk_toplam":    risk[4] if risk else 0,
        "risk_seviyesi":  risk[5] if risk else "DÜŞÜK",
        "skor_w":         risk[0] if risk else 0,
        "skor_s":         risk[1] if risk else 0,
        "skor_p":         risk[2] if risk else 0,
        "skor_l":         risk[3] if risk else 0,
        "sizintilar":     [
            {"ad": l[0], "tarih": l[1], "veriler": json.loads(l[2] or "[]")}
            for l in leaks
        ],
        "tum_portlar":    [{"port": p[0], "servis": p[1], "kritik": bool(p[2])} for p in ports],
        "kritik_portlar": [{"port": p[0], "servis": p[1]} for p in ports if p[2]],
        "sosyal_medya":   [{"platform": s[0], "url": s[1]} for s in socials],
        "whois_gizli":    whois[1] if whois else True,
        "whois_registrar":whois[0] if whois else "-",
        "dns_riskleri":   [d[0] for d in dns_risks],
        "subdomainler":   [{"domain": s[0], "hassas": bool(s[1])} for s in subs],
        "hassas_sub":     [s[0] for s in subs if s[1]],
    }


def analyze_scan(scan_id: int) -> str:
    """Tarama sonucunu AI ile yorumlar."""
    ctx = _get_scan_context(scan_id)

    if ctx["risk_toplam"] == 0 and not ctx["sizintilar"] and not ctx["tum_portlar"]:
        return (
            "### Genel Değerlendirme\n"
            f"**{ctx['hedef']}** hedefi için henüz yeterli veri toplanmamış. "
            "Taramayı tamamlayıp tekrar deneyin.\n\n"
            "> İpucu: Port taraması için Go servisinin çalışıyor olması gerekir."
        )

    prompt = f"""Aşağıdaki OSINT tarama sonucunu analiz et:

## Tarama Bilgileri
- **Hedef:** {ctx['hedef']}
- **Tür:** {ctx['tarama_turu']}
- **Risk Seviyesi:** {ctx['risk_seviyesi']} (Toplam Puan: {ctx['risk_toplam']}/210)
- **WHOIS:** {"Gizli ✓" if ctx['whois_gizli'] else f"AÇIK ✗ — Registrar: {ctx['whois_registrar']}"}

## Bulgular
- **Veri Sızıntıları ({len(ctx['sizintilar'])} adet):**
{chr(10).join(f"  - {s['ad']} ({s['tarih']}): {', '.join(s['veriler'])}" for s in ctx['sizintilar']) or "  Yok"}

- **Açık Portlar ({len(ctx['tum_portlar'])} adet, {len(ctx['kritik_portlar'])} kritik):**
{chr(10).join(f"  - Port {p['port']} ({p['servis']}) {'⚠️ KRİTİK' if p['kritik'] else ''}" for p in ctx['tum_portlar'][:10]) or "  Yok"}

- **Sosyal Medya ({len(ctx['sosyal_medya'])} hesap):**
{chr(10).join(f"  - {s['platform']}: {s['url']}" for s in ctx['sosyal_medya']) or "  Bulunamadı"}

- **DNS Güvenlik Sorunları ({len(ctx['dns_riskleri'])} adet):**
{chr(10).join(f"  - {d}" for d in ctx['dns_riskleri']) or "  Yok"}

- **Hassas Subdomainler ({len(ctx['hassas_sub'])} adet):**
{chr(10).join(f"  - {s}" for s in ctx['hassas_sub'][:5]) or "  Yok"}

## İstenen Analiz

Şu 4 başlık altında analiz yaz (markdown kullan):

### 1. Genel Değerlendirme
(2-3 cümle — genel tablo ve önem derecesi)

### 2. En Kritik Tehditler
(en az 3 madde — somut bulgulara dayandır)

### 3. Acil Yapılması Gerekenler
(öncelik sırasıyla, somut adımlar)

### 4. Orta Vadeli Öneriler
(3-5 madde)"""

    return _gemini_call(prompt, max_tokens=1500)


def generate_ai_scenarios(scan_id: int) -> list:
    """AI destekli saldırı senaryoları üretir."""
    ctx = _get_scan_context(scan_id)

    # Veri yoksa boş dön
    bulgular = (
        ctx["sizintilar"] or ctx["kritik_portlar"] or
        ctx["dns_riskleri"] or ctx["hassas_sub"] or
        ctx["sosyal_medya"]
    )
    if not bulgular:
        return []

    # Bulguları özetle
    bulgu_ozet = []
    if ctx["sizintilar"]:
        bulgu_ozet.append(f"{len(ctx['sizintilar'])} veri sızıntısı: " +
                          ", ".join(s['ad'] for s in ctx['sizintilar'][:3]))
    if ctx["kritik_portlar"]:
        bulgu_ozet.append(f"Kritik açık portlar: " +
                          ", ".join(str(p['port']) for p in ctx['kritik_portlar']))
    if ctx["dns_riskleri"]:
        bulgu_ozet.append("DNS sorunları: " + "; ".join(ctx['dns_riskleri'][:2]))
    if ctx["hassas_sub"]:
        bulgu_ozet.append(f"Hassas subdomainler: " + ", ".join(ctx['hassas_sub'][:3]))
    if ctx["sosyal_medya"]:
        bulgu_ozet.append(f"Sosyal medya hesapları: " +
                          ", ".join(s['platform'] for s in ctx['sosyal_medya']))

    prompt = f"""Hedef: {ctx['hedef']} | Risk: {ctx['risk_seviyesi']} ({ctx['risk_toplam']} puan)

Bulgular:
{chr(10).join(f"- {b}" for b in bulgu_ozet)}

Bu bulgulara dayanarak 3 farklı gerçekçi saldırı senaryosu üret.
Yanıtı SADECE aşağıdaki JSON formatında ver, başka hiçbir şey ekleme:

[
  {{
    "tur": "Saldırı türü adı",
    "kaynak": "Hangi bulgulardan tetiklendi",
    "aciklama": "Saldırı nasıl gerçekleşebilir (2-3 cümle)",
    "onlem": "Bu saldırıyı önlemek için yapılması gerekenler"
  }}
]"""

    raw = _gemini_call(prompt, max_tokens=1200, json_mode=True)

    if raw.startswith("⚠️"):
        return []

    try:
        json_str  = _extract_json(raw)
        scenarios = json.loads(json_str)

        if not isinstance(scenarios, list):
            return []

        return [
            {
                "tür":      s.get("tur", "Bilinmeyen Saldırı"),
                "kaynak":   s.get("kaynak", "-"),
                "açıklama": s.get("aciklama", "-"),
                "önlem":    s.get("onlem", "-"),
                "ai":       True,
            }
            for s in scenarios
            if isinstance(s, dict) and s.get("tur")
        ]
    except (json.JSONDecodeError, Exception):
        return []


def chat(scan_id: int, soru: str, gecmis: list) -> str:
    """Kullanıcının tarama sonucu hakkında soru sormasına izin verir."""
    ctx = _get_scan_context(scan_id)

    bagiam = (
        f"Mevcut tarama: {ctx['hedef']} | "
        f"Risk: {ctx['risk_seviyesi']} ({ctx['risk_toplam']} puan) | "
        f"Sızıntı: {len(ctx['sizintilar'])} | "
        f"Kritik port: {len(ctx['kritik_portlar'])} | "
        f"Sosyal medya: {len(ctx['sosyal_medya'])} hesap | "
        f"DNS sorunu: {len(ctx['dns_riskleri'])} | "
        f"Hassas subdomain: {len(ctx['hassas_sub'])}"
    )

    konusma = ""
    for m in gecmis[-6:]:
        rol = "Kullanıcı" if m["rol"] == "kullanici" else "Asistan"
        konusma += f"{rol}: {m['mesaj']}\n"

    prompt = f"""{bagiam}

{konusma}
Kullanıcı: {soru}

Kullanıcının sorusunu tarama bağlamını göz önünde bulundurarak yanıtla."""

    return _gemini_call(prompt, max_tokens=600)
