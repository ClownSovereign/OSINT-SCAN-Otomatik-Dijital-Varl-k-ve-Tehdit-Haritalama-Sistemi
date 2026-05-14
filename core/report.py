from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import cm
from datetime import datetime
from core.db import get_conn
import json

RISK_COLORS = {
    "DÜŞÜK":  "#2ecc71",
    "ORTA":   "#f1c40f",
    "YÜKSEK": "#e67e22",
    "KRİTİK": "#e74c3c",
}
DEFAULT_RISK_COLOR = "#2ecc71"

# Ortak stiller
def _get_styles():
    return {
        "title": ParagraphStyle(
            "title", fontSize=20, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1a1a2e"), spaceAfter=6
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontSize=11, fontName="Helvetica",
            textColor=colors.HexColor("#555555"), spaceAfter=20
        ),
        "heading": ParagraphStyle(
            "heading", fontSize=13, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#16213e"), spaceBefore=16, spaceAfter=8
        ),
        "normal": ParagraphStyle(
            "normal2", fontSize=10, fontName="Helvetica",
            textColor=colors.HexColor("#333333"), spaceAfter=4
        ),
        "footer": ParagraphStyle(
            "footer", fontSize=8, textColor=colors.HexColor("#999999")
        ),
    }

def _make_table(data, col_widths, header=True):
    t = Table(data, colWidths=col_widths)
    base = [
        ("FONTSIZE",  (0,0), (-1,-1), 10),
        ("GRID",      (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
        ("PADDING",   (0,0), (-1,-1), 6),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#fafafa")]),
    ]
    if header:
        base += [
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#16213e")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTNAME",   (0,1), (-1,-1), "Helvetica"),
        ]
    else:
        base += [
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f0f0f0")),
            ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTNAME",   (1,0), (-1,-1), "Helvetica"),
        ]
    t.setStyle(TableStyle(base))
    return t

def _header(story, baslik, alt_baslik, styles):
    story.append(Paragraph(baslik, styles["title"]))
    story.append(Paragraph(alt_baslik, styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.4*cm))

def _footer(story, scan_id, styles):
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"OSINT-SCAN | Rapor No: OSINT-{scan_id:04d} | "
        f"Tarih: {datetime.now().strftime('%d.%m.%Y %H:%M')} | TUBITAK 2204-A",
        styles["footer"]
    ))

def _build(story, output_path):
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )
    doc.build(story)
    return output_path

def _fetch_all(scan_id):
    with get_conn() as conn:
        scan    = conn.execute("SELECT target, scan_type, created_at FROM scans WHERE id=?", (scan_id,)).fetchone()
        whois   = conn.execute("SELECT registrar, admin_email, country, is_private FROM whois_results WHERE scan_id=?", (scan_id,)).fetchone()
        ports   = conn.execute("SELECT ip, port, service, is_critical FROM port_results WHERE scan_id=?", (scan_id,)).fetchall()
        leaks   = conn.execute("SELECT email, breach_name, breach_date, data_classes FROM leak_results WHERE scan_id=?", (scan_id,)).fetchall()
        socials = conn.execute("SELECT platform, url, found FROM social_links WHERE scan_id=? AND found=1", (scan_id,)).fetchall()
        risk    = conn.execute("SELECT score_w, score_s, score_p, score_l, total, risk_level FROM risk_scores WHERE scan_id=? ORDER BY id DESC LIMIT 1", (scan_id,)).fetchone()
        try:
            dns   = conn.execute("SELECT record_type, value, priority, risk_note FROM dns_results WHERE scan_id=?", (scan_id,)).fetchall()
        except Exception:
            dns = []
        try:
            subs  = conn.execute("SELECT subdomain, ip, is_sensitive FROM subdomain_results WHERE scan_id=?", (scan_id,)).fetchall()
        except Exception:
            subs = []
    return scan, whois, ports, leaks, socials, risk, dns, subs


# PDF 1 — ANA ÖZET RAPORU
# Tek sayfaya sığan yönetici özeti + risk skoru
def generate_summary_pdf(scan_id: int, output_path: str) -> str:
    scan, whois, ports, leaks, socials, risk, dns, subs = _fetch_all(scan_id)
    styles = _get_styles()
    story  = []

    _header(story, "OSINT-SCAN", "Yonetici Ozet Raporu", styles)

    # Tarama bilgileri
    story.append(Paragraph("Tarama Bilgileri", styles["heading"]))
    story.append(_make_table([
        ["Hedef",       scan[0] if scan else "-"],
        ["Tarama Turu", scan[1] if scan else "-"],
        ["Tarih",       scan[2] if scan else "-"],
        ["Rapor No",    f"OSINT-{scan_id:04d}"],
    ], [4*cm, 13*cm], header=False))
    story.append(Spacer(1, 0.4*cm))

    # Risk özeti
    level      = risk[5] if risk else "DUSUK"
    risk_color = colors.HexColor(RISK_COLORS.get(level, DEFAULT_RISK_COLOR))

    story.append(Paragraph("Risk Ozeti", styles["heading"]))
    risk_data = [
        ["Metrik",              "Puan", "Aciklama"],
        ["W - WHOIS Gizliligi", str(risk[0] if risk else 0), "+10 kayit aciksa"],
        ["S - Sizinti Skoru",   str(risk[1] if risk else 0), "+30 her sizinti (max 90)"],
        ["P - Port Skoru",      str(risk[2] if risk else 0), "+20 kritik port (max 60)"],
        ["L - Sosyal Baglanti", str(risk[3] if risk else 0), "+8 sosyal hesap (max 40)"],
        ["TOPLAM (TP)",         str(risk[4] if risk else 0), f"Seviye: {level}"],
    ]
    t = _make_table(risk_data, [5*cm, 2.5*cm, 9.5*cm], header=True)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,-1), (-1,-1), risk_color),
        ("TEXTCOLOR",  (0,-1), (-1,-1), colors.white),
        ("FONTNAME",   (0,-1), (-1,-1), "Helvetica-Bold"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("Hizli Bakis", styles["heading"]))
    ozet = [
        ["Modül",              "Bulgu Sayısı", "Durum"],
        ["Veri Sizintisi",     str(len(leaks)),   "VAR" if leaks   else "YOK"],
        ["Kritik Acik Port",   str(sum(1 for p in ports if p[3])), "VAR" if any(p[3] for p in ports) else "YOK"],
        ["Sosyal Medya Hesabi",str(len(socials)), "VAR" if socials else "YOK"],
        ["DNS Guvenlik Sorunu",str(len([d for d in dns if d[0]=="RISK"])), "VAR" if any(d[0]=="RISK" for d in dns) else "YOK"],
        ["Hassas Subdomain",   str(sum(1 for s in subs if s[2])), "VAR" if any(s[2] for s in subs) else "YOK"],
    ]
    story.append(_make_table(ozet, [6*cm, 4*cm, 7*cm], header=True))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Detayli bulgular icin: Sizinti Raporu, Port Raporu, DNS & Subdomain Raporu dosyalarini inceleyiniz.",
        styles["normal"]
    ))

    _footer(story, scan_id, styles)
    return _build(story, output_path)

def generate_leak_pdf(scan_id: int, output_path: str) -> str:
    scan, whois, ports, leaks, socials, risk, dns, subs = _fetch_all(scan_id)
    styles = _get_styles()
    story  = []

    _header(story, "OSINT-SCAN", "Sizinti ve Sosyal Medya Raporu", styles)

    # WHOIS
    if whois:
        story.append(Paragraph("WHOIS Bilgileri", styles["heading"]))
        story.append(_make_table([
            ["Registrar",   whois[0] or "-"],
            ["Admin Email", whois[1] or "-"],
            ["Ulke",        whois[2] or "-"],
            ["Gizlilik",    "Gizli" if whois[3] else "ACIK (Risk!)"],
        ], [4*cm, 13*cm], header=False))
        story.append(Spacer(1, 0.4*cm))

    # Sızıntılar
    story.append(Paragraph(f"Veri Sizinti Kayitlari ({len(leaks)} adet)", styles["heading"]))
    if leaks:
        l_data = [["E-posta", "Sizinti Adi", "Tarih", "Etkilenen Veriler"]]
        for l in leaks:
            classes = ", ".join(json.loads(l[3] or "[]"))
            l_data.append([l[0], l[1], l[2] or "-", classes])
        story.append(_make_table(l_data, [4.5*cm, 3.5*cm, 2.5*cm, 6.5*cm], header=True))
    else:
        story.append(Paragraph("Herhangi bir sizinti kaydi tespit edilmedi.", styles["normal"]))
    story.append(Spacer(1, 0.4*cm))

    # Sosyal medya
    story.append(Paragraph(f"Bulunan Sosyal Medya Hesaplari ({len(socials)} adet)", styles["heading"]))
    if socials:
        s_data = [["Platform", "URL"]]
        for s in socials:
            s_data.append([s[0], s[1]])
        story.append(_make_table(s_data, [4*cm, 13*cm], header=True))
    else:
        story.append(Paragraph("Herhangi bir sosyal medya hesabi tespit edilmedi.", styles["normal"]))

    _footer(story, scan_id, styles)
    return _build(story, output_path)


def generate_port_pdf(scan_id: int, output_path: str) -> str:
    scan, whois, ports, leaks, socials, risk, dns, subs = _fetch_all(scan_id)
    styles = _get_styles()
    story  = []

    _header(story, "OSINT-SCAN", "Port Tarama Raporu", styles)

    kritik = [p for p in ports if p[3]]
    normal = [p for p in ports if not p[3]]

    # Özet
    story.append(Paragraph("Port Tarama Ozeti", styles["heading"]))
    story.append(_make_table([
        ["Toplam Acik Port", str(len(ports))],
        ["Kritik Port Sayisi", str(len(kritik))],
        ["Normal Port Sayisi", str(len(normal))],
    ], [6*cm, 11*cm], header=False))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph(f"Kritik Portlar ({len(kritik)} adet)", styles["heading"]))
    if kritik:
        p_data = [["IP", "Port", "Servis", "Risk"]]
        for p in kritik:
            p_data.append([p[0], str(p[1]), p[2] or "-", "KRITIK"])
        t = _make_table(p_data, [4*cm, 2.5*cm, 5*cm, 5.5*cm], header=True)
        t.setStyle(TableStyle([
            ("TEXTCOLOR", (3,1), (3,-1), colors.HexColor("#e74c3c")),
            ("FONTNAME",  (3,1), (3,-1), "Helvetica-Bold"),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Kritik port tespit edilmedi.", styles["normal"]))
    story.append(Spacer(1, 0.4*cm))

    if normal:
        story.append(Paragraph(f"Diger Acik Portlar ({len(normal)} adet)", styles["heading"]))
        p_data = [["IP", "Port", "Servis"]]
        for p in normal[:50]:  # max 50 satır
            p_data.append([p[0], str(p[1]), p[2] or "-"])
        story.append(_make_table(p_data, [5*cm, 3*cm, 9*cm], header=True))
        if len(normal) > 50:
            story.append(Paragraph(f"... ve {len(normal)-50} port daha.", styles["normal"]))

    _footer(story, scan_id, styles)
    return _build(story, output_path)


def generate_dns_pdf(scan_id: int, output_path: str) -> str:
    scan, whois, ports, leaks, socials, risk, dns, subs = _fetch_all(scan_id)
    styles = _get_styles()
    story  = []

    _header(story, "OSINT-SCAN", "DNS ve Subdomain Raporu", styles)

    # DNS risk notları
    dns_risks  = [d for d in dns if d[0] == "RISK"]
    dns_kayitlar = [d for d in dns if d[0] != "RISK"]

    story.append(Paragraph(f"DNS Guvenlik Sorunlari ({len(dns_risks)} adet)", styles["heading"]))
    if dns_risks:
        r_data = [["Sorun"]]
        for r in dns_risks:
            r_data.append([r[3] or r[1]])
        t = _make_table(r_data, [17*cm], header=True)
        t.setStyle(TableStyle([
            ("TEXTCOLOR", (0,1), (-1,-1), colors.HexColor("#e74c3c")),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("DNS kayitlarinda guvenlik sorunu tespit edilmedi.", styles["normal"]))
    story.append(Spacer(1, 0.4*cm))

    # DNS kayıtları türe göre
    for rtype in ("A", "MX", "NS", "TXT"):
        kayitlar = [d for d in dns_kayitlar if d[0] == rtype]
        if kayitlar:
            story.append(Paragraph(f"{rtype} Kayitlari ({len(kayitlar)} adet)", styles["heading"]))
            d_data = [["Deger", "Oncelik"]]
            for k in kayitlar:
                d_data.append([k[1], str(k[2]) if k[2] else "-"])
            story.append(_make_table(d_data, [13*cm, 4*cm], header=True))
            story.append(Spacer(1, 0.3*cm))

    # Subdomainler
    hassas = [s for s in subs if s[2]]
    normal = [s for s in subs if not s[2]]

    story.append(Paragraph(f"Subdomain Sonuclari (Toplam: {len(subs)})", styles["heading"]))

    if hassas:
        story.append(Paragraph(f"Hassas Subdomainler ({len(hassas)} adet)", styles["heading"]))
        s_data = [["Subdomain", "IP", "Durum"]]
        for s in hassas:
            s_data.append([s[0], s[1], "HASSAS"])
        t = _make_table(s_data, [8*cm, 5*cm, 4*cm], header=True)
        t.setStyle(TableStyle([
            ("TEXTCOLOR", (2,1), (2,-1), colors.HexColor("#e67e22")),
            ("FONTNAME",  (2,1), (2,-1), "Helvetica-Bold"),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3*cm))

    if normal:
        story.append(Paragraph(f"Diger Subdomainler ({len(normal)} adet)", styles["heading"]))
        s_data = [["Subdomain", "IP"]]
        for s in normal[:30]:
            s_data.append([s[0], s[1]])
        story.append(_make_table(s_data, [10*cm, 7*cm], header=True))
        if len(normal) > 30:
            story.append(Paragraph(f"... ve {len(normal)-30} subdomain daha.", styles["normal"]))

    if not subs:
        story.append(Paragraph("Aktif subdomain tespit edilmedi.", styles["normal"]))

    _footer(story, scan_id, styles)
    return _build(story, output_path)


# Geriye uyumluluk — eski generate_pdf() çağrıları çalışmaya devam eder
def generate_pdf(scan_id: int, output_path: str) -> str:
    return generate_summary_pdf(scan_id, output_path)
