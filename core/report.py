from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import cm
from datetime import datetime
from core.db import get_conn
import json

# ─────────────────────────────────────────────
# Risk seviyesi → renk eşlemesi
# risk_engine.py'nin ürettiği Türkçe karakterli
# değerlerle birebir eşleşiyor.
# ─────────────────────────────────────────────
RISK_COLORS = {
    "DÜŞÜK":  "#2ecc71",   # yeşil
    "ORTA":   "#f1c40f",   # sarı
    "YÜKSEK": "#e67e22",   # turuncu
    "KRİTİK": "#e74c3c",   # kırmızı
}
DEFAULT_RISK_COLOR = "#2ecc71"


def generate_pdf(scan_id: int, output_path: str) -> str:
    with get_conn() as conn:
        scan = conn.execute(
            "SELECT target, scan_type, created_at FROM scans WHERE id=?", (scan_id,)
        ).fetchone()

        whois = conn.execute(
            "SELECT registrar, admin_email, country, is_private FROM whois_results WHERE scan_id=?",
            (scan_id,)
        ).fetchone()

        ports = conn.execute(
            "SELECT ip, port, service, is_critical FROM port_results WHERE scan_id=?",
            (scan_id,)
        ).fetchall()

        leaks = conn.execute(
            "SELECT email, breach_name, breach_date, data_classes FROM leak_results WHERE scan_id=?",
            (scan_id,)
        ).fetchall()

        socials = conn.execute(
            "SELECT platform, url, found FROM social_links WHERE scan_id=? AND found=1",
            (scan_id,)
        ).fetchall()

        risk = conn.execute(
            """SELECT score_w, score_s, score_p, score_l, total, risk_level
               FROM risk_scores WHERE scan_id=? ORDER BY id DESC LIMIT 1""",
            (scan_id,)
        ).fetchone()

    # ── PDF belgesi ──
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    # ── Stiller ──
    title_style = ParagraphStyle(
        "title", fontSize=20, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1a1a2e"), spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        "subtitle", fontSize=11, fontName="Helvetica",
        textColor=colors.HexColor("#555555"), spaceAfter=20
    )
    heading_style = ParagraphStyle(
        "heading", fontSize=13, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#16213e"), spaceBefore=16, spaceAfter=8
    )

    # ── Risk rengi — eşleşme garantili ──
    level      = risk[5] if risk else "DÜŞÜK"
    risk_color = colors.HexColor(RISK_COLORS.get(level, DEFAULT_RISK_COLOR))

    story = []

    # Başlık
    story.append(Paragraph("OSINT-SCAN", title_style))
    story.append(Paragraph("Dijital Varlik ve Tehdit Haritasi Raporu", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.4 * cm))

    # ── Tarama Bilgileri ──
    story.append(Paragraph("Tarama Bilgileri", heading_style))
    info_data = [
        ["Hedef",       scan[0] if scan else "-"],
        ["Tarama Turu", scan[1] if scan else "-"],
        ["Tarih",       scan[2] if scan else datetime.now().strftime("%Y-%m-%d %H:%M")],
        ["Rapor No",    f"OSINT-{scan_id:04d}"],
    ]
    story.append(_make_table(info_data, [4 * cm, 13 * cm], header=False))
    story.append(Spacer(1, 0.4 * cm))

    # ── Risk Skoru ──
    story.append(Paragraph("Risk Skoru", heading_style))
    risk_data = [
        ["Metrik",              "Puan", "Aciklama"],
        ["W - WHOIS Gizliligi", str(risk[0] if risk else 0), "Kayit bilgileri herkese aciksa +10"],
        ["S - Sizinti Skoru",   str(risk[1] if risk else 0), "Her sizinti icin +30 (max 90)"],
        ["P - Port Skoru",      str(risk[2] if risk else 0), "Her kritik port icin +20 (max 60)"],
        ["L - Sosyal Baglanti", str(risk[3] if risk else 0), "Her sosyal hesap icin +8 (max 40)"],
        ["TOPLAM (TP)",         str(risk[4] if risk else 0), f"Risk Seviyesi: {level}"],
    ]
    t = _make_table(risk_data, [5 * cm, 2.5 * cm, 9.5 * cm], header=True)
    # Son satırı risk rengiyle boyama
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, -1), (-1, -1), risk_color),
        ("TEXTCOLOR",  (0, -1), (-1, -1), colors.white),
        ("FONTNAME",   (0, -1), (-1, -1), "Helvetica-Bold"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    # ── WHOIS ──
    if whois:
        story.append(Paragraph("WHOIS Bilgileri", heading_style))
        w_data = [
            ["Registrar",   whois[0] or "-"],
            ["Admin Email", whois[1] or "-"],
            ["Ulke",        whois[2] or "-"],
            ["Gizlilik",    "Gizli" if whois[3] else "Acik (Risk!)"],
        ]
        story.append(_make_table(w_data, [4 * cm, 13 * cm], header=False))
        story.append(Spacer(1, 0.4 * cm))

    # ── Portlar ──
    if ports:
        story.append(Paragraph(f"Acik Portlar ({len(ports)} adet)", heading_style))
        p_data = [["IP", "Port", "Servis", "Kritik mi?"]]
        for p in ports:
            p_data.append([p[0], str(p[1]), p[2] or "-", "EVET" if p[3] else "Hayir"])
        story.append(_make_table(p_data, [4 * cm, 2.5 * cm, 5 * cm, 5.5 * cm], header=True))
        story.append(Spacer(1, 0.4 * cm))

    # ── Sızıntılar ──
    if leaks:
        story.append(Paragraph(f"Sizinti Kayitlari ({len(leaks)} adet)", heading_style))
        l_data = [["E-posta", "Sizinti Adi", "Tarih", "Etkilenen Veriler"]]
        for l in leaks:
            classes = ", ".join(json.loads(l[3] or "[]"))
            l_data.append([l[0], l[1], l[2], classes])
        story.append(_make_table(l_data, [4.5 * cm, 3.5 * cm, 2.5 * cm, 6.5 * cm], header=True))
        story.append(Spacer(1, 0.4 * cm))

    # ── Sosyal Medya ──
    if socials:
        story.append(Paragraph(f"Bulunan Sosyal Medya Hesaplari ({len(socials)} adet)", heading_style))
        s_data = [["Platform", "URL"]]
        for s in socials:
            s_data.append([s[0], s[1]])
        story.append(_make_table(s_data, [4 * cm, 13 * cm], header=True))
        story.append(Spacer(1, 0.4 * cm))

    # ── Footer ──
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        f"Bu rapor OSINT-SCAN sistemi tarafindan otomatik olarak uretilmistir. "
        f"Tarih: {datetime.now().strftime('%d.%m.%Y %H:%M')} | TUBITAK 2204-A",
        ParagraphStyle("footer", fontSize=8, textColor=colors.HexColor("#999999"))
    ))

    doc.build(story)
    return output_path


# ─────────────────────────────────────────────
# Yardımcı — tekrar eden tablo stilini merkeziler
# ─────────────────────────────────────────────
def _make_table(data: list, col_widths: list, header: bool = True) -> Table:
    t = Table(data, colWidths=col_widths)

    base_style = [
        ("FONTSIZE",  (0, 0), (-1, -1), 10),
        ("GRID",      (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("PADDING",   (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.white, colors.HexColor("#fafafa")]),
    ]

    if header:
        base_style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME",   (0, 1), (-1, -1), "Helvetica"),
        ]
    else:
        # Header'sız tablolarda sol sütun kalın
        base_style += [
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
            ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",   (1, 0), (-1, -1), "Helvetica"),
        ]

    t.setStyle(TableStyle(base_style))
    return t