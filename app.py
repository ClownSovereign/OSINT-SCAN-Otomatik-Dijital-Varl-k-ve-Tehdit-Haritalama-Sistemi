import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import tempfile
import os
import random
import time
from dotenv import load_dotenv
load_dotenv()  

from core.db import init_db, get_conn
from core.go_runner import ensure_go_scanner
from core.collector import collect_whois, collect_leaks, collect_social, collect_ports_go
from core.dns_collector import collect_dns
from core.subdomain_scanner import collect_subdomains
from core.risk_engine import calculate_risk, build_attack_scenarios
from core.report import generate_summary_pdf, generate_leak_pdf, generate_port_pdf, generate_dns_pdf
from core.ai_analyst import analyze_scan, generate_ai_scenarios, chat as ai_chat

st.set_page_config(
    page_title="OSINT-SCAN | TÜBİTAK",
    page_icon="🔍",
    layout="wide"
)
init_db()

if "go_status" not in st.session_state:
    with st.spinner("⚙️ Go tarayıcı motoru başlatılıyor..."):
        st.session_state["go_status"] = ensure_go_scanner()

if not st.session_state["go_status"]["ok"]:
    st.warning(
        f"⚠️ Go tarayıcısı başlatılamadı — port taraması devre dışı.\n\n"
        f"{st.session_state['go_status']['error']}"
    )

st.title("🔍 OSINT-SCAN — Dijital Varlık ve Tehdit Haritalama Sistemi")
st.caption("TÜBİTAK 2204-A Proje Portalı | Otomatik Açık Kaynak İstihbarat Analizi")

sekme_tarama, sekme_dns, sekme_subdomain, sekme_ai, sekme_gecmis = st.tabs([
    "🛰️ Yeni Tarama",
    "🌐 DNS Analizi",
    "🔎 Subdomain Tarama",
    "🤖 AI Analist",
    "🗂️ Geçmiş Taramalar",
])

with sekme_tarama:

    with st.sidebar:
        st.header("🛰️ Yeni Tarama")
        st.markdown("---")
        target = st.text_input("Hedef Girin",
                               placeholder="örnek.com veya kullanici@eposta.com")
        scan_type = st.radio(
            "Tarama Türü",
            ["domain", "eposta", "kullanici_adi"],
            format_func=lambda x: {
                "domain":        "🌐 Alan Adı (Domain)",
                "eposta":        "📧 E-Posta Adresi",
                "kullanici_adi": "👤 Kullanıcı Adı"
            }[x]
        )
        st.markdown("---")
        st.markdown("**Tarama Modülleri:**")
        st.markdown("✅ WHOIS Kayıt Analizi")
        st.markdown("✅ Veri Sızıntısı Kontrolü")
        st.markdown("✅ Sosyal Medya Taraması")
        st.markdown("✅ DNS Kayıt Analizi")
        st.markdown("✅ Subdomain Keşfi")
        go_icon = "✅" if st.session_state["go_status"]["ok"] else "❌"
        st.markdown(f"{go_icon} Port Taraması (Go)")
        st.markdown("✅ Risk Skoru Hesaplama")
        st.markdown("---")
        baslat = st.button("🚀 Taramayı Başlat", type="primary", width='stretch')

    if baslat and target:
        with get_conn() as conn:
            cur     = conn.execute("INSERT INTO scans (target, scan_type) VALUES (?, ?)",
                                   (target, scan_type))
            scan_id = cur.lastrowid

        ilerleme   = st.progress(0)
        durum_yazi = st.empty()

        def guncelle(pct, msg):
            ilerleme.progress(pct, text=msg)

        guncelle(5,  "🔎 WHOIS kayıt bilgileri toplanıyor...")
        collect_whois(scan_id, target)

        guncelle(20, "💧 Veri sızıntıları kontrol ediliyor...")
        collect_leaks(scan_id, target if "@" in target else f"admin@{target}")

        guncelle(35, "🌐 DNS kayıtları analiz ediliyor...")
        dns_veri = collect_dns(scan_id, target.split("@")[-1] if "@" in target else target)

        guncelle(50, "🔎 Subdomainler taranıyor...")
        collect_subdomains(scan_id, target.split("@")[-1] if "@" in target else target)

        guncelle(65, "📱 Sosyal medya hesapları taranıyor...")
        collect_social(scan_id, target.split(".")[0].split("@")[0])

        if st.session_state["go_status"]["ok"]:
            guncelle(80, "🔌 Açık portlar taranıyor (Go motoru)...")
            collect_ports_go(scan_id, target)
        else:
            guncelle(80, "⏭️ Port taraması atlandı (Go servisi kapalı)")

        guncelle(93, "🧠 Risk puanı hesaplanıyor...")
        risk       = calculate_risk(scan_id)
        senaryolar = build_attack_scenarios(scan_id)

        guncelle(100, "✅ Tarama tamamlandı!")
        durum_yazi.empty()

        st.session_state.update({
            "son_tarama": scan_id,
            "risk":       risk,
            "senaryolar": senaryolar,
            "dns_veri":   dns_veri,
        })

    elif baslat and not target:
        st.sidebar.error("⚠️ Lütfen bir hedef girin.")

    if "son_tarama" in st.session_state:
        scan_id = st.session_state["son_tarama"]
        risk    = st.session_state["risk"]

        st.markdown("---")
        seviye_bilgi = {
            "DÜŞÜK":  ("🟢", "Düşük Risk",  "Hedefe yönelik ciddi bir tehdit tespit edilmedi."),
            "ORTA":   ("🟡", "Orta Risk",   "Bazı güvenlik açıkları mevcut, dikkat önerilir."),
            "YÜKSEK": ("🟠", "Yüksek Risk", "Önemli güvenlik açıkları tespit edildi."),
            "KRİTİK": ("🔴", "Kritik Risk", "Acil müdahale gerektirecek düzeyde tehdit var!"),
        }
        seviye = risk["level"]
        emoji, etiket, aciklama = seviye_bilgi.get(seviye, ("⚪", seviye, ""))

        st.subheader(f"{emoji} Genel Risk Değerlendirmesi: {etiket}")
        st.info(aciklama)

        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("🎯 Tehdit Puanı", risk["total"], delta=seviye, delta_color="inverse")
        k2.metric("🔍 WHOIS",  risk["breakdown"]["W"],
                  delta="Açık" if risk["breakdown"]["W"] > 0 else "Gizli")
        k3.metric("💧 Sızıntı", risk["breakdown"]["S"],
                  delta="Bulundu" if risk["breakdown"]["S"] > 0 else "Temiz")
        k4.metric("🔌 Port",   risk["breakdown"]["P"],
                  delta="Kritik" if risk["breakdown"]["P"] > 0 else "Güvenli")
        k5.metric("🌐 DNS",    risk["breakdown"].get("D", 0),
                  delta="Risk var" if risk["breakdown"].get("D", 0) > 0 else "Temiz")

        st.markdown("---")

        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk["total"],
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Dijital Tehdit Seviyesi", "font": {"size": 20}},
            gauge={
                "axis": {"range": [0, 210], "tickwidth": 1},
                "bar":  {"color": "darkred"},
                "steps": [
                    {"range": [0,   40],  "color": "#2ecc71"},
                    {"range": [40,  80],  "color": "#f1c40f"},
                    {"range": [80,  150], "color": "#e67e22"},
                    {"range": [150, 210], "color": "#e74c3c"},
                ],
                "threshold": {"line": {"color": "white", "width": 3},
                              "thickness": 0.75, "value": risk["total"]}
            }
        ))
        st.plotly_chart(fig_gauge, width='stretch')

        st.info(f"📐 **Tehdit Puanı Formülü:** {risk['formula']}")
        with st.expander("ℹ️ Formül Hakkında Bilgi"):
            st.markdown("""
            | Değişken | Ağırlık | Açıklama |
            |----------|---------|----------|
            | **W** | +10     | WHOIS kaydı gizli değilse |
            | **S** | +30×n   | Her veri sızıntısı (max 90) |
            | **P** | +20×n   | Her kritik açık port (max 60) |
            | **L** | +8×n    | Her sosyal medya hesabı (max 40) |
            | **D** | +5×n    | Her DNS güvenlik açığı (max 20) |
            """)
            st.markdown("**Risk Seviyeleri:** 0-40 Düşük | 40-80 Orta | 80-150 Yüksek | 150+ Kritik")

        st.markdown("---")
        st.subheader("📄 Raporlar")

        def _pdf_indir(uretici, dosya_adi, buton_adi):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
                yol = uretici(scan_id, f.name)
            with open(yol, "rb") as f:
                veri = f.read()
            os.unlink(yol)
            st.download_button(
                label=buton_adi,
                data=veri,
                file_name=dosya_adi,
                mime="application/pdf",
                width="stretch",
                key=dosya_adi
            )

        st.markdown("**📋 Ana Özet Raporu** — Risk skoru, hızlı bakış ve modül özetleri")
        if st.button("📥 Özet Raporu İndir", key="btn_ozet", type="primary"):
            with st.spinner("Özet rapor hazırlanıyor..."):
                _pdf_indir(generate_summary_pdf, f"ozet_rapor_{scan_id}.pdf", "⬇️ Özet Raporu Kaydet")

        st.markdown("**💧 Sızıntı & Sosyal Medya Raporu** — WHOIS, veri sızıntıları, sosyal hesaplar")
        if st.button("📥 Sızıntı Raporunu İndir", key="btn_leak"):
            with st.spinner("Sızıntı raporu hazırlanıyor..."):
                _pdf_indir(generate_leak_pdf, f"sizinti_rapor_{scan_id}.pdf", "⬇️ Sızıntı Raporunu Kaydet")

        st.markdown("**🔌 Port Tarama Raporu** — Açık portlar, kritik servisler")
        if st.button("📥 Port Raporunu İndir", key="btn_port"):
            with st.spinner("Port raporu hazırlanıyor..."):
                _pdf_indir(generate_port_pdf, f"port_rapor_{scan_id}.pdf", "⬇️ Port Raporunu Kaydet")

        st.markdown("**🌐 DNS & Subdomain Raporu** — DNS kayıtları, güvenlik sorunları, subdomainler")
        if st.button("📥 DNS Raporunu İndir", key="btn_dns"):
            with st.spinner("DNS raporu hazırlanıyor..."):
                _pdf_indir(generate_dns_pdf, f"dns_rapor_{scan_id}.pdf", "⬇️ DNS Raporunu Kaydet")

        st.markdown("---")
        if st.session_state.get("senaryolar"):
            st.subheader("⚠️ Tespit Edilen Olası Saldırı Senaryoları")
            for i, s in enumerate(st.session_state["senaryolar"], 1):
                ai_badge = " 🤖" if s.get("ai") else ""
                with st.expander(f"🎯 Senaryo {i}: {s['tür']}{ai_badge}"):
                    st.error(f"**📌 Kaynak:** {s['kaynak']}")
                    st.warning(f"**📋 Açıklama:** {s['açıklama']}")
                    if s.get("önlem"):
                        st.success(f"**🛡️ Önlem:** {s['önlem']}")
        else:
            st.success("✅ Herhangi bir saldırı senaryosu tespit edilmedi.")


with sekme_dns:
    st.subheader("🌐 DNS Kayıt Analizi")

    if "son_tarama" not in st.session_state:
        st.info("Önce 'Yeni Tarama' sekmesinden bir tarama başlatın.")
    else:
        scan_id = st.session_state["son_tarama"]

        with get_conn() as conn:
            try:
                dns_rows = conn.execute("""
                    SELECT record_type, value, priority, risk_note
                    FROM dns_results WHERE scan_id=?
                    ORDER BY record_type, priority
                """, (scan_id,)).fetchall()
            except Exception:
                dns_rows = []

        if not dns_rows:
            st.info("Bu tarama için DNS verisi bulunamadı.")
        else:
            # Risk notları
            risk_notlari = [r for r in dns_rows if r[0] == "RISK"]
            if risk_notlari:
                st.error(f"⚠️ {len(risk_notlari)} DNS güvenlik sorunu tespit edildi:")
                for r in risk_notlari:
                    st.warning(f"• {r[3]}")
            else:
                st.success("✅ DNS kayıtlarında güvenlik sorunu tespit edilmedi.")

            st.markdown("---")

            for rtype in ("A", "MX", "NS", "TXT"):
                kayitlar = [r for r in dns_rows if r[0] == rtype]
                if kayitlar:
                    with st.expander(f"**{rtype} Kayıtları** ({len(kayitlar)} adet)", expanded=True):
                        for r in kayitlar:
                            oncelik = f" (öncelik: {r[2]})" if r[2] and rtype == "MX" else ""
                            st.code(f"{r[1]}{oncelik}")


with sekme_subdomain:
    st.subheader("🔎 Subdomain Keşfi")

    if "son_tarama" not in st.session_state:
        st.info("Önce 'Yeni Tarama' sekmesinden bir tarama başlatın.")
    else:
        scan_id = st.session_state["son_tarama"]

        with get_conn() as conn:
            try:
                sub_rows = conn.execute("""
                    SELECT subdomain, ip, is_sensitive
                    FROM subdomain_results WHERE scan_id=?
                    ORDER BY is_sensitive DESC, subdomain
                """, (scan_id,)).fetchall()
            except Exception:
                sub_rows = []

        if not sub_rows:
            st.success("✅ Aktif subdomain bulunamadı.")
        else:
            hassas = [r for r in sub_rows if r[2]]
            normal = [r for r in sub_rows if not r[2]]

            m1, m2, m3 = st.columns(3)
            m1.metric("🔎 Toplam Subdomain", len(sub_rows))
            m2.metric("🔴 Hassas Subdomain", len(hassas))
            m3.metric("🟢 Normal Subdomain", len(normal))

            st.markdown("---")

            if hassas:
                st.error(f"⚠️ {len(hassas)} hassas subdomain tespit edildi (admin paneli, dev ortamı vb.):")
                df_hassas = pd.DataFrame(
                    [{"Subdomain": r[0], "IP": r[1], "Durum": "⚠️ Hassas"} for r in hassas]
                )
                st.dataframe(df_hassas, width='stretch', hide_index=True)

            if normal:
                with st.expander(f"Normal Subdomainler ({len(normal)} adet)"):
                    df_normal = pd.DataFrame(
                        [{"Subdomain": r[0], "IP": r[1]} for r in normal]
                    )
                    st.dataframe(df_normal, width='stretch', hide_index=True)



with sekme_ai:
    st.subheader("🤖 Yapay Zeka Analist")

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    if not gemini_key:
        st.warning(
            "⚠️ GEMINI_API_KEY tanımlanmamış.\n\n"
            "1. [Google AI Studio](https://aistudio.google.com/apikey) adresinden ücretsiz API anahtarı alın\n"
            "2. `.env` dosyasına `GEMINI_API_KEY=...` satırını ekleyin\n"
            "3. Uygulamayı yeniden başlatın"
        )
    elif "son_tarama" not in st.session_state:
        st.info("Önce \'Yeni Tarama\' sekmesinden bir tarama başlatın.")
    else:
        scan_id = st.session_state["son_tarama"]

        st.markdown("### 📊 Otomatik Tarama Yorumu")
        if st.button("🔍 AI ile Analiz Et", type="primary", width='stretch'):
            with st.spinner("🤖 Gemini analiz yapıyor..."):
                analiz = analyze_scan(scan_id)
                st.session_state["ai_analiz"] = analiz

        if "ai_analiz" in st.session_state:
            st.markdown(st.session_state["ai_analiz"])

        st.markdown("---")

        st.markdown("### ⚔️ AI Destekli Saldırı Senaryoları")
        if st.button("🎯 AI Senaryoları Üret", width='stretch'):
            with st.spinner("🤖 Senaryolar üretiliyor..."):
                ai_senaryolar = generate_ai_scenarios(scan_id)
                if ai_senaryolar:
                    # Mevcut senaryolara AI senaryolarını ekle
                    mevcut = st.session_state.get("senaryolar", [])
                    ai_yeni = [s for s in ai_senaryolar
                               if s["tür"] not in {m["tür"] for m in mevcut}]
                    st.session_state["senaryolar"] = mevcut + ai_yeni
                    st.success(f"✅ {len(ai_yeni)} yeni AI senaryosu eklendi!")
                    st.info("Senaryoları \'Yeni Tarama\' sekmesinde görüntüleyin.")
                else:
                    st.info("Mevcut bulgular için ek senaryo üretilemedi.")

        st.markdown("---")

        st.markdown("### 💬 Tarama Hakkında Soru Sor")

        if "chat_gecmis" not in st.session_state:
            st.session_state["chat_gecmis"] = []

        for msg in st.session_state["chat_gecmis"]:
            with st.chat_message("user" if msg["rol"] == "kullanici" else "assistant"):
                st.markdown(msg["mesaj"])

        if soru := st.chat_input("Tarama sonucu hakkında bir şey sorun..."):
            st.session_state["chat_gecmis"].append({"rol": "kullanici", "mesaj": soru})
            with st.chat_message("user"):
                st.markdown(soru)

            with st.chat_message("assistant"):
                with st.spinner("🤖 Düşünüyor..."):
                    yanit = ai_chat(
                        scan_id,
                        soru,
                        st.session_state["chat_gecmis"][:-1]
                    )
                st.markdown(yanit)
                st.session_state["chat_gecmis"].append({"rol": "asistan", "mesaj": yanit})

        if st.session_state["chat_gecmis"]:
            if st.button("🗑️ Sohbeti Temizle", width='stretch'):
                st.session_state["chat_gecmis"] = []
                st.rerun()
with sekme_gecmis:
    st.subheader("🗂️ Geçmiş Taramalar")

    with get_conn() as conn:
        rows = conn.execute("""
            SELECT s.id, s.target, s.scan_type, s.created_at,
                   COALESCE(r.total, '-')      AS toplam_puan,
                   COALESCE(r.risk_level, '-') AS risk_seviyesi
            FROM scans s
            LEFT JOIN risk_scores r ON r.scan_id = s.id
                AND r.id = (SELECT MAX(id) FROM risk_scores WHERE scan_id = s.id)
            ORDER BY s.created_at DESC LIMIT 50
        """).fetchall()

    if not rows:
        st.info("Henüz hiç tarama yapılmadı.")
    else:
        with get_conn() as conn:
            toplam = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            kritik = conn.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_level='KRİTİK'").fetchone()[0]
            yuksek = conn.execute("SELECT COUNT(*) FROM risk_scores WHERE risk_level='YÜKSEK'").fetchone()[0]

        m1, m2, m3 = st.columns(3)
        m1.metric("📊 Toplam Tarama", toplam)
        m2.metric("🔴 Kritik Seviye", kritik)
        m3.metric("🟠 Yüksek Seviye", yuksek)

        st.markdown("---")

        seviye_emoji = {"DÜŞÜK":"🟢","ORTA":"🟡","YÜKSEK":"🟠","KRİTİK":"🔴","-":"⚪"}
        df = pd.DataFrame([dict(r) for r in rows])
        df["risk_seviyesi"] = df["risk_seviyesi"].apply(
            lambda x: f"{seviye_emoji.get(x,'⚪')} {x}"
        )
        df.columns = ["ID","Hedef","Tür","Tarih","Toplam Puan","Risk Seviyesi"]
        # Toplam Puan sütununu string'e zorla — '-' değeri Arrow'u bozuyor
        df["Toplam Puan"] = df["Toplam Puan"].astype(str)
        df["ID"] = df["ID"].astype(int)
        st.dataframe(df, width='stretch', hide_index=True)

        st.markdown("---")
        st.markdown("**Geçmiş taramayı görüntüle:**")
        secili_id = st.number_input("Tarama ID", min_value=1,
                                    max_value=int(df["ID"].max()), step=1,
                                    label_visibility="collapsed")
        if st.button("📂 Bu Taramayı Yükle", width='stretch'):
            with get_conn() as conn:
                risk_row = conn.execute("""
                    SELECT score_w, score_s, score_p, score_l, total, risk_level
                    FROM risk_scores WHERE scan_id=? ORDER BY id DESC LIMIT 1
                """, (int(secili_id),)).fetchone()
            if risk_row:
                st.session_state.update({
                    "son_tarama": int(secili_id),
                    "risk": {
                        "breakdown": {"W": risk_row[0], "S": risk_row[1],
                                      "P": risk_row[2], "L": risk_row[3], "D": 0},
                        "total":   risk_row[4],
                        "level":   risk_row[5],
                        "formula": (f"TP = W({risk_row[0]}) + S({risk_row[1]}) + "
                                    f"P({risk_row[2]}) + L({risk_row[3]}) = {risk_row[4]}")
                    },
                    "senaryolar": build_attack_scenarios(int(secili_id)),
                })
                st.success(f"✅ Tarama #{secili_id} yüklendi. 'Yeni Tarama' sekmesine geçin.")
            else:
                st.error(f"ID {secili_id} için risk skoru bulunamadı.")
