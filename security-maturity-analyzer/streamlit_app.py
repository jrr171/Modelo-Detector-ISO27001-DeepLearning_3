"""
Streamlit Web App — Evaluador de Madurez en Seguridad de la Información
Desplegable en Streamlit Cloud desde GitHub.

Título de tesis:
  Modelo de Evaluación De la Madurez en Seguridad de la Información
  Usando Simulador para la Detección de Incumplimiento de Requisitos
  en una Empresa de Inteligencia Comercial en el Sector Comercio Exterior
"""

import sys
import io
import json
import tempfile
import os
from pathlib import Path

import streamlit as st

# ── path fix so sibling modules resolve both locally and on Streamlit Cloud ──
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from analyzer.log_parser       import LogParser
from analyzer.event_classifier import EventClassifier
from analyzer.maturity_scorer  import MaturityScorer
from analyzer.report_generator import export_html, export_json
from rules.iso27001_controls   import MATURITY_LEVELS, ISO27001_DOMAINS

# ────────────────────────────────────────────────────────────────────────────
# Page config
# ────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Evaluador de Madurez ISO 27001",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ────────────────────────────────────────────────────────────────────────────
# Custom CSS
# ────────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  .main-title   { font-size:2rem; font-weight:800; color:#1565C0; }
  .subtitle     { font-size:.95rem; color:#555; margin-bottom:1.5rem; }
  .level-badge  { display:inline-block; padding:6px 18px; border-radius:20px;
                  font-weight:700; font-size:1rem; margin-top:6px; }
  .level-0,.level-1 { background:#FFEBEE; color:#C62828; }
  .level-2,.level-3 { background:#FFF8E1; color:#F57F17; }
  .level-4,.level-5 { background:#E8F5E9; color:#2E7D32; }
  .domain-card  { border-radius:10px; padding:14px 18px; margin-bottom:10px;
                  border-left:5px solid #ccc; background:#fafafa; }
  .finding-item { background:#FFEBEE; border-radius:6px; padding:8px 12px;
                  margin-bottom:6px; color:#B71C1C; }
  .rec-item     { background:#E3F2FD; border-radius:6px; padding:8px 12px;
                  margin-bottom:6px; color:#0D47A1; }
  .metric-box   { text-align:center; padding:14px; border-radius:10px;
                  background:#F5F5F5; }
</style>
""", unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# Sidebar
# ────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://img.icons8.com/color/96/security-shield-green.png", width=72)
    st.markdown("## 🛡 Evaluador ISO 27001")
    st.markdown("""
**Modelo COBIT — 6 Niveles de Madurez**

| Nivel | Nombre |
|-------|--------|
| **0** | Inexistente |
| **1** | Inicial / Ad Hoc |
| **2** | Repetible |
| **3** | Proceso Definido |
| **4** | Administrado |
| **5** | Optimizado |
""")
    st.divider()
    st.caption("Basado en ISO/IEC 27001:2013 · COBIT 5 · NTP ISO/IEC 27001:2008")
    st.caption("Tesis: Modelo de Evaluación de Madurez en Seguridad de la Información")

# ────────────────────────────────────────────────────────────────────────────
# Header
# ────────────────────────────────────────────────────────────────────────────

st.markdown('<div class="main-title">🛡 Evaluador de Madurez en Seguridad de la Información</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Detecta el nivel de madurez ISO 27001 de tu empresa analizando los logs del servidor · Basado en el modelo COBIT (Niveles 0–5)</div>', unsafe_allow_html=True)

# ────────────────────────────────────────────────────────────────────────────
# Input section
# ────────────────────────────────────────────────────────────────────────────

tab_upload, tab_demo, tab_paste = st.tabs(["📁 Subir archivo(s)", "🧪 Usar logs de demo", "📋 Pegar texto"])

entries = []
source_label = ""

# ── Tab 1: File upload ───────────────────────────────────────────────────────
with tab_upload:
    st.markdown("**Formatos soportados:** Apache/Nginx `.log`, Linux syslog/auth.log, Windows Event Log `.csv`, JSON `.json`, comprimidos `.gz`")
    uploaded = st.file_uploader(
        "Arrastra tus archivos de log aquí",
        type=["log", "txt", "csv", "json", "gz"],
        accept_multiple_files=True,
    )
    if uploaded:
        with tempfile.TemporaryDirectory() as tmpdir:
            for f in uploaded:
                dest = Path(tmpdir) / f.name
                dest.write_bytes(f.read())
            parser = LogParser()
            entries = parser.parse_path(tmpdir)
            source_label = f"{len(uploaded)} archivo(s) subido(s)"
            st.success(f"✅ {parser.stats['parsed_ok']:,} eventos leídos de {len(uploaded)} archivo(s)")

# ── Tab 2: Demo logs ─────────────────────────────────────────────────────────
with tab_demo:
    st.info("Se usarán los 4 archivos de muestra incluidos (1 800 eventos realistas: Apache, auth, syslog, Windows CSV).")
    if st.button("▶ Ejecutar análisis con logs de demo", type="primary"):
        samples_dir = ROOT / "samples"
        # Generate if missing
        sample_files = list(samples_dir.glob("sample_*.log")) + list(samples_dir.glob("sample_*.csv"))
        if not sample_files:
            import subprocess, sys
            subprocess.run([sys.executable, str(samples_dir / "generate_samples.py")], check=True)
        parser = LogParser()
        entries = parser.parse_path(str(samples_dir))
        source_label = "Logs de demo"
        st.success(f"✅ {parser.stats['parsed_ok']:,} eventos leídos de los logs de muestra")
        st.session_state["entries"] = entries
        st.session_state["source"]  = source_label

# ── Tab 3: Paste raw text ────────────────────────────────────────────────────
with tab_paste:
    pasted = st.text_area(
        "Pega el contenido de tu log aquí:",
        height=200,
        placeholder="Jan  1 10:00:00 srv sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2\n...",
    )
    if st.button("▶ Analizar texto pegado", type="primary") and pasted.strip():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tf:
            tf.write(pasted)
            tf_path = tf.name
        parser = LogParser()
        entries = parser.parse_path(tf_path)
        os.unlink(tf_path)
        source_label = "Texto pegado"
        st.success(f"✅ {len(entries):,} eventos leídos")

# Restore from session state (demo tab)
if not entries and "entries" in st.session_state:
    entries = st.session_state["entries"]
    source_label = st.session_state.get("source", "")

# ────────────────────────────────────────────────────────────────────────────
# Analysis
# ────────────────────────────────────────────────────────────────────────────

if entries:
    with st.spinner("Clasificando eventos y calculando nivel de madurez…"):
        classifier   = EventClassifier()
        domain_stats = classifier.classify(entries)
        scorer       = MaturityScorer()
        result       = scorer.score(domain_stats)

    lvl      = result.overall_level
    lvl_info = MATURITY_LEVELS[lvl]
    lvl_cls  = f"level-{lvl}"

    st.divider()

    # ── KPI row ──────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("🎯 Score Global", f"{result.overall_score:.1f} / 100")
    with c2:
        st.metric("📊 Nivel de Madurez", f"Nivel {lvl} — {lvl_info['name']}")
    with c3:
        st.metric("📋 Eventos Procesados", f"{result.total_events:,}")
    with c4:
        st.metric("⚠ Eventos de Riesgo", f"{result.total_risk_events:,}")
    with c5:
        st.metric("✅ Dominios Activos", f"{result.total_domains_active} / {len(domain_stats)}")

    # ── Overall level card ────────────────────────────────────────────────────
    st.markdown("---")
    col_gauge, col_desc = st.columns([1, 2])

    with col_gauge:
        st.markdown(f"### Resultado Global")
        st.progress(result.overall_score / 100)
        st.markdown(
            f'<div class="level-badge {lvl_cls}">Nivel {lvl} — {lvl_info["name"]}</div>',
            unsafe_allow_html=True,
        )

        # Level ladder
        st.markdown("#### Escala de Madurez")
        for i in range(5, -1, -1):
            info     = MATURITY_LEVELS[i]
            lo, hi   = info["range"]
            rng      = f"{lo}–{hi}%" if i > 0 else "0%"
            is_curr  = (i == lvl)
            icon     = "◄" if is_curr else " "
            bold     = "**" if is_curr else ""
            st.markdown(f"{bold}Nivel {i} · {rng} · {info['name']}{bold} {icon}")

    with col_desc:
        st.markdown(f"### {lvl_info['name']}")
        st.info(lvl_info["description"])

        # Bar chart per domain
        st.markdown("#### Score por Dominio ISO 27001")
        import json as _json

        chart_data = {
            ds.domain_name: ds.raw_score
            for ds in result.domain_scores.values()
        }

        # Use st.bar_chart
        import pandas as pd
        df_chart = pd.DataFrame.from_dict(
            {"Score": chart_data}
        )
        st.bar_chart(df_chart, height=250, color="#1565C0")

    # ── Domain detail ─────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 📋 Evaluación por Dominio ISO 27001")

    domain_border = {0: "#EF5350", 1: "#EF5350", 2: "#FFA726", 3: "#FFA726", 4: "#66BB6A", 5: "#66BB6A"}

    cols = st.columns(2)
    for idx, (key, ds) in enumerate(
        sorted(result.domain_scores.items(), key=lambda x: x[1].raw_score, reverse=True)
    ):
        with cols[idx % 2]:
            border_color = domain_border.get(ds.level, "#ccc")
            pct = int(ds.raw_score)
            ds_stat = domain_stats[key]
            notes_html = "".join(
                f"<div style='color:#E65100;font-size:.85em;margin-top:4px'>⚠ {n}</div>"
                for n in ds.notes
            )
            st.markdown(f"""
<div class="domain-card" style="border-left-color:{border_color}">
  <strong>{ds.domain_name}</strong>
  <span style="float:right;color:{border_color};font-weight:700">{ds.raw_score:.1f}/100</span><br>
  <small style="color:#777">{ds.clause} · Nivel {ds.level} — {ds.level_name} · Peso {ds.weight:.0%}</small>
  {notes_html}
  <div style="margin-top:8px;background:#eee;border-radius:4px;height:10px;">
    <div style="width:{pct}%;background:{border_color};height:10px;border-radius:4px;"></div>
  </div>
  <small style="color:#999">
    Eventos: {ds_stat.total_events} · Riesgo: {ds_stat.risk_events} · 
    IPs únicas: {len(ds_stat.unique_ips)} · Usuarios: {len(ds_stat.unique_users)}
  </small>
</div>
""", unsafe_allow_html=True)

    # ── Critical findings ──────────────────────────────────────────────────────
    if result.critical_findings:
        st.markdown("---")
        st.markdown("### 🚨 Hallazgos Críticos")
        for f in result.critical_findings:
            st.markdown(f'<div class="finding-item">✖ {f}</div>', unsafe_allow_html=True)

    # ── Recommendations ────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 💡 Recomendaciones")
    for i, rec in enumerate(result.recommendations, 1):
        st.markdown(f'<div class="rec-item">{i}. {rec}</div>', unsafe_allow_html=True)

    # ── Downloads ──────────────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### 💾 Descargar Resultados")
    dl1, dl2 = st.columns(2)

    with dl1:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
            export_html(result, source_label, tf.name)
            html_bytes = Path(tf.name).read_bytes()
            os.unlink(tf.name)
        st.download_button(
            "⬇ Descargar Reporte HTML",
            data=html_bytes,
            file_name="reporte_madurez_iso27001.html",
            mime="text/html",
            use_container_width=True,
        )

    with dl2:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            export_json(result, tf.name)
            json_bytes = Path(tf.name).read_bytes()
            os.unlink(tf.name)
        st.download_button(
            "⬇ Descargar Datos JSON",
            data=json_bytes,
            file_name="resultado_madurez_iso27001.json",
            mime="application/json",
            use_container_width=True,
        )

    st.caption(f"📄 Fuente analizada: {source_label} · Ref: ISO/IEC 27001:2013 · COBIT 5 · NTP ISO/IEC 27001:2008")

else:
    # Welcome screen
    st.markdown("---")
    st.markdown("""
    ### ¿Cómo usar esta herramienta?

    1. **Sube tus logs** en la pestaña *Subir archivo(s)* — acepta Apache, Nginx, Linux syslog/auth.log, Windows Event Log CSV, y JSON.
    2. O presiona **"Ejecutar análisis con logs de demo"** para ver un ejemplo inmediato.
    3. La herramienta clasifica los eventos según los **6 dominios ISO 27001** y calcula tu **nivel de madurez COBIT**.
    4. Descarga el reporte en **HTML o JSON**.

    ---
    **Dominios evaluados:**
    """)
    cols = st.columns(3)
    for i, (key, domain) in enumerate(ISO27001_DOMAINS.items()):
        with cols[i % 3]:
            st.markdown(f"**{domain.id}** — {domain.name}  \n_{domain.description}_")
