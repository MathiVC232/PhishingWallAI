import streamlit as st
from datetime import datetime
from urllib.parse import urlparse
import time
import sqlite3
import pandas as pd
import re
from difflib import SequenceMatcher

st.set_page_config(
    page_title="PhishingWall AI",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# BASE DE DATOS SQLITE
# =========================

conn = sqlite3.connect("phishingwall.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS historial (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo_analisis TEXT,
    contenido TEXT,
    url TEXT,
    dominio TEXT,
    entidad TEXT,
    riesgo INTEGER,
    estado TEXT,
    reputacion TEXT,
    similitud INTEGER,
    fecha TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS amenazas_reportadas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contenido TEXT,
    url TEXT,
    dominio TEXT,
    entidad TEXT,
    riesgo INTEGER,
    motivo TEXT,
    fecha TEXT
)
""")

conn.commit()

# =========================
# DATOS DEL SISTEMA
# =========================

bancos_oficiales = {
    "Banco Pichincha": ["pichincha.com"],
    "Banco Guayaquil": ["bancoguayaquil.com"],
    "Produbanco": ["produbanco.com"],
    "Banco del Pacífico": ["bancodelpacifico.com"],
    "PayPal": ["paypal.com"],
    "Chase Bank": ["chase.com"],
    "Bank of America": ["bankofamerica.com"],
    "BBVA": ["bbva.com"],
    "Santander": ["santander.com"],
    "HSBC": ["hsbc.com"]
}

palabras_sospechosas = [
    "verificar", "verifique", "bloqueo", "bloqueada", "premio", "bono",
    "actualizar", "seguridad", "login", "cuenta", "clave", "validar",
    "urgente", "regalo", "confirmar", "acceso", "suspendida", "reactivar"
]

dominios_raros = [".xyz", ".top", ".click", ".info", ".site", ".online", ".shop", ".live"]

amenazas_recientes = [
    "paypal-verificacion.xyz",
    "chase-security-login.top",
    "pichincha-bono.site",
    "bbva-premio.click",
    "bancoguayaquil-validacion.info"
]

# =========================
# FUNCIONES SQLITE
# =========================

def guardar_analisis(tipo_analisis, contenido, url, dominio, entidad, riesgo, estado, reputacion, similitud):
    cursor.execute("""
    INSERT INTO historial (
        tipo_analisis, contenido, url, dominio, entidad, riesgo, estado,
        reputacion, similitud, fecha
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        tipo_analisis,
        contenido,
        url,
        dominio,
        entidad,
        riesgo,
        estado,
        reputacion,
        similitud,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()

def guardar_reporte(contenido, url, dominio, entidad, riesgo, motivo):
    cursor.execute("""
    INSERT INTO amenazas_reportadas (
        contenido, url, dominio, entidad, riesgo, motivo, fecha
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        contenido,
        url,
        dominio,
        entidad,
        riesgo,
        motivo,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()

def cargar_historial():
    return pd.read_sql_query(
        "SELECT fecha, tipo_analisis, contenido, url, dominio, entidad, riesgo, estado, reputacion, similitud FROM historial ORDER BY id DESC",
        conn
    )

def cargar_reportes():
    return pd.read_sql_query(
        "SELECT fecha, contenido, url, dominio, entidad, riesgo, motivo FROM amenazas_reportadas ORDER BY id DESC",
        conn
    )

# =========================
# FUNCIONES DE ANÁLISIS
# =========================

def extraer_links(texto):
    return re.findall(r'https?://[^\s]+', texto)

def calcular_similitud(a, b):
    return int(SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100)

def reputacion_dominio(riesgo):
    if riesgo <= 30:
        return "🟢 Verificada"
    elif riesgo <= 60:
        return "🟡 Dudosa"
    else:
        return "🔴 Mala"

def analizar_url(url):
    riesgo = 0
    razones = []
    entidad = "No detectada"
    tipo = "Análisis general"
    similitud_max = 0

    url_lower = url.lower()
    dominio = urlparse(url).netloc.replace("www.", "")

    if dominio == "":
        dominio = "No válido"
        riesgo += 30
        razones.append("La URL no tiene un dominio válido.")

    if not url_lower.startswith("https://"):
        riesgo += 20
        razones.append("El enlace no usa HTTPS seguro.")

    for palabra in palabras_sospechosas:
        if palabra in url_lower:
            riesgo += 10
            razones.append(f"Contiene palabra sospechosa: '{palabra}'.")

    for raro in dominios_raros:
        if raro in dominio:
            riesgo += 20
            razones.append(f"Usa un dominio poco confiable: '{raro}'.")

    for banco, oficiales in bancos_oficiales.items():
        nombre_simple = banco.lower().replace("banco", "").replace("bank", "").replace(" ", "")

        for oficial in oficiales:
            similitud = calcular_similitud(dominio, oficial)
            similitud_max = max(similitud_max, similitud)

            if oficial in dominio:
                entidad = banco
                tipo = "Sitio oficial identificado"
                riesgo = max(riesgo - 20, 0)
                razones.append(f"Dominio oficial detectado para {banco}.")
                return riesgo, razones, entidad, dominio, tipo, similitud_max

        url_simple = url_lower.replace("-", "").replace("_", "").replace(".", "")

        if nombre_simple in url_simple:
            entidad = banco
            tipo = "Posible clon financiero"
            riesgo += 35
            razones.append(f"El enlace intenta usar el nombre de {banco} sin ser dominio oficial.")

    if len(url) > 75:
        riesgo += 10
        razones.append("La URL es demasiado larga.")

    if "-" in dominio:
        riesgo += 10
        razones.append("El dominio contiene guiones, común en sitios falsos.")

    riesgo = min(riesgo, 100)
    return riesgo, razones, entidad, dominio, tipo, similitud_max

def analizar_sms(texto):
    links = extraer_links(texto)
    riesgo_total = 0
    razones_total = []
    entidad = "No detectada"
    dominio = "No detectado"
    tipo = "SMS sospechoso"
    url_detectada = "Sin enlace"
    similitud = 0

    texto_lower = texto.lower()

    for palabra in palabras_sospechosas:
        if palabra in texto_lower:
            riesgo_total += 8
            razones_total.append(f"El SMS contiene palabra sospechosa: '{palabra}'.")

    if not links:
        riesgo_total += 10
        razones_total.append("El SMS no contiene enlace, pero utiliza lenguaje que puede ser engañoso.")
    else:
        url_detectada = links[0]
        riesgo, razones, entidad, dominio, tipo_url, similitud = analizar_url(url_detectada)
        riesgo_total += riesgo
        razones_total.extend(razones)

        if riesgo > 60:
            tipo = "Posible clon financiero enviado por SMS"
        else:
            tipo = "SMS con enlace analizado"

    riesgo_total = min(riesgo_total, 100)
    return riesgo_total, razones_total, entidad, dominio, tipo, url_detectada, links, similitud

def obtener_estado(riesgo):
    if riesgo <= 30:
        return "✅ Seguro", "El contenido parece confiable."
    elif riesgo <= 60:
        return "⚠️ Sospechoso", "Revisa cuidadosamente antes de ingresar información personal."
    else:
        return "🚨 Alto riesgo", "No abras el enlace ni ingreses datos bancarios."

# =========================
# DISEÑO VISUAL
# =========================

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #020617, #0f172a, #111827);
    color: white;
}

.block-container {
    padding-top: 2rem;
}

.title {
    font-size: 44px;
    font-weight: 900;
    color: #38bdf8;
}

.subtitle {
    color: #cbd5e1;
    font-size: 18px;
}

.card-alert {
    padding: 20px;
    border-radius: 18px;
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid #334155;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="title">🛡️ PhishingWall AI</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Protección inteligente contra phishing, SMS fraudulentos y clones financieros</div>', unsafe_allow_html=True)

st.divider()

# =========================
# DASHBOARD
# =========================

df_historial = cargar_historial()

d1, d2, d3, d4 = st.columns(4)

with d1:
    st.metric("Análisis realizados", len(df_historial))

with d2:
    st.metric("Amenazas detectadas", len(df_historial[df_historial["riesgo"] > 60]) if not df_historial.empty else 0)

with d3:
    st.metric("Sospechosos", len(df_historial[(df_historial["riesgo"] > 30) & (df_historial["riesgo"] <= 60)]) if not df_historial.empty else 0)

with d4:
    st.metric("Seguros", len(df_historial[df_historial["riesgo"] <= 30]) if not df_historial.empty else 0)

st.divider()

modo_proteccion = st.toggle("🟢 Protección en tiempo real simulada", value=True)

if modo_proteccion:
    st.success("Live Protection activa: PhishingWall está monitoreando amenazas simuladas.")
else:
    st.warning("Live Protection desactivada.")

st.divider()

# =========================
# PESTAÑAS
# =========================

tab1, tab2, tab3, tab4 = st.tabs([
    "🔗 Analizador URL",
    "📩 Analizador SMS",
    "📊 Dashboard",
    "🏦 Modo empresarial"
])

# =========================
# TAB URL
# =========================

with tab1:
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("### 🔗 Analizador de enlaces")
        url = st.text_input(
            "Pega un enlace sospechoso:",
            placeholder="Ejemplo: http://pichincha-verificar-bono.xyz/login"
        )

        analizar = st.button("🚨 Analizar enlace", use_container_width=True)

    with col2:
        st.markdown("### 🧠 Motor IA")
        st.info("Analiza dominio, HTTPS, palabras sospechosas, similitud bancaria y patrones de clonación financiera.")

    if analizar:
        if url.strip() == "":
            st.warning("Ingresa primero un enlace.")
        else:
            with st.spinner("🧠 Escaneando dominio..."):
                time.sleep(1)
            with st.spinner("🔍 Comparando con bancos oficiales..."):
                time.sleep(1)
            with st.spinner("⚡ Calculando riesgo..."):
                time.sleep(1)

            riesgo, razones, entidad, dominio, tipo, similitud = analizar_url(url)
            estado, mensaje = obtener_estado(riesgo)
            trust_score = 100 - riesgo
            reputacion = reputacion_dominio(riesgo)
            confianza = min(95, riesgo + 20)

            if riesgo <= 30:
                st.success(f"{estado} — Riesgo: {riesgo}/100")
            elif riesgo <= 60:
                st.warning(f"{estado} — Riesgo: {riesgo}/100")
            else:
                st.error(f"{estado} — Riesgo: {riesgo}/100")

            guardar_analisis("URL", url, url, dominio, entidad, riesgo, estado, reputacion, similitud)

            st.markdown("### 🚨 Vista de amenaza detectada")
            st.code(f"""
Entidad detectada : {entidad}
Dominio analizado : {dominio}
Tipo de amenaza   : {tipo}
Riesgo            : {riesgo}/100
Reputación        : {reputacion}
Similitud bancaria: {similitud}%
""")

            st.markdown("### 🛡️ Trust Score")
            st.progress(trust_score)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Trust Score", f"{trust_score}/100")
            c2.metric("Riesgo", f"{riesgo}/100")
            c3.metric("Confianza IA", f"{confianza}%")
            c4.metric("Similitud bancaria", f"{similitud}%")

            if entidad != "No detectada" and entidad in bancos_oficiales:
                oficial = bancos_oficiales[entidad][0]
                st.markdown("### 🔎 Comparación de dominios")
                st.code(f"""
Dominio analizado : {dominio}
Dominio oficial   : {oficial}
""")

            st.markdown("### 📌 Detalles del análisis")
            for r in razones:
                st.write("•", r)

            st.markdown("### 💡 Recomendación")
            st.info(mensaje)

            if st.button("📢 Reportar amenaza URL"):
                guardar_reporte(url, url, dominio, entidad, riesgo, "Usuario reportó esta URL como amenaza.")
                st.success("La amenaza fue reportada correctamente.")

# =========================
# TAB SMS
# =========================

with tab2:
    st.markdown("### 📩 PhishingWall SMS Shield")
    sms = st.text_area(
        "Pega aquí el SMS sospechoso:",
        height=160,
        placeholder="Ejemplo: Banco Pichincha informa que su cuenta fue bloqueada. Verifique aquí: http://pichincha-bono-seguridad.xyz/login"
    )

    analizar_sms_btn = st.button("📲 Analizar SMS", use_container_width=True)

    if analizar_sms_btn:
        if sms.strip() == "":
            st.warning("Ingresa primero un SMS.")
        else:
            with st.spinner("📩 Extrayendo enlaces del SMS..."):
                time.sleep(1)
            with st.spinner("🧠 Detectando posible clon financiero..."):
                time.sleep(1)
            with st.spinner("🚨 Calculando riesgo del mensaje..."):
                time.sleep(1)

            riesgo, razones, entidad, dominio, tipo, url_detectada, links, similitud = analizar_sms(sms)
            estado, mensaje = obtener_estado(riesgo)
            trust_score = 100 - riesgo
            reputacion = reputacion_dominio(riesgo)
            confianza = min(95, riesgo + 20)

            if riesgo <= 30:
                st.success(f"{estado} — Riesgo: {riesgo}/100")
            elif riesgo <= 60:
                st.warning(f"{estado} — Riesgo: {riesgo}/100")
            else:
                st.error(f"🚨 Posible clon financiero por SMS — Riesgo: {riesgo}/100")

            guardar_analisis("SMS", sms, url_detectada, dominio, entidad, riesgo, estado, reputacion, similitud)

            st.markdown("### 🚨 Resumen del SMS")
            st.code(f"""
Entidad detectada : {entidad}
URL detectada     : {url_detectada}
Dominio analizado : {dominio}
Tipo de amenaza   : {tipo}
Riesgo            : {riesgo}/100
Reputación        : {reputacion}
Similitud bancaria: {similitud}%
""")

            st.markdown("### 🔗 Links detectados")
            if links:
                for link in links:
                    st.code(link)
            else:
                st.write("No se detectaron links.")

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Trust Score", f"{trust_score}/100")
            c2.metric("Riesgo", f"{riesgo}/100")
            c3.metric("Confianza IA", f"{confianza}%")
            c4.metric("Reputación", reputacion)

            st.markdown("### 📌 Razones detectadas")
            for r in razones:
                st.write("•", r)

            st.markdown("### 💡 Recomendación")
            st.info(mensaje)

            if st.button("📢 Reportar SMS sospechoso"):
                guardar_reporte(sms, url_detectada, dominio, entidad, riesgo, "Usuario reportó este SMS como amenaza.")
                st.success("El SMS fue reportado correctamente.")

# =========================
# TAB DASHBOARD
# =========================

with tab3:
    st.markdown("### 📊 Historial guardado en SQLite")
    df_historial = cargar_historial()

    if not df_historial.empty:
        st.dataframe(df_historial, use_container_width=True)

        st.markdown("### 📈 Amenazas por entidad")
        entidad_counts = df_historial["entidad"].value_counts()
        st.bar_chart(entidad_counts)

        st.markdown("### 📉 Riesgo promedio por tipo de análisis")
        riesgo_tipo = df_historial.groupby("tipo_analisis")["riesgo"].mean()
        st.bar_chart(riesgo_tipo)

    else:
        st.write("Aún no hay análisis realizados.")

    st.divider()

    col3, col4 = st.columns(2)

    with col3:
        st.markdown("### 🚨 Amenazas recientes detectadas")
        for amenaza in amenazas_recientes:
            st.error(amenaza)

    with col4:
        st.markdown("### 🎓 Consejos de seguridad")
        st.info("""
• Nunca ingreses claves desde enlaces enviados por SMS.

• Verifica siempre el dominio oficial del banco.

• Desconfía de premios, bonos o bloqueos urgentes.

• Usa autenticación en dos pasos siempre que sea posible.
""")

    st.divider()

    st.markdown("### 📢 Amenazas reportadas por usuarios")
    df_reportes = cargar_reportes()

    if not df_reportes.empty:
        st.dataframe(df_reportes, use_container_width=True)
    else:
        st.write("Aún no hay amenazas reportadas.")

# =========================
# TAB EMPRESARIAL
# =========================

with tab4:
    st.markdown("### 🏦 PhishingWall Enterprise")
    st.write("""
PhishingWall también puede convertirse en una plataforma empresarial para bancos,
cooperativas, fintechs y universidades.

Funciones empresariales:
- monitoreo de dominios falsos,
- alertas preventivas,
- reportes de amenazas,
- protección SMS,
- API de reputación de enlaces,
- dashboard de ciberseguridad financiera.
""")

    e1, e2, e3 = st.columns(3)
    e1.metric("Plan Básico", "$0", "Análisis limitado")
    e2.metric("Plan Premium", "$4.99/mes", "Protección personal")
    e3.metric("Plan Enterprise", "Licencia anual", "Bancos y empresas")

st.divider()

st.caption("PhishingWall AI © 2026 — Cybersecurity Intelligence Platform")