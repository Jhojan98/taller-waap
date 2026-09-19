"""Informe v2.0: estructura uniforme por fase + cuestionario. Generador unico."""
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E = os.path.join(BASE, "evidencias")
OUT = os.path.join(BASE, "Informe_Taller_WAAP_Fase0-2.docx")

doc = Document()
normal = doc.styles["Normal"]
normal.font.name = "Calibri"
normal.font.size = Pt(11)


def para(text, bold=False, italic=False):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold = bold
    r.italic = italic
    return p


def h3(text):
    return doc.add_heading(text, level=3)


def code(text):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.font.name = "Consolas"
    r.font.size = Pt(8.5)
    return p


def code_file(rel):
    with open(os.path.join(BASE, rel)) as f:
        code(f.read().rstrip())


def img(rel, caption):
    cap_styles = [s.name for s in doc.styles]
    doc.add_paragraph(caption, style="Caption" if "Caption" in cap_styles else "Normal")
    doc.add_picture(os.path.join(E, rel), width=Inches(6.0))
    doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER


def table(rows):
    t = doc.add_table(rows=len(rows), cols=len(rows[0]))
    t.style = "Table Grid"
    for i, r in enumerate(rows):
        for j, v in enumerate(r):
            c = t.cell(i, j)
            c.text = v
            if i == 0:
                for p in c.paragraphs:
                    for run in p.runs:
                        run.bold = True


def fase(num, titulo):
    doc.add_heading(f"Fase {num} - {titulo}", level=1)


def bloque(objetivo, pasos, resultado):
    h3("Objetivo")
    para(objetivo)
    h3("Que se hizo (paso a paso)")
    code(pasos)
    h3("Resultado y lectura")
    para(resultado)


# ================= PORTADA + RESUMEN =================
t = doc.add_paragraph()
t.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = t.add_run("Taller WAAP con IA/ML, RASP y DevSecOps\nInforme de laboratorio - Fases 0 a 7 (v2.0)")
r.bold = True
r.font.size = Pt(16)
para("Universidad Distrital FJDC - Mecanismos de Seguridad Informatica. Prof. Octavio J. Salcedo Parra.",
     italic=True)
doc.add_heading("Resumen ejecutivo", level=1)
para("Se implemento un prototipo WAAP completo: Juice Shop 20.2.0 tras ModSecurity CRS 3.3.10 "
     "(PL1), detector de anomalias IsolationForest, RASP real sobre fork de Juice Shop y pipeline "
     "DevSecOps en verde. Hallazgos centrales: (1) el CRS frena el ataque automatizado pero deja "
     "pasar payloads fragmentados; (2) el ML detecta variantes a cambio de falsos positivos "
     "(no sirve como gate duro); (3) el RASP captura con contexto de ejecucion lo que evade "
     "firmas, con overhead despreciable (+0.1 micro-s/req). La mejor cobertura es CRS+RASP con "
     "ML como senal de apoyo. Este documento (v2.0) clarifica el informe literal v1.0 y responde "
     "el cuestionario final con datos del laboratorio.")

# ================= FASE 0 =================
fase(0, "Preparacion del entorno")
bloque(
    "Levantar la infraestructura base del laboratorio (PDF p.9).",
    "cd taller-waap\n"
    "cp .env.example .env   # JUICE_PORT=3000, WAAP_PORT=8080, PARANOIA=1\n"
    "docker compose pull && docker compose up -d && docker compose ps\n"
    "curl -i http://localhost:8080   # 200 OK, Server: nginx (proxy WAAP)",
    "Contenedores Up (waap-proxy healthy). Nota operativa: hizo falta anadir el usuario al grupo "
    "docker (permiso denegado en /var/run/docker.sock). En Fase 4 el backend paso a la imagen "
    "local juice-shop:rasp-lab. Evidencia: Fig. 1 y Anexo B.")
code_file("evidencias/06-terminal.txt")
img("01-home-waap.png", "Figura 1. Juice Shop servido a traves del proxy WAAP (:8080).")

# ================= FASE 1 =================
fase(1, "Aplicacion objetivo vulnerable")
bloque(
    "Contar con un blanco controlado con vulnerabilidades documentadas (PDF p.10).",
    "curl -s http://localhost:8080/rest/admin/application-version  # version 20.2.0\n"
    "curl -s 'http://localhost:8080/rest/products/search?q=apple'  # JSON success via WAAP\n"
    "Navegador: http://localhost:8080/#/score-board (retos por categoria OWASP)",
    "Juice Shop 20.2.0 operativo tras el WAAP. Linea base de 5 vulnerabilidades (Tabla 1) usada "
    "en todas las fases. Evidencias: Fig. 2 (Score Board) y Fig. 3 (trafico normal).")
para("Tabla 1. Linea base de vulnerabilidades (entregable Fase 1).")
table([
    ("#", "Vulnerabilidad", "OWASP Top 10", "Endpoint"),
    ("1", "Inyeccion SQL en login", "A03 Injection", "POST /rest/user/login"),
    ("2", "XSS reflejado en busqueda", "A03 Injection", "GET /rest/products/search?q="),
    ("3", "IDOR en cesta/pedidos", "A01 Broken Access Control", "/rest/basket/:id"),
    ("4", "Exposicion de hash de password", "A07 / Sensitive Data", "GET /rest/user/whoami, /api/Users"),
    ("5", "Path traversal / LFI", "A01 / A03", "GET ...q=../../etc/passwd"),
])
img("02-scoreboard.png", "Figura 2. Score Board (categorias OWASP).")
img("03-search-normal.png", "Figura 3. Trafico normal via WAAP (200).")

# ================= FASE 2 =================
fase(2, "Capa base WAF/WAAP con CRS (PL1)")
bloque(
    "Primera linea de defensa con OWASP CRS: un bloqueo y una evasion evidenciados (PDF p.10).",
    "# Paranoia PL1: PARANOIA=1, BLOCKING_PARANOIA=1, BACKEND=http://juice-shop:3000\n"
    "curl -i --get --data-urlencode \"q=' OR '1'='1\" \\\n"
    "  http://localhost:8080/rest/products/search   # -> 403 Forbidden\n"
    "curl -i \"http://localhost:8080/rest/products/search?q='%20&x=OR%201=1\"  # -> 200\n"
    "docker compose logs waap-proxy | grep -E '942100|949110'  # (el audit log sale por docker logs)",
    "SQLi clasico/encoded/comentarios/UNION/XSS/traversal -> 403 (regla 942100 libinjection + "
    "949110). Solo el fragmentado q=' & x=OR 1=1 -> 200: el CRS evalua cada parametro por "
    "separado. Evidencias: Fig. 4 (bloqueo) y Fig. 5 (evasion, base de Fase 3).")
img("04-bloqueo-403.png", "Figura 4. Bloqueo CRS: SQLi clasico -> 403 (nginx).")
img("05-evasion-200.png", "Figura 5. Evasion fragmentada -> 200 (pasa el CRS).")

# ================= FASE 3 =================
fase(3, "Modulo de deteccion basado en IA/ML")
bloque(
    "Modelo de anomalias entrenado solo con trafico normal, capaz de senalar variantes que "
    "evadieron firmas (PDF p.11-12).",
    "python3 -m pip install --user scikit-learn pandas numpy joblib\n"
    "GEN_N=120 PACE=humano python3 waap/ml/gen_traffic.py  # 120 reqs, ~15 min via WAAP\n"
    "python3 waap/ml/extract_features.py  # 6 features literales del PDF\n"
    "python3 waap/ml/train_model.py       # IsolationForest(200, 0.02) -> model.pkl\n"
    "python3 waap/ml/evaluate.py          # matriz 10 + 2 umbrales + rafaga bot",
    "Leccion metodologica: el primer dataset a ritmo maquina contamino req_per_minute; se "
    "regenero a ritmo humano (rpm 8+-1). Umbral -0.05: 2/5 ataques, 2 FP. Umbral 0.0: 5/5 "
    "ataques, 4 FP. La rafaga no cruza el umbral (limitacion de IsolationForest verificada). "
    "Conclusion: el ML es senal de apoyo, no gate. Detalles y numeros abajo.")
h3("Evidencias")
para("Entrenamiento:"); code_file("evidencias/fase3/01-train.txt")
para("Matriz de 10 peticiones:"); code_file("evidencias/fase3/02-matriz-10.txt")
para("Umbrales:"); code_file("evidencias/fase3/03-umbrales.txt")

# ================= FASE 4 =================
fase(4, "Integracion RASP sobre fork de Juice Shop")
bloque(
    "Proteccion en tiempo de ejecucion con contexto real: interceptar la operacion sensible "
    "aunque el payload haya superado el perimetro (PDF p.13).",
    "gh repo fork juice-shop/juice-shop; clone --depth 1 en ~/juice-shop-rasp (rama rasp-lab)\n"
    "sudo npm i -g npm@11 (npm 10 falla con bug arborist); npm install + build frontend/server\n"
    "Nuevo lib/raspGuard.ts (mismo patron del PDF) + app.use() en server.ts\n"
    "Guard sobre la query cruda real de routes/login.ts:34 -> 403 antes de Sequelize\n"
    "PORT=3001 RASP_ENABLED=1 npm start; docker build -t juice-shop:rasp-lab (compose)",
    "Sin RASP el SQLi clasico devuelve el JWT del administrador (takeover total); con RASP, 403 "
    "+ log antes de ejecutar. Tambien cae UNION y fragmentado. Hueco honesto: la forma string "
    "' OR '1'='1 evade el regex literal (fix propuesto). Overhead: +0.1 micro-s/req "
    "(despreciable). Prototipo previo conservado en app/rasp-demo/; referencia Flask en "
    "app/rasp_agent.py.")
h3("Evidencias")
para("Bateria con/sin RASP:"); code_file("evidencias/fase4-real.txt")
para("Stack combinado WAAP+RASP:"); code_file("evidencias/fase4-combinado.txt")

# ================= MATRIZ =================
doc.add_heading("Matriz comparativa por capas (Fase 6, resultado final)", level=1)
para("Tabla 2. Bateria de 9 tecnicas x 3 capas (script waap/ml/bateria_fase6.py; atribucion "
     "CRS-vs-RASP por cuerpo de respuesta).")
table([
    ("Payload / tecnica", "Reglas CRS PL1", "IA/ML (umbral 0.0)", "RASP"),
    ("SQLi clasico", "BLOQUEA 403", "Detecta", "EVADE en search (hueco); BLOQUEA en login"),
    ("SQLi encoded", "BLOQUEA 403", "Detecta", "EVADE en search; BLOQUEA patron OR 1=1"),
    ("SQLi fragmentado q=' & x=OR 1=1", "EVADE 200", "No detecta", "BLOQUEA 403"),
    ("SQLi UNION / comentarios", "BLOQUEA (compacto)", "Detecta", "BLOQUEA 403"),
    ("XSS basico y encoded", "BLOQUEA 403", "Detecta", "N/A (alcance SQL)"),
    ("Traversal", "BLOQUEA 403", "Detecta", "N/A (alcance SQL)"),
    ("Rafaga bot", "N/A", "No cruza umbral", "N/A"),
])

# ================= FASE 5 =================
fase(5, "Pipeline DevSecOps")
bloque(
    "Gate CI/CD con SAST, SCA, contenedor, IaC y DAST; despliegue solo en verde (PDF p.14).",
    "Workflow: Semgrep p/owasp-top-ten; pip-audit (waap/ml/requirements.txt, nuevo);\n"
    "docker build app/; Trivy CRITICAL,HIGH exit 1; Checkov; ZAP baseline; deploy si success.\n"
    "Replicado local + ejercicio: eval() inyectado -> rojo en SAST -> revert -> verde.",
    "El gate trabajo de verdad: Dockerfile sin USER, workflow sin permissions, 67 CVE en base "
    "Debian y 11 en el npm de la imagen -> Alpine + multistage + sin npm en runtime = 0 "
    "findings en las 4 herramientas. deploy_waap_rules.sh: OK (200/403). Evidencias: "
    "evidencias/fase5/.")

# ================= FASE 6 =================
fase(6, "Pruebas de efectividad y evasion")
bloque(
    "Evaluar cada capa individual y combinada con herramientas estandar (PDF p.15).",
    "python3 waap/ml/bateria_fase6.py  # -> matriz.csv (Tabla 2)\n"
    "sqlmap vs WAAP y vs directo (search + login); ZAP baseline vs :8080",
    "sqlmap: 42x403 via WAAP y 14x403+8x500 directo ('not injectable' en ambos). ZAP: 0 FAIL, "
    "59 PASS. Conclusion (media pagina en evidencias/fase6/analisis.md): mejor combinacion "
    "CRS+RASP con ML como senal; residuo: string-form (fix de patron) y rafagas (regla de tasa).")
para("Analisis completo:"); code_file("evidencias/fase6/analisis.md")

# ================= FASE 7 =================
fase(7, "Observabilidad y metricas")
bloque(
    "Visibilidad centralizada y numeros para tuning (PDF p.16).",
    "python3 waap/ml/metricas_fase7.py  # logs/eventos.jsonl + TPR/FPR/FNR + MTTD",
    "CRS: TPR 78% FPR 0%. ML@0.0: TPR 100% FPR 80% (senal, no gate). RASP-SQL: TPR 67% FPR 0%. "
    "MTTD ~60-150 ms por capa. Tuning: CRS en PL1; ML solo como senal + regla hibrida de tasa; "
    "RASP con patron ampliado. Detalles:")
code_file("evidencias/fase7/metricas.txt")

# ================= CUESTIONARIO =================
doc.add_heading("Cuestionario de analisis final (PDF Seccion 8)", level=1)
qs = [
    ("Q1. Motor de reglas insuficiente pero IA/ML si detecta.",
     "El SQLi con comentarios y espacios ('/ **/OR/**/1=1--): la firma exacta del CRS no lo "
     "casa (403 solo del RASP por el '--'), mientras el ML lo marca anomalo por longitud+entropia "
     "atipicas. La firma busca cadenas conocidas; el modelo mide distancia estadistica."),
    ("Q2. Falso positivo del ML sobre trafico legitimo.",
     "El login valido y el home ('/') se marcaron anomalos: el login por body_length alto del "
     "JSON de credenciales y home por url_length=1 (extremo de la distribucion). Feature "
     "responsable principal: longitudes fuera del centro aprendido + entropia."),
    ("Q3. Por que el RASP detecto lo que reglas y ML no.",
     "Porque opera sobre la consulta final concatenada (contexto de ejecucion), no sobre la "
     "peticion HTTP. El fragmentado q=' & x=OR 1=1 es inocuo por partes (evade CRS y es "
     "estadisticamente normal para el ML) pero al concatenarse forma ' OR 1=1--, que el guard "
     "ve y bloquea con 403."),
    ("Q4. WAAP centralizado vs RASP en 15 microservicios.",
     "WAAP centralizado como base (un solo punto de tuning, cubre OWASP Top 10 generico) + "
     "RASP solo en servicios criticos con datos sensibles (auth, pagos), por el costo operativo "
     "de mantener 15 agentes (versionado por lenguaje, overhead de despliegue, logs)."),
    ("Q5. Que etapa detuvo la vulnerabilidad inyectada.",
     "SAST/Semgrep detuvo el eval() inyectado (code-string-concat, blocking). Sin esa etapa, "
     "el codigo habria llegado a la imagen y solo ZAP/Trivy tardios (o produccion) lo habrian "
     "visto, con costo mayor."),
    ("Q6. Mapeo MITRE ATT&CK / API Top 10.",
     "T1190 (Exploit Public-Facing Application): SQLi en /rest/user/login y XSS en "
     "/rest/products/search. API BOLA/IDOR: acceso a /rest/basket/:id ajeno."),
    ("Q7. Mejora contra falsos positivos del ML sin perder deteccion.",
     "Regla hibrida: score ML + tasa (req_per_minute con umbral duro) + whitelist por ruta "
     "(p. ej. login/home con umbral propio). La tasa captura rafagas que el IsolationForest no "
     "ordena; el whitelist baja el FPR sin tocar la deteccion de ataques."),
    ("Q8. Riesgo de reentrenar con trafico de produccion sin validar.",
     "Envenenamiento: ataques de bajo volumen se vuelven 'normales' (lo vivimos al reves: el "
     "dataset rapido normalizo rpm=200). Se requiere curaduria + ventana validada + "
     "comparacion contra baseline antes de promover el modelo."),
]
for title, body in qs:
    h3(title)
    para(body)

# ================= ANEXO A (unico) =================
doc.add_heading("Anexo A - Paso a paso reproducible (Fases 0-7)", level=1)
code(
    "# 0. Requisitos: Ubuntu 22.04, Docker+Compose, Python 3.10, Node 22, LibreOffice.\n"
    "#    sudo usermod -aG docker $USER (re-login).\n"
    "git clone git@github.com:Jhojan98/taller-waap.git && cd taller-waap\n"
    "git checkout lab/fases-0-4   # o main tras el merge\n"
    "# FASE 0: cp .env.example .env; docker compose pull/up; curl :8080\n"
    "# FASE 1: version, search?q=apple, /#/score-board\n"
    "# FASE 2: SQLi clasico -> 403; fragmentado -> 200; logs | grep 942100|949110\n"
    "# FASE 3: pip install sklearn pandas numpy joblib; GEN_N=120 PACE=humano gen_traffic;\n"
    "#   extract_features; train_model; evaluate\n"
    "# FASE 4: fork juice-shop (rama rasp-lab) + lib/raspGuard.ts + hooks;\n"
    "#   PORT=3001 npm start; docker build -t juice-shop:rasp-lab; compose + verificar\n"
    "# FASE 5: semgrep; pip-audit; docker build ./app; trivy; checkov; deploy script\n"
    "# FASE 6: bateria_fase6.py; sqlmap (search+login); zap-baseline.py\n"
    "# FASE 7: metricas_fase7.py\n"
    "# INFORME: python3 build_informe_v2.py; soffice --headless --convert-to pdf ...docx")

doc.add_heading("Anexo B - Salidas de terminal (Fases 0-2)", level=1)
code_file("evidencias/06-terminal.txt")

doc.save(OUT)
print("OK:", OUT, os.path.getsize(OUT), "bytes")


def _head_idx(body_elems, sub):
    for i, el in enumerate(body_elems):
        if el.tag.endswith('}p'):
            st = el.xpath('./w:pPr/w:pStyle/@w:val')
            if st and st[0].startswith('Heading') and sub in ''.join(el.itertext()):
                return i
    raise KeyError(sub)


# La matriz se genera tras Fase 4 pero pertenece a Fase 6: moverla a su sitio.
_doc2 = Document(OUT)
_body = _doc2.element.body
_elems = list(_body)
_mov = _elems[_head_idx(_elems, 'Matriz comparativa'):_head_idx(_elems, 'Fase 5 -')]
for _el in _mov:
    _body.remove(_el)
_elems2 = list(_body)
_iF7 = next(i for i, el in enumerate(_elems2)
            if el.tag.endswith('}p') and 'Fase 7 -' in ''.join(el.itertext()))
for _el in reversed(_mov):
    _body.insert(_iF7, _el)
_doc2.save(OUT)
print("OK matriz reubicada:", OUT)
