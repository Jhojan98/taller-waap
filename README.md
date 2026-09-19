# taller-waap — Prototipo WAAP (Fases 0–7)

WAAP académico: **OWASP Juice Shop 20.2.0** tras **ModSecurity CRS 3.3.10 (PL1)**,
detector de anomalías **IsolationForest**, **RASP real** sobre fork de Juice Shop
y **pipeline DevSecOps** en verde. Informe completo (DOCX/PDF) en la raíz y en
[Releases](../../releases) (`v1.0` literal PDF, `v2.0` clarificado + cuestionario).

Requisitos: Ubuntu 22.04, Docker + Compose, Python 3.10, Node 22, LibreOffice.
Usuario en grupo docker: `sudo usermod -aG docker $USER` (re-login).

## Fase 0 — Entorno

```bash
cp .env.example .env   # JUICE_PORT=3000, WAAP_PORT=8080, PARANOIA=1
docker compose pull && docker compose up -d && docker compose ps
curl -i http://localhost:8080   # 200 OK, Server: nginx (proxy WAAP)
```

## Fase 1 — App vulnerable

```bash
curl -s http://localhost:8080/rest/admin/application-version  # 20.2.0
curl -s 'http://localhost:8080/rest/products/search?q=apple'  # JSON vía WAAP
# Navegador: http://localhost:8080/#/score-board
```

Línea base: SQLi en `POST /rest/user/login`, XSS en `GET /rest/products/search`,
IDOR en `/rest/basket/:id`, hash expuesto en `/rest/user/whoami`, traversal `../../etc/passwd`.

## Fase 2 — CRS (PL1)

```bash
# Bloqueo (403, reglas 942100/949110):
curl -i --get --data-urlencode "q=' OR '1'='1" http://localhost:8080/rest/products/search
# Evasión (200, base de Fase 3):
curl -i "http://localhost:8080/rest/products/search?q='%20&x=OR%201=1"
docker compose logs waap-proxy | grep -E '942100|949110'  # el audit log sale por docker logs
```

## Fase 3 — IA/ML

```bash
python3 -m pip install --user scikit-learn pandas numpy joblib
GEN_N=120 PACE=humano python3 waap/ml/gen_traffic.py  # ~15 min, logs/access_normal.jsonl
python3 waap/ml/extract_features.py  # -> logs/features_normal_traffic.csv
python3 waap/ml/train_model.py       # -> waap/ml/model.pkl (no versionado, regenerar)
python3 waap/ml/evaluate.py          # matriz 10 + umbrales -0.05/0.0 + ráfaga bot
```

## Fase 4 — RASP real (fork)

```bash
gh repo fork juice-shop/juice-shop --clone=false
git clone --depth 1 git@github.com:<tu-usuario>/juice-shop.git ~/juice-shop-rasp
cd ~/juice-shop-rasp && git checkout -b rasp-lab
sudo npm i -g npm@11   # npm 10 falla con bug arborist 'edgesOut' en frontend
npm install && (cd frontend && npm install-scripts approve esbuild lmdb @parcel/watcher && npm install && cd ..)
npm run build:frontend && npm run build:server
# Añadir lib/raspGuard.ts + app.use() en server.ts + guard en routes/login.ts (ver fork, rama rasp-lab)
PORT=3001 RASP_ENABLED=1 npm start
docker build -t juice-shop:rasp-lab ~/juice-shop-rasp
# En este repo el compose ya usa juice-shop:rasp-lab + RASP_ENABLED=1:
docker compose up -d && docker compose ps
curl -X POST localhost:3000/rest/user/login -H 'Content-Type: application/json' \
  -d '{"email":"\u0027 OR 1=1--","password":"x"}'   # 403 con RASP (200 + JWT admin sin RASP)
```

Prototipo previo conservado en `app/rasp-demo/`; referencia Flask del PDF en `app/rasp_agent.py`.

## Fase 5 — Pipeline

```bash
pip install --user semgrep pip-audit checkov   # + trivy y sqlmap por apt
semgrep --config=p/owasp-top-ten app/ waap/ --error
pip-audit -r waap/ml/requirements.txt
docker build -t taller-waap/app:local ./app
trivy image --severity CRITICAL,HIGH --exit-code 1 taller-waap/app:local
checkov -d . --quiet --compact
./scripts/deploy_waap_rules.sh   # solo en verde: verifica proxy + smoke 200/403
```

Workflow CI: `pipeline/.github/workflows/devsecops.yml` (corre en GitHub al push/PR).

## Fase 6 — Efectividad

```bash
python3 waap/ml/bateria_fase6.py   # -> evidencias/fase6/matriz.csv
sqlmap -u 'http://localhost:8080/rest/products/search?q=apple' --batch --level=1
docker run --rm --add-host=host.docker.internal:host-gateway \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:8080
```

## Fase 7 — Métricas

```bash
python3 waap/ml/metricas_fase7.py  # logs/eventos.jsonl + TPR/FPR/FNR + MTTD
```

## Informe

```bash
python3 scripts/build_informe.py   # regenera el DOCX (determinista)
soffice --headless --convert-to pdf Informe_Taller_WAAP_Fase0-2.docx
```

Evidencias por fase en `evidencias/`. Estructura del repo: `app/` (demo RASP + Dockerfile
del gate), `waap/ml/` (tráfico, features, modelo, evaluación, batería, métricas),
`pipeline/` (workflow), `scripts/` (deploy WAAP), `logs/`, `evidencias/`.
