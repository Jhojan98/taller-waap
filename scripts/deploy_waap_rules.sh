#!/usr/bin/env bash
# Fase 5 (PDF p.14). Despliegue de reglas WAAP solo si el gate pasa.
# Se invoca desde el workflow (if: success()) o manual: ./scripts/deploy_waap_rules.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[WAAP] Verificando stack..."
docker compose ps --format json | grep -q waap-proxy || { echo "[WAAP] ERROR: proxy no levantado"; exit 1; }

echo "[WAAP] $(grep -E '^PARANOIA=' .env 2>/dev/null || echo 'PARANOIA=1 (defecto)')"
echo "[WAAP] Recargando proxy (aplica reglas CRS + imagen vigente)..."
docker compose up -d waap-proxy
docker compose exec -T waap-proxy nginx -s reload 2>/dev/null || docker compose restart waap-proxy

echo "[WAAP] Smoke test..."
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 http://localhost:8080/rest/products/search?q=apple)
[ "$code" = "200" ] || { echo "[WAAP] ERROR: smoke test -> $code"; exit 1; }
blocked=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 --get --data-urlencode "q=' OR '1'='1" http://localhost:8080/rest/products/search)
[ "$blocked" = "403" ] || { echo "[WAAP] ERROR: CRS no bloquea (->$blocked)"; exit 1; }

echo "[WAAP] Despliegue OK: normal=200, SQLi=403."
