#!/usr/bin/env bash
# Fase 5 (PDF p.14): despliegue de reglas WAAP solo si el security gate pasa.
set -euo pipefail

echo "[deploy] gate de seguridad superado; aplicando reglas CRS/ModSecurity..."
docker compose -f docker-compose.yml up -d --wait
docker compose -f docker-compose.yml exec -T waap-proxy nginx -t
docker compose -f docker-compose.yml exec -T waap-proxy nginx -s reload
echo "[deploy] reglas aplicadas y nginx recargado OK"