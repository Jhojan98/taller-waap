# Fase 5: imagen del demo RASP para el gate (build + Trivy).
# Alpine (base minima) + multistage (npm y su arbol CVE fuera de la imagen final).
FROM node:22-alpine AS deps
WORKDIR /app
COPY rasp-demo/package.json rasp-demo/package-lock.json* ./rasp-demo/
RUN cd rasp-demo && npm install --omit=dev

FROM node:22-alpine
WORKDIR /app
# Hardening: el runtime solo necesita node; npm/corepack salen (traian 11 CVE HIGH/CRIT).
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
  /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
COPY --from=deps /app/rasp-demo/node_modules ./rasp-demo/node_modules
COPY rasp-demo/package.json rasp-demo/server.js ./rasp-demo/
RUN chown -R node:node /app
USER node
ENV RASP_ENABLED=1 RASP_PORT=3001
EXPOSE 3001
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD node -e "fetch('http://localhost:3001/').then(r=>{if(!r.ok)process.exit(1)})" || exit 1
CMD ["node", "rasp-demo/server.js"]
