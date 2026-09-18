# Fase 6 — Análisis de efectividad (mínimo media página, PDF p.15)

## Qué combinación ofrece la mejor cobertura y por qué

Ninguna capa sola cubre todo; la cobertura total solo aparece al combinarlas,
y cada hueco de una capa lo tapa otra (defensa en profundidad verificada):

- **Reglas CRS (PL1)**: bloquean 7/9 técnicas (clásico, encoded, UNION, XSS x2,
  traversal, login clásico/UNION). Fallan en lo **fragmentado** (evalúan cada
  parámetro por separado) y en variantes con espacios que alteran la firma
  (comentarios con espacios: lo paró el RASP, no el CRS).
- **IA/ML (umbral 0.0)**: detecta 9/9 como anómalo, pero al costo de FPR 80%
  (4/5 normales marcados). Con umbral -0.05 solo 2/5 con FPR 40%. Conclusión:
  el modelo **no es bloqueador viable solo**; sirve como señal para el
  orquestador (permitir/bloquear/desafiar) o para revisión, no como gate duro.
  La ráfaga bot ni siquiera cruza el umbral (limitación de IsolationForest
  documentada en Fase 3).
- **RASP (fork)**: bloquea 4/9 en contexto de ejecución (fragmentado, comentarios
  con `--`, UNION y clásico de login), incluyendo las 2 evasiones del CRS.
  Falla en XSS/traversal (fuera de su alcance SQL) y en la forma string
  `' OR '1'='1` (hueco del regex literal, con fix propuesto). Su tasa de falsos
  positivos es 0 en lo probado: solo dispara ante alteración estructural real.

**Mejor combinación: CRS + RASP, con ML como señal de apoyo.** CRS frena el
grueso automatizado (sqlmap: 42×403 vía WAAP, "not injectable", sugiere tamper),
RASP captura lo que evade firmas con contexto real (sqlmap directo: 14×403 +
8×500, tampoco inyectable), y ML aporta detección de variantes raras a cambio
de revisión humana. ZAP baseline: 0 FAIL, 59 PASS (higiene pasiva correcta).

Residuo aceptado: string-form SQLi en search (requiere fix de patrón) y ráfagas
(requieren regla de tasa explícita, no ML puro).
