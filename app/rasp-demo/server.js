/* Fase 4 (PDF p.13): demo RASP en Node/Express.
 * Puerto 1:1 del rasp_agent.py del PDF: el guard inspecciona la consulta SQL
 * FINAL ya concatenada (contexto de ejecucion) y bloquea con 403 antes de
 * ejecutarla. Se usa demo propio porque Juice Shop (proceso Node aparte)
 * no admite incrustar el agente Python del PDF.
 * Uso:  RASP_ENABLED=1 node server.js  -> http://localhost:3001
 */
'use strict';
const express = require('express');

const PORT = process.env.RASP_PORT || 3001;
const RASP_ENABLED = process.env.RASP_ENABLED !== '0';

// Mismo patron del PDF: (\bUNION\b|\bOR\b\s+1=1|--|;\s*DROP\b)
const SQLI_PATTERN = /(\bUNION\b|\bOR\b\s+1=1|--|;\s*DROP\b)/i;

// "Base de datos" en memoria (juguete): la ejecucion solo ocurre si el RASP permite.
const USERS = [
  { user: 'jim', pass: 'ncc-1701' },
  { user: 'admin', pass: 'admin123' },
];

function buildLoginQuery(username, password) {
  // Construccion deliberadamente vulnerable (igual que el ejemplo del PDF).
  return `SELECT * FROM users WHERE user='${username}' AND pass='${password}'`;
}

// Decorador RASP: envuelve la construccion real de la consulta, con visibilidad
// del valor final ya concatenado, despues de cualquier decodificacion previa.
function raspGuardQuery(queryBuilderFunc) {
  return function (...args) {
    const finalQuery = queryBuilderFunc(...args);
    if (RASP_ENABLED && SQLI_PATTERN.test(finalQuery)) {
      console.warn('RASP: consulta SQL bloqueada en tiempo de ejecucion: %s', finalQuery);
      const err = new Error('Operacion bloqueada por RASP');
      err.status = 403;
      throw err;
    }
    return finalQuery;
  };
}

const guardedLoginQuery = raspGuardQuery(buildLoginQuery);

function fakeExecute(finalQuery) {
  // Modelo minimo de semantica SQL real: estos constructos alteran la
  // estructura del WHERE (tautologia / comentario / union) -> dump total.
  // (Simplificacion documentada del demo; un motor real parsearia el SQL.)
  if (/(--|\bUNION\b|\bOR\b\s+1\s*=\s*1|\bOR\b\s*'[^']*'\s*=\s*'[^']*')/i.test(finalQuery)) {
    return { injected: true, rows: USERS };
  }
  const m = finalQuery.match(/^SELECT \* FROM users WHERE user='(.*)' AND pass='(.*)'$/s);
  if (!m) return { injected: true, rows: USERS }; // cualquier otra alteracion estructural
  const [, u, p] = m;
  return { injected: false, rows: USERS.filter((r) => r.user === u && r.pass === p) };
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => res.json({ status: 'rasp-demo ok', rasp: RASP_ENABLED ? 'ON' : 'OFF' }));

app.post('/login', (req, res) => {
  try {
    const finalQuery = guardedLoginQuery(req.body.username || '', req.body.password || '');
    const result = fakeExecute(finalQuery);
    if (result.injected) {
      // La inyeccion altero la estructura: vuelca usuarios (account takeover).
      return res.json({ status: 'success', user: '*', note: 'injection: full dump', rows: result.rows.length });
    }
    if (result.rows.length === 0) {
      return res.status(401).json({ status: 'fail', reason: 'bad credentials' });
    }
    return res.json({ status: 'success', user: result.rows[0].user });
  } catch (e) {
    return res.status(e.status || 500).json({ status: 'blocked', reason: e.message });
  }
});

app.listen(PORT, () => console.log(`rasp-demo escuchando en :${PORT} (RASP=${RASP_ENABLED ? 'ON' : 'OFF'})`));
