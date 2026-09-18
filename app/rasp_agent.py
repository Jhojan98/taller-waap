"""Fase 4 (PDF p.13): middleware RASP simplificado (Flask/WSGI).

REFERENCIA LITERAL DEL PDF — no ejecutable contra Juice Shop (Node/Express):
ver app/rasp-demo/server.js, puerto 1:1 de esta logica a Express, probado
en Fase 4 (bloqueos 403 + latencia).
"""
import functools
import logging
import re

try:
    from flask import abort
except ImportError:  # sin Flask instalado: el decorador sigue siendo legible/importable
    def abort(code, description=None):
        raise RuntimeError(f"RASP abort {code}: {description}")

SQLI_PATTERN = re.compile(r"(\bUNION\b|\bOR\b\s+1=1|--|;\s*DROP\b)", re.I)
logger = logging.getLogger("rasp")


def rasp_guard_query(query_builder_func):
    """Decorador que envuelve la construccion real de la consulta SQL
    dentro de la aplicacion, con visibilidad del valor final ya
    concatenado -- despues de cualquier decodificacion previa."""
    @functools.wraps(query_builder_func)
    def wrapper(*args, **kwargs):
        final_query = query_builder_func(*args, **kwargs)
        if SQLI_PATTERN.search(final_query):
            logger.warning(
                "RASP: consulta SQL bloqueada en tiempo de ejecucion: %s",
                final_query,
            )
            abort(403, description="Operacion bloqueada por RASP")
        return final_query
    return wrapper


@rasp_guard_query
def build_login_query(username, password):
    # Ejemplo deliberadamente vulnerable a nivel de construccion de la
    # consulta; el RASP intercepta el resultado final antes de ejecutarlo.
    # nosemgrep - hallazgo intencional del demo RASP (Fase 4): se bloquea en runtime.
    return f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"  # nosemgrep
