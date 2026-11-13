"""Registro de auditoría append-only, encadenado por hashes.

Cada registro guarda el hash del anterior, así que alterar o quitar una línea
rompe la cadena a partir de ahí y la verificación lo señala. Es el requisito
de registros auditables de IEC 62443-3-3 (SR 6.1).

El archivo es JSONL: una línea por registro, legible con cualquier herramienta.

    {"seq": 0, "time": "...", "prev": "000...", "hash": "...", "event": {...}}

**Por qué no es fail-closed.** Un portón entre un agente y sus herramientas
hace bien en bloquear cuando no puede auditar: es preferible frenar a actuar
sin registro. Un sensor de red industrial es lo contrario. Si el disco se
llena o el archivo no se puede escribir, dejar de analizar sería quedarse
ciego justo cuando hace falta ver. Así que el sensor sigue detectando,
cuenta cuántos registros no pudo escribir y lo informa al cerrar. La
integridad de lo que sí quedó escrito se mantiene: la cadena nunca se
reconstruye para disimular un hueco.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev, seq, time_text, event):
    body = json.dumps({"seq": seq, "time": time_text, "event": event},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


class AuditLog:
    """Abre o continúa un registro. Si el archivo existe, sigue su cadena."""

    def __init__(self, path, fsync=True):
        self.path = Path(path)
        self.fsync = fsync
        self.failed = 0          # registros que no se pudieron escribir
        self.last_error = None
        self.seq, self.prev = 0, GENESIS
        if self.path.exists():
            state = verify(self.path)
            if not state["ok"]:
                raise ValueError(f"{path}: la cadena está rota en el registro {state['broken_at']}. "
                                 "Conservar ese archivo como evidencia y escribir en otro.")
            self.seq, self.prev = state["records"], state["last_hash"]
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event):
        """Agrega un registro. Devuelve su hash, o None si no se pudo escribir."""
        time_text = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        digest = _digest(self.prev, self.seq, time_text, event)
        line = json.dumps({"seq": self.seq, "time": time_text, "prev": self.prev,
                           "hash": digest, "event": event},
                          ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                if self.fsync:
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError as error:       # el sensor no se detiene: ver el encabezado
            self.failed += 1
            self.last_error = str(error)
            return None
        self.seq, self.prev = self.seq + 1, digest
        return digest

    def alert(self, alert, source=None):
        event = {"kind": "alerta", **{k: v for k, v in alert.items() if k != "time"}}
        if source:
            event["capture"] = str(source)
        return self.append(event)

    def summary(self):
        text = f"Auditoría: {self.seq} registros en {self.path}"
        if self.failed:
            text += f". ATENCIÓN: {self.failed} no se pudieron escribir ({self.last_error})"
        return text


def verify(path):
    """Recorre el registro y comprueba la cadena.

    Devuelve ok, cantidad de registros, hash final y, si está rota, en qué
    número y por qué.
    """
    prev, count, broken_at, reason = GENESIS, 0, None, None
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                broken_at, reason = number, "la línea no es JSON válido"
                break
            if record.get("seq") != count:
                broken_at, reason = number, f"número fuera de orden: {record.get('seq')}, se esperaba {count}"
                break
            if record.get("prev") != prev:
                broken_at, reason = number, "no encadena con el registro anterior"
                break
            expected = _digest(prev, record["seq"], record["time"], record["event"])
            if record.get("hash") != expected:
                broken_at, reason = number, "el contenido no coincide con su hash"
                break
            prev, count = record["hash"], count + 1
    return {"ok": broken_at is None, "records": count, "last_hash": prev,
            "broken_at": broken_at, "reason": reason}


def policy_digest(policy):
    """Hash de una política, para fijarla y poder detectar que cambió."""
    body = json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
