"""Aprende una línea base a partir de una captura de operación normal.

La política resultante describe lo que se observó: qué equipos actúan como
maestros, qué funciones recibe cada esclavo, qué registros se escriben y con
qué valores, y a qué ritmo. El sensor alerta después ante lo que se aparte.

La captura debe corresponder a un período sin incidentes: todo lo que haya
en ella queda aceptado como normal.
"""
import math
from pathlib import Path

from .engine import analyse


def learn(pcap_path, port=502, rate_margin=2.0):
    result = analyse(pcap_path, {"modbus_port": port, "max_illegal_address_errors": 0})
    inventory = result["inventory"]
    masters = [d for d in inventory if "maestro" in d["roles"]]
    slaves = {}
    for d in inventory:
        if "esclavo" in d["roles"]:
            slaves[d["ip"]] = {
                "function_codes": d["function_codes"],
                "write_ranges": {reg: {"min": w["min"], "max": w["max"]} for reg, w in d["writes"].items()},
            }
    peak = max((m["max_requests_per_second"] for m in masters), default=0)
    seconds = 0.0
    seen = [d for d in inventory if d["first_seen"] is not None]
    if seen:
        seconds = max(d["last_seen"] for d in seen) - min(d["first_seen"] for d in seen)
    return {
        "comment": "Línea base aprendida por el sensor. Revisarla antes de usarla: acepta como normal todo lo observado.",
        "modbus_port": port,
        "authorized_masters": sorted(m["ip"] for m in masters),
        "slaves": slaves,
        "hardware_addresses": {d["ip"]: d["hardware_addresses"] for d in inventory if d["hardware_addresses"]},
        "max_requests_per_second": max(10, math.ceil(peak * rate_margin)),
        "max_illegal_address_errors": 3,
        "learned_from": {"capture": Path(pcap_path).name, "seconds": round(seconds, 1),
                         "requests": result["stats"]["requests"], "peak_requests_per_second": peak},
    }
