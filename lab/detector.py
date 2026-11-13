"""Sensor pasivo: analiza un PCAP de Modbus/TCP y genera alertas.

No envía ningún paquete a la red. Cada regla está asociada a una técnica de
MITRE ATT&CK for ICS.
"""
import json
import socket
import struct
import sys
from collections import defaultdict, deque
from pathlib import Path

from . import modbus

RULES = {
    "R1": {"name": "Maestro Modbus no autorizado", "technique": "T0846", "severity": "media"},
    "R2": {"name": "Escritura desde un maestro no autorizado", "technique": "T0855", "severity": "alta"},
    "R3": {"name": "Consigna fuera de los límites de ingeniería", "technique": "T0836", "severity": "alta"},
    "R4": {"name": "Orden de desconexión del inversor", "technique": "T0816", "severity": "alta"},
    "R5": {"name": "Solicitud de identificación o diagnóstico", "technique": "T0888", "severity": "media"},
    "R6": {"name": "Barrido de registros", "technique": "T0846", "severity": "media"},
    "R7": {"name": "Tasa de solicitudes anómala", "technique": "T0814", "severity": "alta"},
    "R8": {"name": "Telemetría físicamente incoherente", "technique": "T0856", "severity": "alta"},
}
DIAGNOSTIC_CODES = {8, 17, 43}


def read_pcap(path):
    """Devuelve (tiempo, ip_origen, puerto_origen, ip_destino, puerto_destino, datos) por paquete TCP."""
    data = Path(path).read_bytes()
    if struct.unpack("<I", data[:4])[0] != 0xA1B2C3D4:
        raise ValueError("Formato PCAP no soportado")
    pos = 24
    while pos + 16 <= len(data):
        sec, usec, caplen, _ = struct.unpack("<IIII", data[pos:pos + 16])
        frame = data[pos + 16:pos + 16 + caplen]
        pos += 16 + caplen
        if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
            continue
        ihl = (frame[14] & 0x0F) * 4
        tcp = 14 + ihl
        sport, dport = struct.unpack(">HH", frame[tcp:tcp + 4])
        offset = (frame[tcp + 12] >> 4) * 4
        yield (sec + usec / 1e6, socket.inet_ntoa(frame[26:30]), sport,
               socket.inet_ntoa(frame[30:34]), dport, frame[tcp + offset:])


class Detector:
    """Motor de reglas que procesa un paquete por vez.

    Sirve tanto para analizar un PCAP grabado como para tráfico en vivo.
    cooldown: segundos antes de repetir una misma alerta. None = no repetir nunca.
    """

    def __init__(self, policy, cooldown=None):
        self.policy = policy
        self.cooldown = cooldown
        self.port = policy["modbus_port"]
        self.authorized = set(policy["authorized_masters"])
        self.limits = {int(k): v for k, v in policy["registers"].items()}
        self.seen = {}
        self.buffers = defaultdict(bytes)
        self.illegal = defaultdict(int)
        self.window = defaultdict(deque)
        self.pending = {}                      # lecturas en curso: (maestro, puerto, transacción) -> (dirección, cantidad)
        self.observed = defaultdict(dict)      # últimos valores reportados por cada esclavo
        self.incoherent = defaultdict(int)
        self.stats = {"packets": 0, "requests": 0, "responses": 0, "masters": set()}

    def _alert(self, out, rule, ts, src, detail, key=None):
        key = (rule, src, key)
        last = self.seen.get(key)
        if last is not None and (self.cooldown is None or ts - last < self.cooldown):
            return
        self.seen[key] = ts
        out.append({"rule": rule, **RULES[rule], "time": round(ts, 3), "source": src, "detail": detail})

    def feed(self, ts, sip, sport, dip, dport, payload):
        """Procesa un paquete TCP y devuelve la lista de alertas nuevas."""
        out = []
        port, policy = self.port, self.policy
        if port not in (sport, dport) or not payload:
            return out
        self.stats["packets"] += 1
        flow = (sip, sport, dip, dport)
        adus, self.buffers[flow] = modbus.split_adus(self.buffers[flow] + payload)
        for raw in adus:
            adu = modbus.parse_adu(raw)
            fc, data = adu["fc"], adu["data"]
            if dport == port:  # solicitud
                self.stats["requests"] += 1
                self.stats["masters"].add(sip)
                if fc == modbus.READ_HOLDING and len(data) == 4:
                    self.pending[(sip, sport, adu["tid"])] = struct.unpack(">HH", data)
                known = sip in self.authorized
                if not known:
                    self._alert(out, "R1", ts, sip, f"{sip} no figura en la lista de maestros autorizados")
                if fc in modbus.WRITE_CODES:
                    if not known:
                        self._alert(out, "R2", ts, sip, f"Escritura con código de función {fc} desde {sip}", fc)
                    if fc == modbus.WRITE_SINGLE and len(data) >= 4:
                        addr, value = struct.unpack(">HH", data[:4])
                        lim = self.limits.get(addr)
                        if lim and not lim["min"] <= value <= lim["max"]:
                            self._alert(out, "R3", ts, sip, f"{lim['name']}: valor {value}, fuera de {lim['min']} a {lim['max']}", addr)
                        d = policy["disconnect"]
                        if addr == d["register"] and value == d["value"]:
                            self._alert(out, "R4", ts, sip, "Escritura que desconecta el inversor de la red")
                if fc in DIAGNOSTIC_CODES:
                    self._alert(out, "R5", ts, sip, f"Código de función {fc}, ausente en la operación normal", fc)
                q = self.window[sip]
                q.append(ts)
                while q and ts - q[0] > 1.0:
                    q.popleft()
                if len(q) > policy["max_requests_per_second"]:
                    self._alert(out, "R7", ts, sip, f"Más de {policy['max_requests_per_second']} solicitudes por segundo")
            else:  # respuesta
                self.stats["responses"] += 1
                read = self.pending.pop((dip, dport, adu["tid"]), None)
                if read and fc == modbus.READ_HOLDING and len(data) >= 1 + 2 * read[1]:
                    self._telemetry(out, ts, sip, read[0], struct.unpack(f">{read[1]}H", data[1:1 + 2 * read[1]]))
                if fc & 0x80 and data[:1] == b"\x02":
                    self.illegal[dip] += 1
                    if self.illegal[dip] >= policy["max_illegal_address_errors"]:
                        n = self.illegal[dip]
                        if self.cooldown is not None:
                            self.illegal[dip] = 0
                        self._alert(out, "R6", ts, dip, f"{n} lecturas a direcciones inexistentes")
        return out


    def _telemetry(self, out, ts, slave, address, values):
        """Guarda lo que reporta el esclavo y verifica su coherencia física."""
        regs = self.observed[slave]
        for i, v in enumerate(values):
            regs[address + i] = v
        c = self.policy.get("coherence")
        if not c or not address <= c["power_register"] < address + len(values):
            return
        power = regs[c["power_register"]]
        limit, conn = regs.get(c["limit_register"]), regs.get(c["connection_register"])
        problem = None
        if conn == 0 and power > 0:
            problem = f"Reporta {power} W con el inversor desconectado"
        elif limit is not None:
            ceiling = c["rated_w"] * min(limit, 100) / 100 * (1 + c["tolerance"])
            if power > ceiling:
                problem = f"Reporta {power} W, por encima del máximo posible de {round(ceiling)} W con límite {limit} %"
        if not problem:
            self.incoherent[slave] = 0
            return
        self.incoherent[slave] += 1
        if self.incoherent[slave] >= c["consecutive_readings"]:
            self._alert(out, "R8", ts, slave, problem)


def analyse(pcap_path, policy):
    """Analiza un PCAP grabado completo."""
    det = Detector(policy)
    alerts = []
    for packet in read_pcap(pcap_path):
        alerts.extend(det.feed(*packet))
    stats = dict(det.stats, masters=sorted(det.stats["masters"]))
    return {"alerts": alerts, "stats": stats}


if __name__ == "__main__":
    policy = json.loads((Path(__file__).parent / "policy.json").read_text(encoding="utf-8"))
    print(json.dumps(analyse(sys.argv[1], policy), indent=2, ensure_ascii=False))
