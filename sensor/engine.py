"""Motor del sensor: inventario de activos y reglas de detección.

Procesa un segmento TCP por vez, así que sirve igual para una captura
grabada y para tráfico en vivo. Cada regla está asociada a una técnica de
MITRE ATT&CK for ICS.

La política es opcional. Sin política el sensor solo arma el inventario y
aplica las reglas que no necesitan configuración. Cada sección de la política
activa sus reglas:

  authorized_masters          R1, R2
  registers                   R3 (límites de ingeniería por registro)
  disconnect                  R4
  max_illegal_address_errors  R6
  max_requests_per_second     R7
  coherence                   R8
  slaves (línea base)         R3, R9, R10, R11
  hardware_addresses          R12 contra la línea base (sin ella, R12 compara con la primera dirección vista)
"""
import struct
from collections import defaultdict, deque

from . import modbus, pcap

RULES = {
    "R1": {"name": "Maestro Modbus no autorizado", "technique": "T0846", "severity": "media"},
    "R2": {"name": "Escritura desde un maestro no autorizado", "technique": "T0855", "severity": "alta"},
    "R3": {"name": "Consigna fuera de los límites de ingeniería", "technique": "T0836", "severity": "alta"},
    "R4": {"name": "Orden de desconexión del inversor", "technique": "T0816", "severity": "alta"},
    "R5": {"name": "Solicitud de identificación o diagnóstico", "technique": "T0888", "severity": "media"},
    "R6": {"name": "Barrido de registros", "technique": "T0846", "severity": "media"},
    "R7": {"name": "Tasa de solicitudes anómala", "technique": "T0814", "severity": "alta"},
    "R8": {"name": "Telemetría físicamente incoherente", "technique": "T0856", "severity": "alta"},
    "R9": {"name": "Código de función ausente en la línea base", "technique": "T0855", "severity": "media"},
    "R10": {"name": "Escritura a un registro sin antecedentes", "technique": "T0836", "severity": "alta"},
    "R11": {"name": "Esclavo ausente en la línea base", "technique": "T0846", "severity": "media"},
    "R12": {"name": "Dirección IP con otra dirección física", "technique": "T0830", "severity": "alta"},
}
DIAGNOSTIC_CODES = {8, 17, 43}
DEFAULT_POLICY = {"modbus_port": 502, "max_illegal_address_errors": 5}


def _device():
    return {"roles": set(), "first_seen": None, "last_seen": None, "requests": 0, "responses": 0,
            "exceptions": 0, "function_codes": set(), "peers": set(), "unit_ids": set(),
            "identification": None, "writes": {}, "max_requests_per_second": 0}


class Detector:
    """cooldown: segundos antes de repetir una misma alerta. None = no repetir nunca."""

    def __init__(self, policy=None, cooldown=None):
        self.policy = policy = dict(DEFAULT_POLICY, **(policy or {}))
        self.cooldown = cooldown
        self.port = policy["modbus_port"]
        self.authorized = set(policy["authorized_masters"]) if "authorized_masters" in policy else None
        self.limits = {int(k): v for k, v in policy.get("registers", {}).items()}
        self.baseline = policy.get("slaves")
        self.known_macs = policy.get("hardware_addresses")
        self.macs = defaultdict(list)           # direcciones físicas vistas por cada IP
        self.seen = {}
        self.buffers = defaultdict(bytes)
        self.illegal = defaultdict(int)
        self.window = defaultdict(deque)
        self.pending = {}                       # (maestro, puerto, transacción) -> (función, dirección, cantidad)
        self.observed = defaultdict(dict)       # últimos valores reportados por cada esclavo
        self.incoherent = defaultdict(int)
        self.devices = defaultdict(_device)
        self.stats = {"packets": 0, "requests": 0, "responses": 0, "masters": set()}

    # ------------------------------------------------------------------ alertas
    def _alert(self, out, rule, ts, src, detail, key=None):
        key = (rule, src, key)
        last = self.seen.get(key)
        if last is not None and (self.cooldown is None or ts - last < self.cooldown):
            return
        self.seen[key] = ts
        out.append({"rule": rule, **RULES[rule], "time": round(ts, 3), "source": src, "detail": detail})

    def _touch(self, ip, role, ts, peer):
        d = self.devices[ip]
        d["roles"].add(role)
        d["peers"].add(peer)
        d["first_seen"] = ts if d["first_seen"] is None else d["first_seen"]
        d["last_seen"] = ts
        return d

    # ------------------------------------------------------------------ entrada
    def link(self, ts, ip, mac):
        """Registra la dirección física con la que aparece una IP. Devuelve alertas nuevas.

        Una misma IP con dos direcciones físicas es la huella de un intermediario
        por suplantación ARP. También ocurre al reemplazar un equipo o con
        protocolos de redundancia, así que la alerta pide verificación.
        """
        out = []
        seen = self.macs[ip]
        if mac is None or mac in seen:
            return out
        seen.append(mac)
        if self.known_macs is not None:
            expected = self.known_macs.get(ip)
            if expected and mac not in expected:
                self._alert(out, "R12", ts, ip, f"{ip} aparece con la dirección física {mac}; en la línea base usa {', '.join(expected)}", mac)
        elif len(seen) > 1:
            self._alert(out, "R12", ts, ip, f"{ip} aparece con la dirección física {mac}; antes usaba {seen[0]}", mac)
        return out

    def feed(self, ts, sip, sport, dip, dport, payload):
        """Procesa los datos de un segmento TCP y devuelve la lista de alertas nuevas."""
        out = []
        if self.port not in (sport, dport) or not payload:
            return out
        self.stats["packets"] += 1
        flow = (sip, sport, dip, dport)
        adus, self.buffers[flow] = modbus.split_adus(self.buffers[flow] + payload)
        for raw in adus:
            adu = modbus.parse_adu(raw)
            if dport == self.port:
                self._request(out, ts, sip, sport, dip, adu)
            else:
                self._response(out, ts, sip, dip, dport, adu)
        return out

    def _request(self, out, ts, master, mport, slave, adu):
        fc, data, policy = adu["fc"], adu["data"], self.policy
        self.stats["requests"] += 1
        self.stats["masters"].add(master)
        m = self._touch(master, "maestro", ts, slave)
        s = self._touch(slave, "esclavo", ts, master)
        m["requests"] += 1
        m["function_codes"].add(fc)
        s["function_codes"].add(fc)
        s["unit_ids"].add(adu["unit"])
        address, count = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (None, 0)
        self.pending[(master, mport, adu["tid"])] = (fc, address, count)

        known = self.authorized is None or master in self.authorized
        if not known:
            self._alert(out, "R1", ts, master, f"{master} no figura en la lista de maestros autorizados")
        base = None
        if self.baseline is not None:
            base = self.baseline.get(slave)
            if base is None:
                self._alert(out, "R11", ts, master, f"{slave} recibe solicitudes y no figura en la línea base", slave)
            elif fc not in base["function_codes"]:
                name = modbus.FUNCTION_NAMES.get(fc, "función desconocida")
                self._alert(out, "R9", ts, master, f"Función {fc} ({name}) hacia {slave}, nunca vista en la línea base", (slave, fc))

        if fc in modbus.WRITE_CODES:
            if not known:
                self._alert(out, "R2", ts, master, f"Escritura con código de función {fc} desde {master}", fc)
            for reg, value in modbus.written_values(fc, data):
                w = s["writes"].setdefault(reg, {"min": value, "max": value, "count": 0})
                w["min"], w["max"], w["count"] = min(w["min"], value), max(w["max"], value), w["count"] + 1
                lim = self.limits.get(reg)
                if base is not None:
                    learned = base.get("write_ranges", {}).get(str(reg))
                    if learned is None:
                        self._alert(out, "R10", ts, master, f"Escritura del valor {value} en el registro {reg} de {slave}, nunca escrito en la línea base", (slave, reg))
                    else:
                        lim = lim or {"name": f"Registro {reg}", **learned}
                if lim and not lim["min"] <= value <= lim["max"]:
                    self._alert(out, "R3", ts, master, f"{lim['name']}: valor {value}, fuera de {lim['min']} a {lim['max']}", (slave, reg))
                d = policy.get("disconnect")
                if d and reg == d["register"] and value == d["value"]:
                    self._alert(out, "R4", ts, master, "Escritura que desconecta el inversor de la red")
        if fc in DIAGNOSTIC_CODES and (base is None or fc not in base["function_codes"]):
            self._alert(out, "R5", ts, master, f"Código de función {fc}, ausente en la operación normal", fc)

        q = self.window[master]
        q.append(ts)
        while q and ts - q[0] > 1.0:
            q.popleft()
        m["max_requests_per_second"] = max(m["max_requests_per_second"], len(q))
        limit = policy.get("max_requests_per_second")
        if limit and len(q) > limit:
            self._alert(out, "R7", ts, master, f"Más de {limit} solicitudes por segundo")

    def _response(self, out, ts, slave, master, mport, adu):
        fc, data = adu["fc"], adu["data"]
        self.stats["responses"] += 1
        s = self._touch(slave, "esclavo", ts, master)
        s["responses"] += 1
        s["unit_ids"].add(adu["unit"])
        request = self.pending.pop((master, mport, adu["tid"]), None)
        if fc & 0x80:
            s["exceptions"] += 1
            if data[:1] == b"\x02":
                self.illegal[master] += 1
                limit = self.policy.get("max_illegal_address_errors")
                if limit and self.illegal[master] >= limit:
                    n = self.illegal[master]
                    if self.cooldown is not None:
                        self.illegal[master] = 0
                    self._alert(out, "R6", ts, master, f"{n} lecturas a direcciones inexistentes")
            return
        if fc == modbus.DEVICE_ID:
            s["identification"] = modbus.device_identification(data) or s["identification"]
        if request and fc == modbus.READ_HOLDING and request[0] == fc and len(data) >= 1 + 2 * request[2]:
            self._telemetry(out, ts, slave, request[1], struct.unpack(f">{request[2]}H", data[1:1 + 2 * request[2]]))

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

    # ------------------------------------------------------------------ salida
    def inventory(self):
        """Activos observados, listos para guardar como JSON."""
        out = []
        for ip, d in sorted(self.devices.items()):
            out.append({"ip": ip, "roles": sorted(d["roles"]), "identification": d["identification"],
                        "hardware_addresses": list(self.macs.get(ip, [])),
                        "unit_ids": sorted(d["unit_ids"]), "peers": sorted(d["peers"]),
                        "function_codes": sorted(d["function_codes"]),
                        "requests": d["requests"], "responses": d["responses"], "exceptions": d["exceptions"],
                        "max_requests_per_second": d["max_requests_per_second"],
                        "writes": {str(r): w for r, w in sorted(d["writes"].items())},
                        "first_seen": d["first_seen"], "last_seen": d["last_seen"]})
        return out


def analyse(pcap_path, policy=None):
    """Analiza una captura grabada completa."""
    det, dedup, alerts = Detector(policy), pcap.TcpDeduplicator(), []
    for ts, sip, sport, dip, dport, seq, flags, payload, mac in pcap.read(pcap_path):
        if det.port in (sport, dport):
            alerts.extend(det.link(ts, sip, mac))
        payload = dedup.new_data((sip, sport, dip, dport), seq, flags, payload)
        if payload:
            alerts.extend(det.feed(ts, sip, sport, dip, dport, payload))
    stats = dict(det.stats, masters=sorted(det.stats["masters"]))
    return {"alerts": alerts, "stats": stats, "inventory": det.inventory()}
