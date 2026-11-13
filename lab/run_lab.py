"""Etapa 4: ejecuta los escenarios en el laboratorio emulado y mide la detección.

Uso:  python -m lab.run_lab

Todo corre en la propia máquina (127.0.0.1). Los escenarios de ataque solo
apuntan al inversor emulado de este laboratorio.
"""
import json
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from sensor import baseline

from . import detector, modbus
from .inverter_sim import Inverter
from .tap import Tap

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
INVERTER_IP, GATEWAY_IP, ROGUE_IP = "10.10.40.21", "10.10.15.30", "10.10.40.99"


def unauthorized_write(lab):
    c = lab.client(ROGUE_IP)
    c.write_single(10, 30)
    c.close()


def reconnaissance(lab):
    c = lab.client(ROGUE_IP)
    c.device_id()
    for addr in range(0, 60, 10):
        c.read_holding(addr, 10)
    c.close()


def out_of_range(lab):
    c = lab.client(GATEWAY_IP)
    c.write_single(10, 5)
    c.close()


def flood(lab):
    c = lab.client(ROGUE_IP)
    for _ in range(300):
        c.read_holding(0, 3)
    c.close()


def disconnect(lab):
    c = lab.client(ROGUE_IP)
    c.write_single(11, 0)
    c.close()


def valid_command_as_master(lab):
    c = lab.client(GATEWAY_IP)
    c.write_single(10, 60)
    c.close()


class FalseDataInjector:
    """Intermediario que altera la potencia reportada en las respuestas del inversor."""

    def __init__(self, false_power_w, power_register=0):
        self.value, self.register = false_power_w, power_register
        self.reads = {}

    def __call__(self, src_ip, src_port, dst_ip, dst_port, data):
        adus, rest = modbus.split_adus(data)
        if rest or not adus:
            return data
        out = b""
        for raw in adus:
            adu = modbus.parse_adu(raw)
            if dst_port == 502 and adu["fc"] == modbus.READ_HOLDING and len(adu["data"]) == 4:
                self.reads[(src_ip, src_port, adu["tid"])] = struct.unpack(">HH", adu["data"])
            elif src_port == 502 and adu["fc"] == modbus.READ_HOLDING:
                addr, count = self.reads.pop((dst_ip, dst_port, adu["tid"]), (None, 0))
                if addr is not None and addr <= self.register < addr + count:
                    pos = 9 + 2 * (self.register - addr)
                    raw = raw[:pos] + struct.pack(">H", self.value) + raw[pos + 2:]
            out += raw
        return out


def _inject(lab, false_power_w, seconds=1.5):
    lab.tap.tamper = FalseDataInjector(false_power_w)
    try:
        time.sleep(seconds)
    finally:
        lab.tap.tamper = None


def false_data_incoherent(lab):
    _inject(lab, 6500)


def false_data_coherent(lab):
    _inject(lab, 2000)


SCENARIOS = [
    {"id": "S0", "name": "Operación normal", "threat": None, "attack": None, "expected": [],
     "description": "La pasarela consulta al inversor cada 100 ms. Mide los falsos positivos."},
    {"id": "S1", "name": "Escritura no autorizada del límite de potencia", "threat": "A15", "attack": unauthorized_write,
     "expected": ["R2"], "description": "Un equipo desconocido baja el límite de potencia al 30 %."},
    {"id": "S2", "name": "Reconocimiento", "threat": "A17", "attack": reconnaissance,
     "expected": ["R1", "R5", "R6"], "description": "Un equipo desconocido pide la identificación y recorre registros."},
    {"id": "S3", "name": "Consigna fuera de rango", "threat": "A18", "attack": out_of_range,
     "expected": ["R3"], "description": "El maestro autorizado envía un límite del 5 %, por debajo del mínimo de ingeniería."},
    {"id": "S4", "name": "Inundación de solicitudes", "threat": "A19", "attack": flood,
     "expected": ["R7"], "description": "Un equipo desconocido envía 300 solicitudes seguidas."},
    {"id": "S5", "name": "Desconexión del inversor", "threat": "A16", "attack": disconnect,
     "expected": ["R4"], "description": "Un equipo desconocido envía la orden de desconexión."},
    {"id": "S6", "name": "Consigna válida con identidad del maestro", "threat": "A20", "attack": valid_command_as_master,
     "expected": [], "stealth": True,
     "description": "Desde el maestro autorizado se envía un límite del 60 %, dentro de rango. En la red es igual a una operación legítima."},
    {"id": "S7", "name": "Datos falsos físicamente imposibles", "threat": "A26", "attack": false_data_incoherent,
     "expected": ["R8"],
     "description": "Un intermediario hace que el inversor reporte 6500 W, más que su potencia nominal de 5000 W."},
    {"id": "S8", "name": "Datos falsos coherentes con el modelo", "threat": "A27", "attack": false_data_coherent,
     "expected": [], "stealth": True,
     "description": "Un intermediario hace que el inversor reporte 2000 W en lugar de los 4000 W reales. El valor es físicamente posible."},
]


class Lab:
    def __init__(self):
        self.inverter = Inverter()
        self.tap = Tap(("127.0.0.1", self.inverter.port), INVERTER_IP, [GATEWAY_IP, ROGUE_IP])
        self.polling = False

    def client(self, identity):
        return modbus.Client("127.0.0.1", self.tap.ports[identity])

    def _poll(self):
        c = self.client(GATEWAY_IP)
        while self.polling:
            c.read_holding(0, 3)
            c.read_holding(10, 2)
            time.sleep(0.1)
        c.close()

    def run(self, scenario, baseline_seconds):
        with self.inverter.lock:
            self.inverter.regs[10], self.inverter.regs[11] = 100, 1
            self.inverter._update()
        pcap = RESULTS / "pcap" / f"{scenario['id']}.pcap"
        self.tap.start_capture(pcap)
        self.polling = True
        poller = threading.Thread(target=self._poll, daemon=True)
        poller.start()
        time.sleep(baseline_seconds if scenario["attack"] is None else 0.5)
        if scenario["attack"]:
            scenario["attack"](self)
            time.sleep(0.5)
        with self.inverter.lock:
            state = {"limite_pct": self.inverter.regs[10], "conectado": bool(self.inverter.regs[11]),
                     "potencia_w": self.inverter.regs[0]}
        self.polling = False
        poller.join()
        packets = self.tap.stop_capture()
        return pcap, packets, state

    def stop(self):
        self.tap.stop()
        self.inverter.stop()


def evaluate(scenario, analysis):
    fired = sorted({a["rule"] for a in analysis["alerts"]})
    if scenario["attack"] is None:
        outcome = "sin alertas" if not fired else "falso positivo"
    elif fired:
        outcome = "detectado"
    else:
        outcome = "no detectado"
    return fired, outcome


def main(baseline_seconds=20.0, save=True):
    (RESULTS / "pcap").mkdir(parents=True, exist_ok=True)
    policy = json.loads((Path(__file__).parent / "policy.json").read_text(encoding="utf-8"))
    lab = Lab()
    out = []
    try:
        for sc in SCENARIOS:
            pcap, packets, state = lab.run(sc, baseline_seconds)
            analysis = detector.analyse(pcap, policy)
            fired, outcome = evaluate(sc, analysis)
            out.append({"id": sc["id"], "name": sc["name"], "description": sc["description"],
                        "threat": sc["threat"], "expected_rules": sc["expected"], "fired_rules": fired,
                        "missing_rules": sorted(set(sc["expected"]) - set(fired)),
                        "outcome": outcome, "stealth": sc.get("stealth", False),
                        "packets": packets, "requests": analysis["stats"]["requests"],
                        "masters": analysis["stats"]["masters"], "inverter_state": state,
                        "alerts": analysis["alerts"], "pcap": f"results/pcap/{pcap.name}"})
            print(f"{sc['id']}  {outcome:14} reglas={','.join(fired) or '-':12} paquetes={packets:5}  {sc['name']}")
    finally:
        lab.stop()
    # Segunda evaluación: el sensor aprende la línea base de la operación normal (S0), sin política manual.
    learned = baseline.learn(RESULTS / "pcap" / "S0.pcap")
    for r in out:
        fired = sorted({a["rule"] for a in detector.analyse(ROOT / r["pcap"], learned)["alerts"]}, key=lambda x: int(x[1:]))
        r["learned_rules"] = fired
        r["learned_outcome"] = ("detectado" if fired else "no detectado") if r["threat"] else ("sin alertas" if not fired else "falso positivo")
    inventory = detector.analyse(RESULTS / "pcap" / "S2.pcap")["inventory"]
    attacks = [r for r in out if r["threat"]]
    base = out[0]
    summary = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "attacks": len(attacks), "detected": sum(r["outcome"] == "detectado" for r in attacks),
               "baseline_packets": base["packets"], "baseline_requests": base["requests"],
               "baseline_seconds": baseline_seconds, "baseline_alerts": len(base["alerts"]),
               "detected_learned": sum(r["learned_outcome"] == "detectado" for r in attacks),
               "rules": detector.RULES, "policy": policy, "learned_policy": learned, "inventory": inventory}
    if save:
        (RESULTS / "learned_policy.json").write_text(json.dumps(learned, indent=2, ensure_ascii=False), encoding="utf-8")
        (RESULTS / "lab_results.json").write_text(
            json.dumps({"summary": summary, "scenarios": out}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nCon línea base aprendida: {summary['detected_learned']} de {summary['attacks']} ataques detectados.")
    print(f"Detectados {summary['detected']} de {summary['attacks']} ataques. "
          f"Alertas en operación normal: {summary['baseline_alerts']} en {summary['baseline_requests']} solicitudes.")
    return out


if __name__ == "__main__":
    main()
