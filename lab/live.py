"""Laboratorio en tiempo real: el sensor analiza el tráfico mientras ocurre.

Uso:  python -m lab.live            (abre el sitio completo en http://127.0.0.1:8765, pestaña En vivo)
      python -m lab.live --port 9000

El switch emulado copia cada paquete al sensor en el momento en que pasa.
Un servidor local muestra el estado del inversor y las alertas en un panel
web, y permite lanzar los escenarios de ataque contra el inversor emulado.
Todo escucha solo en 127.0.0.1.

También puede reproducir una captura grabada, respetando sus tiempos, para ver
al sensor trabajar sobre tráfico de equipos reales:

      python -m lab.live --replay captura.pcap --baseline normal.pcap
      python -m lab.live --replay captura.pcap --policy politica.json --speed 60
"""
import argparse
import json
import queue
import runpy
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sensor import baseline, pcap

from . import detector, modbus
from .inverter_sim import Inverter
from .run_lab import GATEWAY_IP, INVERTER_IP, ROGUE_IP, SCENARIOS
from .tap import Tap

ROOT = Path(__file__).resolve().parent.parent
ATTACKS = {s["id"]: s for s in SCENARIOS if s["attack"]}


class LiveLab:
    """Inversor, switch, gateway y sensor corriendo de forma continua."""

    mode = "lab"

    def __init__(self, cooldown=3.0, poll_interval=0.1):
        self.policy = json.loads((Path(__file__).parent / "policy.json").read_text(encoding="utf-8"))
        self.inverter = Inverter()
        self.tap = Tap(("127.0.0.1", self.inverter.port), INVERTER_IP, [GATEWAY_IP, ROGUE_IP])
        self.detector = detector.Detector(self.policy, cooldown=cooldown)
        self.lock = threading.Lock()          # protege al detector y a la lista de alertas
        self.attack_lock = threading.Lock()   # un ataque por vez
        self.alerts = []
        self.subscribers = []
        self.request_times = []
        self.poll_interval = poll_interval
        self.running = True
        self.tap.on_packet = self._on_packet
        threading.Thread(target=self._poll, daemon=True).start()
        threading.Thread(target=self._publish_state, daemon=True).start()

    # --- lo que usan los escenarios de run_lab ---
    def client(self, identity):
        return modbus.Client("127.0.0.1", self.tap.ports[identity])

    # --- sensor en vivo ---
    def _on_packet(self, ts, sip, sport, dip, dport, payload):
        with self.lock:
            new = self.detector.feed(ts, sip, sport, dip, dport, payload)
            if dport == self.policy["modbus_port"]:
                self.request_times.append(ts)
            self.alerts.extend(new)
        for alert in new:
            self.broadcast("alert", alert)

    def _poll(self):
        """El gateway consulta al inversor de forma periódica: es la operación normal."""
        c = self.client(GATEWAY_IP)
        while self.running:
            try:
                c.read_holding(0, 3)
                c.read_holding(10, 2)
            except OSError:
                break
            time.sleep(self.poll_interval)
        c.close()

    def state(self):
        now = time.time()
        with self.inverter.lock:
            regs = list(self.inverter.regs)
        with self.lock:
            self.request_times = [t for t in self.request_times if now - t <= 1.0]
            rate = len(self.request_times)
            stats = self.detector.stats
            reported = self.detector.observed.get(INVERTER_IP, {}).get(0)
            return {"time": round(now, 2), "potencia_w": regs[0], "potencia_reportada_w": reported, "tension_v": regs[1] / 10,
                    "frecuencia_hz": regs[2] / 100, "limite_pct": regs[10], "conectado": bool(regs[11]),
                    "solicitudes_por_segundo": rate, "paquetes": stats["packets"],
                    "solicitudes": stats["requests"], "maestros": sorted(stats["masters"]),
                    "alertas": len(self.alerts)}

    def _publish_state(self):
        while self.running:
            self.broadcast("state", self.state())
            time.sleep(0.5)

    # --- acciones del panel ---
    def run_attack(self, scenario_id, settle=0.6):
        sc = ATTACKS[scenario_id]
        with self.attack_lock:
            start = time.time()
            self.broadcast("attack", {"id": sc["id"], "name": sc["name"], "description": sc["description"],
                                      "threat": sc["threat"], "time": round(start, 3)})
            sc["attack"](self)
            time.sleep(settle)
            with self.lock:
                fired = sorted({a["rule"] for a in self.alerts if a["time"] >= start - 0.001})
            result = {"id": sc["id"], "name": sc["name"], "threat": sc["threat"], "fired_rules": fired,
                      "outcome": "detectado" if fired else "no detectado",
                      "seconds": round(time.time() - start, 2)}
            self.broadcast("result", result)
            return result

    def reset(self):
        with self.inverter.lock:
            self.inverter.regs[10], self.inverter.regs[11] = 100, 1
            self.inverter._update()
        self.broadcast("reset", {"time": round(time.time(), 3)})

    # --- difusión a los navegadores conectados ---
    def subscribe(self):
        q = queue.Queue(maxsize=1000)
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q):
        if q in self.subscribers:
            self.subscribers.remove(q)

    def broadcast(self, event, data):
        for q in list(self.subscribers):
            try:
                q.put_nowait((event, data))
            except queue.Full:
                self.unsubscribe(q)

    def meta(self):
        return {"mode": "lab",
                "attacks": [{"id": s["id"], "name": s["name"], "description": s["description"], "threat": s["threat"]}
                            for s in ATTACKS.values()],
                "rules": detector.RULES, "policy": self.policy,
                "ips": {"gateway": GATEWAY_IP, "inversor": INVERTER_IP, "atacante": ROGUE_IP}}

    def post(self, parts):
        if parts == ["reset"]:
            self.reset()
            return {"ok": True}
        if len(parts) == 2 and parts[0] == "attack" and parts[1] in ATTACKS:
            return self.run_attack(parts[1])
        return None

    def stop(self):
        self.running = False
        self.tap.on_packet = None
        self.tap.stop()
        self.inverter.stop()


class Replay:
    """Reproduce una captura grabada hacia el sensor, respetando sus tiempos.

    No hay equipos ni tráfico nuevo: el sensor recibe los mismos segmentos que
    quedaron en la captura, en el mismo orden y con la misma separación,
    dividida por la velocidad elegida.
    """

    mode = "replay"

    def __init__(self, capture, policy=None, policy_label="Sin política: solo inventario y reglas sin configuración", speed=None):
        self.capture = Path(capture)
        self.policy, self.policy_label = policy, policy_label
        self.segments = list(pcap.read(self.capture))
        if not self.segments:
            raise SystemExit(f"{capture}: la captura no tiene segmentos TCP")
        self.t0 = self.segments[0][0]
        self.total = self.segments[-1][0] - self.t0
        self.speed = float(speed) if speed else max(1.0, round(self.total / 45))
        self.lock = threading.Lock()
        self.alerts, self.subscribers = [], []
        self.running = True
        self._restart, self._new_speed = threading.Event(), None
        self._state = {"elapsed": 0, "total": round(self.total, 1), "speed": self.speed, "finished": False,
                       "packets": 0, "requests": 0, "rate": 0, "alerts": 0, "inventory": []}
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while self.running:
            self._play()
            while self.running and not self._restart.wait(0.2):
                pass
            self._restart.clear()

    def _play(self):
        det, dedup = detector.Detector(self.policy), pcap.TcpDeduplicator()
        with self.lock:
            self.alerts = []
        self.broadcast("replay_start", {"speed": self.speed})
        wall_ref, cap_ref = time.time(), 0.0
        published, last_requests, last_cap = 0.0, 0, 0.0

        def publish(cap, finished=False):
            nonlocal published, last_requests, last_cap
            requests = det.stats["requests"]
            rate = (requests - last_requests) / (cap - last_cap) if cap > last_cap else 0
            last_requests, last_cap, published = requests, cap, time.time()
            self._state = {"elapsed": round(cap, 1), "total": round(self.total, 1), "speed": self.speed,
                           "finished": finished, "packets": det.stats["packets"], "requests": requests,
                           "rate": round(rate, 1), "alerts": len(self.alerts), "inventory": det.inventory()}
            self.broadcast("replay_state", self._state)

        cap = 0.0
        for ts, sip, sport, dip, dport, seq, flags, payload, mac in self.segments:
            cap = ts - self.t0
            while self.running and not self._restart.is_set():
                if self._new_speed:
                    self.speed, self._new_speed = self._new_speed, None
                    wall_ref, cap_ref = time.time(), last_cap
                delay = wall_ref + (cap - cap_ref) / self.speed - time.time()
                if delay <= 0.002:
                    break
                time.sleep(min(delay, 0.05))
                if time.time() - published >= 0.25:
                    publish(min(cap, cap_ref + (time.time() - wall_ref) * self.speed))
            if not self.running or self._restart.is_set():
                return
            new = det.link(ts, sip, mac) if det.port in (sport, dport) else []
            payload = dedup.new_data((sip, sport, dip, dport), seq, flags, payload)
            if payload:
                new += det.feed(ts, sip, sport, dip, dport, payload)
            for alert in new:
                alert["second"] = round(cap)
                with self.lock:
                    self.alerts.append(alert)
                self.broadcast("alert", alert)
            if time.time() - published >= 0.25:
                publish(cap)
        publish(cap, finished=True)

    def state(self):
        return self._state

    def meta(self):
        return {"mode": "replay", "capture": self.capture.name, "seconds": round(self.total, 1),
                "segments": len(self.segments), "policy_label": self.policy_label, "rules": detector.RULES}

    def post(self, parts):
        if parts == ["replay", "restart"]:
            self._restart.set()
            return {"ok": True}
        if len(parts) == 3 and parts[:2] == ["replay", "speed"] and parts[2].isdigit() and 1 <= int(parts[2]) <= 3600:
            self._new_speed = float(parts[2])
            return {"ok": True, "speed": int(parts[2])}
        return None

    def subscribe(self):
        q = queue.Queue(maxsize=5000)
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q):
        if q in self.subscribers:
            self.subscribers.remove(q)

    def broadcast(self, event, data):
        for q in list(self.subscribers):
            try:
                q.put_nowait((event, data))
            except queue.Full:
                self.unsubscribe(q)

    def stop(self):
        self.running = False


def make_handler(lab):
    runpy.run_path(str(ROOT / "web" / "build.py"), run_name="__main__")  # sitio con los últimos resultados
    page = (ROOT / "docs" / "index.html").read_bytes()
    meta = json.dumps(lab.meta(), ensure_ascii=False).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, page, "text/html; charset=utf-8")
            elif self.path == "/meta":
                self._send(200, meta)
            elif self.path == "/events":
                self._events()
            else:
                self._send(404, b'{"error":"no encontrado"}')

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            parts = self.path.strip("/").split("/")
            result = lab.post(parts)
            if result is not None:
                self._send(200, json.dumps(result, ensure_ascii=False).encode("utf-8"))
            else:
                self._send(404, b'{"error":"no encontrado"}')

        def _events(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            q = lab.subscribe()
            try:
                with lab.lock:
                    recent = lab.alerts[-50:]
                self._emit("history", recent)
                if lab.mode == "replay":
                    self._emit("replay_state", lab.state())
                while lab.running:
                    try:
                        event, data = q.get(timeout=10)
                        self._emit(event, data)
                    except queue.Empty:
                        self.wfile.write(b": activo\n\n")
                        self.wfile.flush()
            except OSError:
                pass
            finally:
                lab.unsubscribe(q)

        def _emit(self, event, data):
            body = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            self.wfile.write(body.encode("utf-8"))
            self.wfile.flush()

    return Handler


def serve(port=8765, open_browser=True, source=None):
    lab = source or LiveLab()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(lab))
    server.daemon_threads = True
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"{'Reproducción de ' + lab.capture.name if lab.mode == 'replay' else 'Laboratorio en vivo'}: {url}")
    print("Cortar con Ctrl+C.")
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url + "/#en-vivo",)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDetenido.")
    finally:
        lab.stop()
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Laboratorio OT en tiempo real")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true", help="No abrir el navegador")
    parser.add_argument("--replay", metavar="PCAP", help="Reproducir una captura en lugar del laboratorio emulado")
    parser.add_argument("--baseline", metavar="PCAP", help="Con --replay: aprender la línea base de esta captura de operación normal")
    parser.add_argument("--policy", metavar="JSON", help="Con --replay: política o línea base ya guardada")
    parser.add_argument("--speed", type=float, help="Con --replay: velocidad (por defecto, la que hace durar la reproducción unos 45 s)")
    args = parser.parse_args()
    source = None
    if args.replay:
        policy, label = None, "Sin política: solo inventario y reglas que no requieren configuración"
        if args.baseline:
            policy, label = baseline.learn(args.baseline), f"Línea base aprendida de {Path(args.baseline).name}"
        elif args.policy:
            policy, label = json.loads(Path(args.policy).read_text(encoding="utf-8")), f"Política {Path(args.policy).name}"
        source = Replay(args.replay, policy, label, args.speed)
    serve(args.port, not args.no_browser, source)
