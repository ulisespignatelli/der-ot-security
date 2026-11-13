"""Laboratorio en tiempo real: el sensor analiza el tráfico mientras ocurre.

Uso:  python -m lab.live            (abre el sitio completo en http://127.0.0.1:8765, pestaña En vivo)
      python -m lab.live --port 9000

El switch emulado copia cada paquete al sensor en el momento en que pasa.
Un servidor local muestra el estado del inversor y las alertas en un panel
web, y permite lanzar los escenarios de ataque contra el inversor emulado.
Todo escucha solo en 127.0.0.1.
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

from . import detector, modbus
from .inverter_sim import Inverter
from .run_lab import GATEWAY_IP, INVERTER_IP, ROGUE_IP, SCENARIOS
from .tap import Tap

ROOT = Path(__file__).resolve().parent.parent
ATTACKS = {s["id"]: s for s in SCENARIOS if s["attack"]}


class LiveLab:
    """Inversor, switch, gateway y sensor corriendo de forma continua."""

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

    def stop(self):
        self.running = False
        self.tap.on_packet = None
        self.tap.stop()
        self.inverter.stop()


def make_handler(lab):
    runpy.run_path(str(ROOT / "web" / "build.py"), run_name="__main__")  # sitio con los últimos resultados
    page = (ROOT / "docs" / "index.html").read_bytes()
    meta = json.dumps({
        "attacks": [{"id": s["id"], "name": s["name"], "description": s["description"], "threat": s["threat"]}
                    for s in ATTACKS.values()],
        "rules": detector.RULES, "policy": lab.policy,
        "ips": {"gateway": GATEWAY_IP, "inversor": INVERTER_IP, "atacante": ROGUE_IP},
    }, ensure_ascii=False).encode("utf-8")

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
            if parts == ["reset"]:
                lab.reset()
                self._send(200, b'{"ok":true}')
            elif len(parts) == 2 and parts[0] == "attack" and parts[1] in ATTACKS:
                result = lab.run_attack(parts[1])
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


def serve(port=8765, open_browser=True):
    lab = LiveLab()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(lab))
    server.daemon_threads = True
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Laboratorio en vivo: {url}")
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
    args = parser.parse_args()
    serve(args.port, not args.no_browser)
