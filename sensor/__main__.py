"""Sensor pasivo de Modbus/TCP.

  python -m sensor analyze captura.pcap [--policy politica.json] [--json salida.json]
  python -m sensor learn   captura.pcap -o politica.json
  python -m sensor live    --iface eth0 [--policy politica.json] [--seconds 60]
"""
import argparse
import json
import signal
import sys
import time
from pathlib import Path

from . import baseline, capture, engine, modbus, pcap


def load_policy(path):
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def print_inventory(inventory):
    print(f"\nActivos observados: {len(inventory)}")
    for d in inventory:
        ident = f"  [{d['identification']}]" if d["identification"] else ""
        macs = f"  {', '.join(d['hardware_addresses'])}" if d["hardware_addresses"] else ""
        print(f"  {d['ip']:<39} {'/'.join(d['roles']):<16}{macs}{ident}")
        if "esclavo" in d["roles"]:
            codes = ", ".join(f"{c} {modbus.FUNCTION_NAMES.get(c, '?')}" for c in d["function_codes"])
            print(f"      unidades {d['unit_ids']}  funciones: {codes}")
            if d["exceptions"]:
                print(f"      respuestas de excepción: {d['exceptions']}")
            for reg, w in d["writes"].items():
                print(f"      registro {reg}: {w['count']} escrituras, valores de {w['min']} a {w['max']}")
        if "maestro" in d["roles"]:
            print(f"      {d['requests']} solicitudes a {', '.join(p for p in d['peers'])}; "
                  f"pico de {d['max_requests_per_second']} por segundo")


def print_alert(a):
    stamp = time.strftime("%H:%M:%S", time.localtime(a["time"]))
    print(f"  {stamp}  {a['severity'].upper():<5} {a['rule']:<3} {a['name']} ({a['technique']}) · {a['detail']} · origen {a['source']}")


def cmd_analyze(args):
    result = engine.analyse(args.capture, dict(load_policy(args.policy) or {}, modbus_port=args.port) if args.policy
                            else {"modbus_port": args.port})
    s = result["stats"]
    print(f"{args.capture}: {s['packets']} segmentos Modbus, {s['requests']} solicitudes, {s['responses']} respuestas")
    print_inventory(result["inventory"])
    print(f"\nAlertas: {len(result['alerts'])}" + ("" if args.policy else "  (sin política: solo reglas que no requieren configuración)"))
    for a in result["alerts"]:
        print_alert(a)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nResultado guardado en {args.json}")
    return 1 if result["alerts"] else 0


def cmd_learn(args):
    policy = baseline.learn(args.capture, port=args.port)
    Path(args.output).write_text(json.dumps(policy, indent=2, ensure_ascii=False), encoding="utf-8")
    info = policy["learned_from"]
    print(f"Línea base aprendida de {info['requests']} solicitudes en {info['seconds']} s")
    print(f"  maestros autorizados: {', '.join(policy['authorized_masters']) or 'ninguno'}")
    for ip, s in policy["slaves"].items():
        print(f"  esclavo {ip}: funciones {s['function_codes']}, registros escritos {list(s['write_ranges']) or 'ninguno'}")
    print(f"  límite de tasa: {policy['max_requests_per_second']} solicitudes por segundo")
    print(f"Guardada en {args.output}. Revisala antes de usarla.")
    return 0


def cmd_live(args):
    policy = dict(load_policy(args.policy) or {}, modbus_port=args.port)
    det, dedup = engine.Detector(policy, cooldown=args.cooldown), pcap.TcpDeduplicator()
    deadline = time.time() + args.seconds if args.seconds else None
    stopped = []
    signal.signal(signal.SIGINT, lambda *_: stopped.append(True))

    def on_segment(ts, sip, sport, dip, dport, seq, flags, payload, mac):
        alerts = det.link(ts, sip, mac)
        payload = dedup.new_data((sip, sport, dip, dport), seq, flags, payload)
        if payload:
            alerts += det.feed(ts, sip, sport, dip, dport, payload)
        for alert in alerts:
            print_alert(alert)
            sys.stdout.flush()

    print(f"Escuchando Modbus/TCP (puerto {args.port}) en {args.iface}. El sensor no transmite. Cortar con Ctrl+C.")
    sys.stdout.flush()
    capture.sniff(args.iface, on_segment, lambda: bool(stopped) or (deadline and time.time() > deadline), args.port)
    s = det.stats
    print(f"\n{s['packets']} segmentos Modbus, {s['requests']} solicitudes, {s['responses']} respuestas")
    print_inventory(det.inventory())
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m sensor", description="Sensor pasivo de Modbus/TCP")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="Analiza una captura PCAP o PCAPNG")
    a.add_argument("capture")
    a.add_argument("--policy", help="Política o línea base en JSON")
    a.add_argument("--json", help="Guarda inventario y alertas en un archivo")
    a.set_defaults(run=cmd_analyze)
    l = sub.add_parser("learn", help="Aprende una línea base desde una captura de operación normal")
    l.add_argument("capture")
    l.add_argument("-o", "--output", required=True)
    l.set_defaults(run=cmd_learn)
    v = sub.add_parser("live", help="Escucha una interfaz de red")
    v.add_argument("--iface", required=True)
    v.add_argument("--policy")
    v.add_argument("--seconds", type=float, help="Detenerse después de este tiempo")
    v.add_argument("--cooldown", type=float, default=30.0, help="Segundos antes de repetir una misma alerta")
    v.set_defaults(run=cmd_live)
    for p in (a, l, v):
        p.add_argument("--port", type=int, default=502, help="Puerto TCP de Modbus (por defecto 502)")
    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
