"""Sensor pasivo de Modbus/TCP.

  python -m sensor analyze captura.pcap [--policy politica.json] [--audit registro.jsonl]
  python -m sensor learn   normal.pcap -o politica.json
  python -m sensor propose captura.pcap --policy politica.json [-o propuesta.json]
  python -m sensor live    --iface eth0 [--policy politica.json] [--audit registro.jsonl]
  python -m sensor verify  registro.jsonl
"""
import argparse
import json
import signal
import sys
import time
from pathlib import Path

from . import audit as audit_mod
from . import baseline, capture, engine, modbus, pcap, propose as propose_mod

EFFECT_LABEL = {"afloja": "AFLOJA ", "revisar": "revisar"}


def load_policy(args):
    """Carga la política y, si se pidió, comprueba que no haya cambiado."""
    if not getattr(args, "policy", None):
        if getattr(args, "policy_sha256", None):
            raise SystemExit("--policy-sha256 necesita --policy")
        return None
    policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    digest = audit_mod.policy_digest(policy)
    expected = getattr(args, "policy_sha256", None)
    if expected and digest != expected:
        raise SystemExit(f"La política {args.policy} cambió: su hash es {digest} y se esperaba {expected}. "
                         "Revisar el cambio antes de usarla.")
    return policy


def open_audit(args, policy):
    if not getattr(args, "audit", None):
        return None
    log = audit_mod.AuditLog(args.audit)
    log.append({"kind": "inicio", "command": args.command,
                "policy": Path(args.policy).name if getattr(args, "policy", None) else None,
                "policy_sha256": audit_mod.policy_digest(policy) if policy else None,
                "source": str(getattr(args, "capture", None) or getattr(args, "iface", ""))})
    return log


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
    policy = load_policy(args)
    log = open_audit(args, policy)
    result = engine.analyse(args.capture, dict(policy or {}, modbus_port=args.port))
    s = result["stats"]
    print(f"{args.capture}: {s['packets']} segmentos Modbus, {s['requests']} solicitudes, {s['responses']} respuestas")
    print_inventory(result["inventory"])
    print(f"\nAlertas: {len(result['alerts'])}" + ("" if policy else "  (sin política: solo reglas que no requieren configuración)"))
    for a in result["alerts"]:
        print_alert(a)
        if log:
            log.alert(a, source=Path(args.capture).name)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nResultado guardado en {args.json}")
    if log:
        log.append({"kind": "fin", "alerts": len(result["alerts"]), "requests": s["requests"]})
        print(log.summary())
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
    print(f"  hash de la política: {audit_mod.policy_digest(policy)}")
    print(f"Guardada en {args.output}. Revisala antes de usarla.")
    return 0


def cmd_propose(args):
    current = load_policy(args)
    result = propose_mod.propose(args.capture, current, port=args.port)
    changes = result["changes"]
    loosens = [c for c in changes if c["effect"] == "afloja"]
    print(f"{args.capture}: {len(changes)} cambios propuestos, {len(loosens)} que aflojan la política\n")
    for c in changes:
        print(f"  {EFFECT_LABEL[c['effect']]}  [{c['area']}] {c['detail']}")
        if c["evidence"]:
            print(f"            {c['evidence']}")
    if not changes:
        print("  La política vigente ya cubre todo lo observado.")
    if args.output:
        Path(args.output).write_text(json.dumps(result["proposal"], indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nPropuesta guardada en {args.output}. La política vigente no se modificó.")
        print(f"Para aplicarla, revisar cada cambio y reemplazar la política a mano.")
    else:
        print("\nSin -o no se escribe nada. La política vigente no se modificó.")
    return 1 if loosens else 0


def cmd_live(args):
    policy = load_policy(args)
    log = open_audit(args, policy)
    det, dedup = engine.Detector(dict(policy or {}, modbus_port=args.port), cooldown=args.cooldown), pcap.TcpDeduplicator()
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
            if log:
                log.alert(alert, source=args.iface)
            sys.stdout.flush()

    print(f"Escuchando Modbus/TCP (puerto {args.port}) en {args.iface}. El sensor no transmite. Cortar con Ctrl+C.")
    sys.stdout.flush()
    capture.sniff(args.iface, on_segment, lambda: bool(stopped) or (deadline and time.time() > deadline), args.port)
    s = det.stats
    print(f"\n{s['packets']} segmentos Modbus, {s['requests']} solicitudes, {s['responses']} respuestas")
    print_inventory(det.inventory())
    if log:
        log.append({"kind": "fin", "requests": s["requests"]})
        print(log.summary())
    return 0


def cmd_verify(args):
    state = audit_mod.verify(args.audit)
    if state["ok"]:
        print(f"{args.audit}: cadena íntegra, {state['records']} registros.")
        print(f"  último hash: {state['last_hash']}")
        return 0
    print(f"{args.audit}: CADENA ROTA en la línea {state['broken_at']}: {state['reason']}")
    print(f"  los primeros {state['records']} registros son íntegros")
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m sensor", description="Sensor pasivo de Modbus/TCP")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="Analiza una captura PCAP o PCAPNG")
    a.add_argument("capture")
    a.add_argument("--json", help="Guarda inventario y alertas en un archivo")
    a.set_defaults(run=cmd_analyze)

    l = sub.add_parser("learn", help="Aprende una línea base desde una captura de operación normal")
    l.add_argument("capture")
    l.add_argument("-o", "--output", required=True)
    l.set_defaults(run=cmd_learn)

    pr = sub.add_parser("propose", help="Propone cambios a una política, sin aplicarlos")
    pr.add_argument("capture")
    pr.add_argument("-o", "--output", help="Archivo donde escribir la propuesta")
    pr.set_defaults(run=cmd_propose)

    v = sub.add_parser("live", help="Escucha una interfaz de red")
    v.add_argument("--iface", required=True)
    v.add_argument("--seconds", type=float, help="Detenerse después de este tiempo")
    v.add_argument("--cooldown", type=float, default=30.0, help="Segundos antes de repetir una misma alerta")
    v.set_defaults(run=cmd_live)

    vf = sub.add_parser("verify", help="Comprueba la cadena de un registro de auditoría")
    vf.add_argument("audit")
    vf.set_defaults(run=cmd_verify)

    for p in (a, pr, v):
        p.add_argument("--policy", help="Política o línea base en JSON")
        p.add_argument("--policy-sha256", help="Hash esperado de la política: si no coincide, no se ejecuta")
    for p in (a, v):
        p.add_argument("--audit", help="Registro de auditoría append-only (JSONL encadenado)")
    for p in (a, l, pr, v):
        p.add_argument("--port", type=int, default=502, help="Puerto TCP de Modbus (por defecto 502)")

    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
