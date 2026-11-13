"""Graba el análisis de una captura para verlo en el sitio sin servidor.

Procesa la captura con el sensor y guarda cómo evolucionan las solicitudes,
el inventario y las alertas a lo largo del tiempo. No guarda el tráfico.

Uso:
  python tools/record_replay.py CAPTURA --baseline NORMAL --title "Intermediario" \\
      --description "..." [--source "cita del conjunto de datos"]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sensor import baseline, engine, pcap  # noqa: E402

OUTPUT = ROOT / "results" / "replays.json"


def shape(inventory):
    """Lo que cambia poco: equipos, direcciones, roles, funciones y rangos escritos."""
    return [{"ip": d["ip"], "hardware_addresses": d["hardware_addresses"], "roles": d["roles"],
             "identification": d["identification"], "function_codes": d["function_codes"],
             "writes": {r: [w["min"], w["max"]] for r, w in d["writes"].items()}} for d in inventory]


def record(capture, policy, step=10.0):
    det, dedup = engine.Detector(policy), pcap.TcpDeduplicator()
    segments = pcap.read(capture)
    frames, shapes, alerts = [], [], []
    t0 = last_t = None
    next_frame, last_requests, last_shape = step, 0, None

    def frame(elapsed):
        nonlocal last_requests, last_shape
        inventory = det.inventory()
        current = shape(inventory)
        if current != last_shape:
            shapes.append({"frame": len(frames), "devices": current})
            last_shape = current
        requests = det.stats["requests"]
        frames.append([round(elapsed, 1), requests, round((requests - last_requests) / step, 1),
                       [d["requests"] for d in inventory]])
        last_requests = requests

    for ts, sip, sport, dip, dport, seq, flags, payload, mac in segments:
        t0 = ts if t0 is None else t0
        last_t = ts
        while ts - t0 >= next_frame:
            frame(next_frame)
            next_frame += step
        new = det.link(ts, sip, mac) if det.port in (sport, dport) else []
        payload = dedup.new_data((sip, sport, dip, dport), seq, flags, payload)
        if payload:
            new += det.feed(ts, sip, sport, dip, dport, payload)
        for a in new:
            alerts.append({"second": round(ts - t0), "rule": a["rule"], "name": a["name"], "technique": a["technique"],
                           "severity": a["severity"], "detail": a["detail"], "source": a["source"]})
    total = (last_t - t0) if t0 is not None else 0
    frame(total)
    return {"seconds": round(total, 1), "step": step, "requests": det.stats["requests"],
            "frames": frames, "shapes": shapes, "alerts": alerts}


def main():
    parser = argparse.ArgumentParser(description="Graba el análisis de una captura para el sitio")
    parser.add_argument("capture")
    parser.add_argument("--baseline", help="Captura de operación normal de la que se aprende la línea base")
    parser.add_argument("--policy", help="Política en JSON, en lugar de --baseline")
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--source", default="", help="Origen de la captura, para citarlo")
    parser.add_argument("--name", help="Nombre de la captura a mostrar (por defecto, el del archivo)")
    parser.add_argument("--step", type=float, default=10.0, help="Segundos de captura entre cuadros")
    args = parser.parse_args()
    if args.baseline:
        policy, label = baseline.learn(args.baseline), f"Línea base aprendida de {Path(args.baseline).name}"
    elif args.policy:
        policy, label = json.loads(Path(args.policy).read_text(encoding="utf-8")), f"Política {Path(args.policy).name}"
    else:
        policy, label = None, "Sin política"
    name = args.name or Path(args.capture).name
    entry = {"capture": name, "title": args.title, "description": args.description, "policy_label": label,
             "source": args.source, **record(args.capture, policy, args.step)}
    recordings = json.loads(OUTPUT.read_text(encoding="utf-8")) if OUTPUT.exists() else []
    recordings = [r for r in recordings if r["capture"] != name] + [entry]
    OUTPUT.write_text(json.dumps(recordings, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{name}: {len(entry['frames'])} cuadros, {len(entry['alerts'])} alertas, {entry['requests']} solicitudes -> {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
