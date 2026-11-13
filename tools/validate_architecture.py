"""Etapa 2: valida los flujos de la arquitectura contra las zonas y conductos.

Un flujo es válido si ocurre dentro de una misma zona, o si existe un conducto
declarado entre la zona de origen y la de destino para ese puerto.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(path=ROOT / "model" / "architecture.json"):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate(arch):
    zone_of = {a["id"]: a["zone"] for a in arch["assets"]}
    zones = {z["id"] for z in arch["zones"]}
    errors = [f"El activo {a['id']} usa una zona inexistente: {a['zone']}"
              for a in arch["assets"] if a["zone"] not in zones]
    results = []
    for f in arch["flows"]:
        if f["src"] not in zone_of or f["dst"] not in zone_of:
            errors.append(f"El flujo {f['id']} referencia un activo inexistente")
            continue
        zs, zd = zone_of[f["src"]], zone_of[f["dst"]]
        conduit = None
        if zs == zd:
            status, reason = "permitido", "Dentro de la misma zona"
        else:
            conduit = next((c for c in arch["conduits"]
                            if c["from"] == zs and c["to"] == zd and c["port"] == f["port"]), None)
            if conduit:
                status, reason = "permitido", f"Conducto {conduit['id']}"
            else:
                status = "violación"
                reason = f"No hay conducto de {zs} a {zd} para el puerto {f['port']}"
        results.append({**f, "src_zone": zs, "dst_zone": zd, "status": status,
                        "reason": reason, "conduit": conduit["id"] if conduit else None})
    return {"errors": errors, "flows": results,
            "violations": sum(r["status"] == "violación" for r in results)}


if __name__ == "__main__":
    report = validate(load())
    for r in report["flows"]:
        mark = "OK " if r["status"] == "permitido" else "!! "
        print(f"{mark}{r['id']:4} {r['src']} -> {r['dst']} ({r['protocol']}/{r['port']}): {r['reason']}")
    for e in report["errors"]:
        print("ERROR:", e)
    print(f"\n{report['violations']} violaciones en {len(report['flows'])} flujos")
    sys.exit(1 if report["errors"] else 0)
