"""Genera docs/index.html a partir de los modelos y de los resultados del laboratorio.

Uso:  python web/build.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import expert_consensus, risk_matrix, validate_architecture  # noqa: E402


def main():
    arch = validate_architecture.load()
    threat_model = risk_matrix.load()
    threats = risk_matrix.assess(threat_model)
    lab_path = ROOT / "results" / "lab_results.json"
    if not lab_path.exists():
        sys.exit("Falta results/lab_results.json. Ejecutar antes: python -m lab.run_lab")
    third = ROOT / "results" / "third_party_validation.json"
    replays = ROOT / "results" / "replays.json"
    audit_path = ROOT / "results" / "audit.jsonl"
    items, ratings, _ = expert_consensus.read_csv(ROOT / "model" / "experts_sample.csv")
    data = {
        "architecture": arch,
        "validation": validate_architecture.validate(arch),
        "threats": threats,
        "levels": threat_model["meta"]["levels"],
        "families": threat_model["meta"]["families"],
        "lab": json.loads(lab_path.read_text(encoding="utf-8")),
        "third_party": json.loads(third.read_text(encoding="utf-8")) if third.exists() else None,
        "replays": json.loads(replays.read_text(encoding="utf-8")) if replays.exists() else [],
        "audit": [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
                 if audit_path.exists() else [],
        "experts": expert_consensus.analyse(items, ratings, {t["id"]: t["risk"] for t in threats}),
        "maturity": json.loads((ROOT / "model" / "maturity.json").read_text(encoding="utf-8")),
    }
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html = (ROOT / "web" / "template.html").read_text(encoding="utf-8").replace("/*__DATA__*/null", blob)
    out = ROOT / "docs" / "index.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"Sitio generado: {out.relative_to(ROOT)} ({len(html) // 1024} KB)")


if __name__ == "__main__":
    main()
