"""Etapa 3: calcula el riesgo de cada amenaza y arma la matriz 5x5."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(path=ROOT / "model" / "threats.json"):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def level_for(score, levels):
    for lv in sorted(levels, key=lambda x: -x["min"]):
        if score >= lv["min"]:
            return lv["name"]
    raise ValueError(f"Puntaje sin nivel: {score}")


def assess(model):
    levels = model["meta"]["levels"]
    out = []
    for t in model["threats"]:
        if not (1 <= t["likelihood"] <= 5 and 1 <= t["impact"] <= 5):
            raise ValueError(f"{t['id']}: probabilidad e impacto deben estar entre 1 y 5")
        score = t["likelihood"] * t["impact"]
        out.append({**t, "risk": score, "level": level_for(score, levels)})
    out.sort(key=lambda t: (-t["risk"], t["id"]))
    return out


def matrix(threats):
    """Devuelve {(probabilidad, impacto): [ids]}."""
    cells = {}
    for t in threats:
        cells.setdefault((t["likelihood"], t["impact"]), []).append(t["id"])
    return cells


if __name__ == "__main__":
    for t in assess(load()):
        print(f"{t['id']}  P{t['likelihood']} x I{t['impact']} = {t['risk']:2}  {t['level']:8} {t['title']}")
