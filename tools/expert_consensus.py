"""Etapa 4: mide el acuerdo entre expertos sobre la relevancia de cada amenaza.

Entrada: CSV con una fila por experto y una columna por amenaza (1 a 5).
Salida: mediana y rango intercuartil por amenaza, coeficiente W de Kendall
(0 = sin acuerdo, 1 = acuerdo total) y correlación de Spearman entre el orden
de los expertos y el orden de riesgo del modelo.
"""
import csv
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    items = [c for c in rows[0] if c not in ("experto", "perfil")]
    ratings = [[float(r[i]) for i in items] for r in rows]
    return items, ratings, [r.get("perfil", "") for r in rows]


def ranks(values):
    """Rangos promedio (1 = menor valor), con empates."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            out[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return out


def kendall_w(ratings):
    """W de Kendall con corrección por empates."""
    m, n = len(ratings), len(ratings[0])
    ranked = [ranks(r) for r in ratings]
    sums = [sum(r[j] for r in ranked) for j in range(n)]
    mean = m * (n + 1) / 2
    s = sum((x - mean) ** 2 for x in sums)
    ties = 0.0
    for r in ratings:
        counts = {}
        for v in r:
            counts[v] = counts.get(v, 0) + 1
        ties += sum(c ** 3 - c for c in counts.values())
    denom = m ** 2 * (n ** 3 - n) - m * ties
    return 12 * s / denom if denom else 0.0


def spearman(a, b):
    ra, rb = ranks(a), ranks(b)
    ma, mb = statistics.mean(ra), statistics.mean(rb)
    num = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    den = (sum((x - ma) ** 2 for x in ra) * sum((y - mb) ** 2 for y in rb)) ** 0.5
    return num / den if den else 0.0


def analyse(items, ratings, model_risk=None):
    per_item = []
    for j, item in enumerate(items):
        col = sorted(r[j] for r in ratings)
        q = statistics.quantiles(col, n=4, method="inclusive")
        per_item.append({"id": item, "median": statistics.median(col),
                         "q1": q[0], "q3": q[2], "iqr": q[2] - q[0],
                         "consensus": (q[2] - q[0]) <= 1})
    out = {"experts": len(ratings), "kendall_w": round(kendall_w(ratings), 3), "items": per_item}
    if model_risk:
        out["spearman_vs_model"] = round(
            spearman([p["median"] for p in per_item], [model_risk[i] for i in items]), 3)
    return out


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else ROOT / "model" / "experts_sample.csv"
    items, ratings, _ = read_csv(path)
    print(json.dumps(analyse(items, ratings), indent=2, ensure_ascii=False))
