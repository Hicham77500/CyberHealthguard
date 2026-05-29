"""Risk Scoring Engine for CyberHealthGuard.

Computes a composite risk score (0–100) per event from the feature matrix
produced by feature_engineering.py.

Scoring formula
---------------
Each factor contributes a capped additive weight:

    is_off_hours          × 20   (max 20)
    severity              → 0–5  mapped to 0–20
    category_risk         → 1–4  mapped to 0–15
    role_risk_score       → 1–4  mapped to 0–10
    status_risk           → 0–5  mapped to 0–20
    bytes_zscore          clipped to 0–3 → mapped to 0–15
    ─────────────────────────────────────────────
    Total raw             0–100

Risk levels
-----------
    0–20    Low
    21–50   Medium
    51–80   High
    81–100  Critical

Usage:
    python src/scoring/risk_scoring.py --input artifacts/features.csv
    python src/scoring/risk_scoring.py --input artifacts/features.csv --output artifacts/risk_scores.csv
    python src/scoring/risk_scoring.py --input artifacts/features.csv --top 20
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import pandas as pd

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

RISK_LEVELS: List[Dict] = [
    {"label": "Critical", "min": 81, "max": 100},
    {"label": "High",     "min": 51, "max": 80},
    {"label": "Medium",   "min": 21, "max": 50},
    {"label": "Low",      "min": 0,  "max": 20},
]


def risk_level(score: float) -> str:
    for level in RISK_LEVELS:
        if score >= level["min"]:
            return level["label"]
    return "Low"


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

def compute_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Add a risk_score (0–100) and risk_level column to *df*.

    Works on any DataFrame that contains the expected columns.
    Missing columns default to 0 contribution (graceful degradation).
    """
    df = df.copy()

    off_hours   = df.get("is_off_hours",    pd.Series(0, index=df.index)).clip(0, 1)
    severity    = df.get("severity",        pd.Series(1, index=df.index)).clip(1, 5)
    cat_risk    = df.get("category_risk",   pd.Series(1, index=df.index)).clip(1, 4)
    role_risk   = df.get("role_risk_score", pd.Series(1, index=df.index)).clip(1, 4)
    status_risk = df.get("status_risk",     pd.Series(0, index=df.index)).clip(0, 5)
    bytes_z     = df.get("bytes_zscore",    pd.Series(0.0, index=df.index)).clip(0, 3)

    score = (
        off_hours * 20
        + (severity - 1) / 4 * 20       # severity 1→0, 5→20
        + (cat_risk - 1) / 3 * 15       # cat 1→0, 4→15
        + (role_risk - 1) / 3 * 10      # role 1→0, 4→10
        + status_risk / 5 * 20          # status 0→0, 5→20
        + bytes_z / 3 * 15              # z 0→0, 3→15
    ).clip(0, 100).round(1)

    df["risk_score"] = score
    df["risk_level"] = score.map(risk_level)
    return df


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

def summary(df: pd.DataFrame) -> Dict:
    counts = df["risk_level"].value_counts().to_dict()
    return {
        "total": len(df),
        "Critical": counts.get("Critical", 0),
        "High":     counts.get("High",     0),
        "Medium":   counts.get("Medium",   0),
        "Low":      counts.get("Low",      0),
        "mean_score": round(float(df["risk_score"].mean()), 2),
        "max_score":  round(float(df["risk_score"].max()),  2),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Risk Scoring Engine — CyberHealthGuard"
    )
    parser.add_argument("--input", type=Path, required=True,
                        help="CSV features (issu de feature_engineering.py)")
    parser.add_argument("--output", type=Path, default=Path("artifacts/risk_scores.csv"),
                        help="CSV enrichi avec risk_score + risk_level")
    parser.add_argument("--top", type=int, default=10,
                        help="Afficher les N événements les plus risqués")
    parser.add_argument("--report", type=Path, default=None,
                        help="Exporter le résumé JSON vers ce chemin")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input.exists():
        print(f"[risk-scoring] ❌ Fichier introuvable : {args.input}")
        return 2

    df = pd.read_csv(args.input)
    df = compute_scores(df)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)

    stats = summary(df)
    print(
        f"[risk-scoring] ✅ {stats['total']} événements scorés → {args.output}\n"
        f"  Critical: {stats['Critical']}  High: {stats['High']}  "
        f"Medium: {stats['Medium']}  Low: {stats['Low']}\n"
        f"  Score moyen: {stats['mean_score']}  Score max: {stats['max_score']}"
    )

    top = df.nlargest(args.top, "risk_score")[
        [c for c in ["risk_score", "risk_level", "is_off_hours", "severity",
                     "category_risk", "bytes_zscore", "is_anomaly"] if c in df.columns]
    ]
    print(f"\nTop {args.top} événements :")
    print(top.to_string(index=False))

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(stats, indent=2, ensure_ascii=False))
        print(f"\n[risk-scoring] Résumé → {args.report}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
