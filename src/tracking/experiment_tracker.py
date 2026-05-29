"""Experiment Tracker for CyberHealthGuard.

Lightweight JSON-based ML experiment tracker (no external dependency).
Records each run's parameters, dataset stats and evaluation metrics
into artifacts/experiments.jsonl (one JSON object per line).

Metrics computed (when is_anomaly label is available)
-----------------------------------------------------
    precision   TP / (TP + FP)
    recall      TP / (TP + FN)
    f1_score    harmonic mean of precision and recall
    auc_roc     area under ROC curve (requires scikit-learn)
    detected_anomalies   count of true positives
    false_positives      count of FP

Usage:
    python src/tracking/experiment_tracker.py \\
        --features  artifacts/features.csv \\
        --scores    artifacts/risk_scores.csv \\
        --threshold 51.0 \\
        --model-params '{"contamination": 0.08, "random_state": 42}'

    python src/tracking/experiment_tracker.py --list
"""
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

EXPERIMENTS_FILE = Path("artifacts/experiments.jsonl")

# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _compute_metrics(
    labels: pd.Series,
    risk_scores: pd.Series,
    threshold: float,
) -> Dict[str, Any]:
    predicted = (risk_scores >= threshold).astype(int)
    y_true = labels.astype(int)

    tp = int(((predicted == 1) & (y_true == 1)).sum())
    fp = int(((predicted == 1) & (y_true == 0)).sum())
    fn = int(((predicted == 0) & (y_true == 1)).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )

    auc: Optional[float] = None
    try:
        from sklearn.metrics import roc_auc_score  # type: ignore
        auc = float(roc_auc_score(y_true, risk_scores))
    except Exception:
        pass

    return {
        "precision":            round(precision, 4),
        "recall":               round(recall, 4),
        "f1_score":             round(f1, 4),
        "auc_roc":              round(auc, 4) if auc is not None else None,
        "detected_anomalies":   tp,
        "false_positives":      fp,
        "false_negatives":      fn,
        "total_alerted":        int(predicted.sum()),
        "total_anomalies_true": int(y_true.sum()),
    }


# ---------------------------------------------------------------------------
# Run recording
# ---------------------------------------------------------------------------

def record_run(
    features_path: Path,
    scores_path: Path,
    threshold: float,
    model_params: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a run record and append it to experiments.jsonl."""
    features_df = pd.read_csv(features_path)
    scores_df   = pd.read_csv(scores_path)

    run: Dict[str, Any] = {
        "run_id":     f"RUN-{uuid.uuid4().hex[:8].upper()}",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "features_file": str(features_path),
            "scores_file":   str(scores_path),
            "total_events":  len(features_df),
            "anomaly_ratio": round(
                float(features_df["is_anomaly"].mean())
                if "is_anomaly" in features_df.columns else 0.0,
                4,
            ),
        },
        "model": {
            "type":   "IsolationForest",
            "params": model_params,
        },
        "threshold": threshold,
        "features_used": [
            c for c in features_df.columns
            if c not in ("is_anomaly", "label")
        ],
        "metrics": {},
    }

    if "is_anomaly" in features_df.columns and "risk_score" in scores_df.columns:
        run["metrics"] = _compute_metrics(
            features_df["is_anomaly"],
            scores_df["risk_score"],
            threshold,
        )

    EXPERIMENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with EXPERIMENTS_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(run, ensure_ascii=False) + "\n")

    return run


# ---------------------------------------------------------------------------
# List runs
# ---------------------------------------------------------------------------

def list_runs() -> List[Dict[str, Any]]:
    if not EXPERIMENTS_FILE.exists():
        return []
    runs = []
    for line in EXPERIMENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            runs.append(json.loads(line))
    return runs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Experiment Tracker — CyberHealthGuard"
    )
    sub = parser.add_subparsers(dest="command")

    rec = sub.add_parser("record", help="Enregistrer un run ML")
    rec.add_argument("--features",  type=Path, required=True,
                     help="CSV features (feature_engineering.py)")
    rec.add_argument("--scores",    type=Path, required=True,
                     help="CSV scores (risk_scoring.py)")
    rec.add_argument("--threshold", type=float, default=51.0,
                     help="Seuil d'alerte utilisé")
    rec.add_argument("--model-params", type=json.loads,
                     default={"contamination": 0.08, "random_state": 42},
                     help='Paramètres modèle JSON, ex: \'{"contamination":0.08}\'')

    sub.add_parser("list", help="Afficher l'historique des runs")

    # Backward-compat: allow top-level --features/--scores without subcommand
    parser.add_argument("--features",  type=Path, default=None)
    parser.add_argument("--scores",    type=Path, default=None)
    parser.add_argument("--threshold", type=float, default=51.0)
    parser.add_argument("--model-params", type=json.loads,
                        default={"contamination": 0.08, "random_state": 42})
    parser.add_argument("--list", action="store_true",
                        help="Afficher l'historique des runs")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    show_list = (args.command == "list") or getattr(args, "list", False)
    if show_list:
        runs = list_runs()
        if not runs:
            print("[tracker] Aucun run enregistré.")
            return 0
        print(f"[tracker] {len(runs)} run(s) enregistré(s) :\n")
        for run in runs:
            m = run.get("metrics", {})
            print(
                f"  {run['run_id']}  {run['timestamp'][:19]}  "
                f"threshold={run['threshold']}  "
                f"precision={m.get('precision', '-')}  "
                f"recall={m.get('recall', '-')}  "
                f"f1={m.get('f1_score', '-')}  "
                f"auc={m.get('auc_roc', '-')}"
            )
        return 0

    features = getattr(args, "features", None) or (
        args.features if args.command == "record" else None
    )
    scores = getattr(args, "scores", None) or (
        args.scores if args.command == "record" else None
    )

    if not features or not scores:
        print("[tracker] Usage: experiment_tracker.py --features <csv> --scores <csv>")
        return 2

    for path, label in ((features, "--features"), (scores, "--scores")):
        if not path.exists():
            print(f"[tracker] ❌ Fichier introuvable ({label}): {path}")
            return 2

    run = record_run(features, scores, args.threshold, args.model_params)
    m = run["metrics"]
    print(
        f"[tracker] ✅ Run enregistré : {run['run_id']}\n"
        f"  Dataset     : {run['dataset']['total_events']} événements "
        f"({run['dataset']['anomaly_ratio']*100:.1f}% anomalies)\n"
        f"  Features    : {len(run['features_used'])}\n"
        f"  Threshold   : {run['threshold']}\n"
        f"  Precision   : {m.get('precision', '-')}\n"
        f"  Recall      : {m.get('recall', '-')}\n"
        f"  F1          : {m.get('f1_score', '-')}\n"
        f"  AUC-ROC     : {m.get('auc_roc', '-')}\n"
        f"  → {EXPERIMENTS_FILE}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
