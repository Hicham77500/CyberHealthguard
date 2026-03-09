"""Demo IsolationForest sur logs applicatifs anonymisés.

Usage:
    python src/ml/anomaly_demo.py --generate > artifacts/anomaly_report.json
    python src/ml/anomaly_demo.py --input data/logs.csv --threshold 0.65
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

ARTIFACTS_DIR = Path("artifacts")
DEFAULT_THRESHOLD = 0.7


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IsolationForest quickstart")
    parser.add_argument("--input", type=Path, help="CSV des logs (colonnes bytes_in, bytes_out, status, latency_ms)")
    parser.add_argument("--generate", action="store_true", help="Génère un dataset synthétique")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="Score (0-1) au-delà duquel on alerte")
    parser.add_argument("--limit", type=int, default=20, help="Nombre max d'anomalies à afficher")
    return parser.parse_args()


def generate_dataset(rows: int = 500) -> pd.DataFrame:
    rng = np.random.default_rng(seed=42)
    normal = pd.DataFrame(
        {
            "bytes_in": rng.normal(1_200, 300, rows).clip(min=100),
            "bytes_out": rng.normal(800, 150, rows).clip(min=50),
            "status": rng.choice([200, 201, 204], rows),
            "latency_ms": rng.normal(120, 25, rows).clip(min=10),
        }
    )
    anomalies = pd.DataFrame(
        {
            "bytes_in": rng.normal(12_000, 1_000, rows // 10).clip(min=5000),
            "bytes_out": rng.normal(5_000, 600, rows // 10).clip(min=1000),
            "status": rng.choice([500, 502, 503], rows // 10),
            "latency_ms": rng.normal(900, 120, rows // 10).clip(min=400),
        }
    )
    dataset = pd.concat([normal, anomalies], ignore_index=True)
    dataset["status"] = dataset["status"].astype(int)
    dataset["label"] = [0] * len(normal) + [1] * len(anomalies)
    return dataset.sample(frac=1, random_state=42).reset_index(drop=True)


def load_dataset(args: argparse.Namespace) -> pd.DataFrame:
    if args.generate or not args.input:
        return generate_dataset()
    if not args.input.exists():
        raise FileNotFoundError(args.input)
    return pd.read_csv(args.input)


def train_model(df: pd.DataFrame) -> IsolationForest:
    features = df[["bytes_in", "bytes_out", "status", "latency_ms"]]
    model = IsolationForest(random_state=42, contamination=0.08)
    model.fit(features)
    return model


def score_events(model: IsolationForest, df: pd.DataFrame, threshold: float) -> List[Dict[str, Any]]:
    features = df[["bytes_in", "bytes_out", "status", "latency_ms"]]
    raw_scores = model.decision_function(features)
    normalized = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() or 1)
    df = df.copy()
    df["anomaly_score"] = 1 - normalized  # inversé: 1 == risque max
    df.sort_values("anomaly_score", ascending=False, inplace=True)
    findings = []
    for _, row in df.iterrows():
        score = float(row["anomaly_score"])
        if score < threshold:
            break
        findings.append(
            {
                "bytes_in": float(row["bytes_in"]),
                "bytes_out": float(row["bytes_out"]),
                "status": int(row["status"]),
                "latency_ms": float(row["latency_ms"]),
                "score": round(score, 3),
            }
        )
    return findings


def save_report(events: List[Dict[str, Any]], threshold: float) -> Path:
    ARTIFACTS_DIR.mkdir(exist_ok=True)
    report_path = ARTIFACTS_DIR / "anomaly_report.json"
    payload = {"threshold": threshold, "findings": events, "total": len(events)}
    report_path.write_text(json.dumps(payload, indent=2))
    return report_path


def main() -> int:
    args = parse_args()
    df = load_dataset(args)
    model = train_model(df)
    events = score_events(model, df, args.threshold)
    if not events:
        print("✅ Aucune anomalie au-dessus du seuil.")
    else:
        print(f"⚠️  {len(events)} anomalies détectées (top {min(len(events), args.limit)} affichées):")
        for event in events[: args.limit]:
            print(
                f" - status={event['status']} bytes_in={event['bytes_in']:.0f} "
                f"bytes_out={event['bytes_out']:.0f} latency={event['latency_ms']:.0f}ms score={event['score']}"
            )
    report_path = save_report(events, args.threshold)
    print(f"Rapport → {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
