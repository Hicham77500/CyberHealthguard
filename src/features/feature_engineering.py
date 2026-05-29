"""Feature Engineering Pipeline for CyberHealthGuard.

Transforms raw JSONL log events into a feature matrix suitable for ML.

Features produced
-----------------
Temporal:
    hour_of_day               int   0–23
    day_of_week               int   0 (Mon) – 6 (Sun)
    is_off_hours              int   1 if hour in [0-5], else 0

Categorical risk scores:
    severity                  int   1–5 (pass-through)
    category_risk             int   1–4
    role_risk_score           int   1–4
    status_risk               int   0–5

Volume:
    bytes_zscore              float z-score of bytes_transferred

Behavioral (per-user aggregates over the full dataset):
    user_event_count          int   total events by this user
    user_patient_access_count int   patient_data_access events by user
    user_failed_login_count   int   login_failure events by user

Label:
    is_anomaly                int   0 or 1

Usage:
    python src/features/feature_engineering.py --input data/logs/cyber_logs_*.json
    python src/features/feature_engineering.py --input data/logs/cyber_logs_*.json --output artifacts/features.csv
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Risk lookup tables
# ---------------------------------------------------------------------------

CATEGORY_RISK: Dict[str, int] = {
    "patient_data_access": 4,
    "network_activity": 3,
    "system_event": 2,
    "user_access": 1,
}

ROLE_RISK_SCORE: Dict[str, int] = {
    "it_admin": 4,
    "physician": 3,
    "billing_specialist": 3,
    "nurse": 2,
    "lab_tech": 2,
    "imaging_specialist": 2,
    "receptionist": 1,
}

STATUS_RISK: Dict[str, int] = {
    "alert": 5,
    "detected": 4,
    "quarantined": 4,
    "warning": 3,
    "blocked": 3,
    "failure": 2,
    "unexpected": 2,
    "pending": 1,
    "success": 0,
    "allowed": 0,
    "ok": 0,
    "resolved": 0,
}

FEATURE_COLS: List[str] = [
    "hour_of_day",
    "day_of_week",
    "is_off_hours",
    "severity",
    "category_risk",
    "role_risk_score",
    "status_risk",
    "bytes_zscore",
    "user_event_count",
    "user_patient_access_count",
    "user_failed_login_count",
]

# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def load_events(path: Path) -> List[Dict[str, Any]]:
    """Read a JSONL file and return a list of event dicts."""
    events: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def engineer_features(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Transform raw log events into a feature DataFrame.

    The returned DataFrame contains FEATURE_COLS + ['is_anomaly'].
    Behavioral aggregates are computed over the full dataset (whole-window UEBA).
    """
    rows: List[Dict[str, Any]] = []
    for evt in events:
        ts_str = evt.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            hour: int = ts.hour
            dow: int = ts.weekday()
        except (ValueError, AttributeError):
            hour = 0
            dow = 0

        rows.append({
            # Internal keys used for behavioral aggregates (dropped later)
            "_user_id": evt.get("user_id", ""),
            "_category": evt.get("category", ""),
            "_event_type": evt.get("event_type", ""),
            # Features
            "hour_of_day": hour,
            "day_of_week": dow,
            "is_off_hours": int(hour < 6),
            "severity": int(evt.get("severity", 1)),
            "category_risk": CATEGORY_RISK.get(evt.get("category", ""), 1),
            "role_risk_score": ROLE_RISK_SCORE.get(evt.get("user_role", ""), 1),
            "status_risk": STATUS_RISK.get(evt.get("status", ""), 0),
            "bytes_transferred": float(evt.get("bytes_transferred", 0)),
            # Label
            "is_anomaly": int(bool(evt.get("is_anomaly", False))),
        })

    df = pd.DataFrame(rows)

    # --- bytes z-score ---
    std = df["bytes_transferred"].std()
    mean = df["bytes_transferred"].mean()
    df["bytes_zscore"] = (
        ((df["bytes_transferred"] - mean) / std).round(4)
        if std > 0
        else 0.0
    )

    # --- Behavioral aggregates (whole-dataset window) ---
    df["user_event_count"] = (
        df.groupby("_user_id")["_user_id"].transform("count").astype(int)
    )
    df["user_patient_access_count"] = (
        df.assign(_is_patient=(df["_category"] == "patient_data_access").astype(int))
        .groupby("_user_id")["_is_patient"]
        .transform("sum")
        .astype(int)
    )
    df["user_failed_login_count"] = (
        df.assign(_is_fail=(df["_event_type"] == "login_failure").astype(int))
        .groupby("_user_id")["_is_fail"]
        .transform("sum")
        .astype(int)
    )

    return df[FEATURE_COLS + ["is_anomaly"]].reset_index(drop=True)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pipeline de feature engineering pour CyberHealthGuard"
    )
    parser.add_argument("--input", type=Path, required=True, help="Fichier JSONL source")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/features.csv"),
        help="Fichier CSV de sortie (défaut : artifacts/features.csv)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input.exists():
        print(f"[feature-eng] ❌ Fichier introuvable : {args.input}")
        return 2

    print(f"[feature-eng] Chargement de {args.input} …")
    events = load_events(args.input)
    print(f"[feature-eng] {len(events)} événements chargés.")

    df = engineer_features(events)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)

    anomaly_count = int(df["is_anomaly"].sum())
    print(
        f"[feature-eng] ✅ {len(df)} lignes → {args.output} "
        f"({anomaly_count} anomalies, {len(FEATURE_COLS)} features)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
