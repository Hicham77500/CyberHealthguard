"""Alert Manager for CyberHealthGuard.

Reads the risk-scored feature CSV and emits structured JSON alerts
for events above a given risk threshold.

Alert structure
---------------
{
  "alert_id":    "ALT-<hex8>",
  "timestamp":   "<ISO 8601 UTC>",
  "severity":    "Critical|High|Medium|Low",
  "alert_type":  "<inferred from features>",
  "risk_score":  94.5,
  "details": { ...relevant feature values... }
}

Alert type inference (priority order)
--------------------------------------
1. off_hours_patient_access   → is_off_hours=1 AND category_risk≥4
2. mass_data_exfiltration      → bytes_zscore≥2 AND category_risk≥4
3. privilege_abuse             → role_risk_score=4 AND status_risk≥3
4. suspicious_network          → category_risk=3 AND status_risk≥4
5. repeated_login_failure      → user_failed_login_count≥5
6. anomalous_activity          → fallback

Usage:
    python src/alerts/alert_manager.py --input artifacts/risk_scores.csv
    python src/alerts/alert_manager.py --input artifacts/risk_scores.csv --threshold 50 --output artifacts/alerts.json
"""
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

# ---------------------------------------------------------------------------
# Alert type inference
# ---------------------------------------------------------------------------

def _infer_alert_type(row: pd.Series) -> str:
    off_hours   = int(row.get("is_off_hours",          0))
    cat_risk    = float(row.get("category_risk",       1))
    bytes_z     = float(row.get("bytes_zscore",        0.0))
    role_risk   = float(row.get("role_risk_score",     1))
    status_risk = float(row.get("status_risk",         0))
    failed_log  = int(row.get("user_failed_login_count", 0))

    if off_hours and cat_risk >= 4:
        return "off_hours_patient_access"
    if bytes_z >= 2 and cat_risk >= 4:
        return "mass_data_exfiltration"
    if role_risk >= 4 and status_risk >= 3:
        return "privilege_abuse"
    if cat_risk >= 3 and status_risk >= 4:
        return "suspicious_network_activity"
    if failed_log >= 5:
        return "repeated_login_failure"
    return "anomalous_activity"


# ---------------------------------------------------------------------------
# Alert generation
# ---------------------------------------------------------------------------

_DETAIL_COLS = [
    "hour_of_day", "day_of_week", "is_off_hours",
    "severity", "category_risk", "role_risk_score", "status_risk",
    "bytes_zscore", "user_event_count", "user_patient_access_count",
    "user_failed_login_count",
]


def generate_alerts(df: pd.DataFrame, threshold: float) -> List[Dict[str, Any]]:
    """Return a list of alert dicts for rows where risk_score >= threshold."""
    if "risk_score" not in df.columns:
        raise ValueError("Input DataFrame must contain 'risk_score'. Run risk_scoring.py first.")

    triggered = df[df["risk_score"] >= threshold].copy()
    triggered.sort_values("risk_score", ascending=False, inplace=True)

    now = datetime.now(timezone.utc).isoformat()
    alerts: List[Dict[str, Any]] = []

    for _, row in triggered.iterrows():
        details = {
            col: (float(row[col]) if isinstance(row[col], float) else int(row[col]))
            for col in _DETAIL_COLS
            if col in row.index
        }
        alerts.append({
            "alert_id":   f"ALT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp":  now,
            "severity":   str(row.get("risk_level", "Low")),
            "alert_type": _infer_alert_type(row),
            "risk_score": float(row["risk_score"]),
            "details":    details,
        })

    return alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Alert Manager — CyberHealthGuard"
    )
    parser.add_argument(
        "--input", type=Path, required=True,
        help="CSV issu de risk_scoring.py (doit contenir risk_score + risk_level)"
    )
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/alerts.json"),
        help="Fichier JSON de sortie des alertes"
    )
    parser.add_argument(
        "--threshold", type=float, default=51.0,
        help="Score minimum pour déclencher une alerte (défaut: 51 = High+Critical)"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input.exists():
        print(f"[alert-mgr] ❌ Fichier introuvable : {args.input}")
        return 2

    df = pd.read_csv(args.input)
    alerts = generate_alerts(df, args.threshold)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threshold":    args.threshold,
        "total_alerts": len(alerts),
        "by_severity": {
            level: sum(1 for a in alerts if a["severity"] == level)
            for level in ("Critical", "High", "Medium", "Low")
        },
        "alerts": alerts,
    }
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False))

    print(
        f"[alert-mgr] ✅ {len(alerts)} alerte(s) générée(s) "
        f"(seuil ≥ {args.threshold}) → {args.output}"
    )
    by_sev = payload["by_severity"]
    print(
        f"  Critical: {by_sev['Critical']}  High: {by_sev['High']}  "
        f"Medium: {by_sev['Medium']}  Low: {by_sev['Low']}"
    )

    if alerts:
        print(f"\nTop 5 alertes :")
        for alert in alerts[:5]:
            print(
                f"  [{alert['severity']:8s}] {alert['alert_type']:35s} "
                f"score={alert['risk_score']}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
