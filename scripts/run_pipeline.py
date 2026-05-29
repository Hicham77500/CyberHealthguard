"""Pipeline orchestrator — CyberHealthGuard control interface.

Chains all 7 pipeline steps end-to-end and generates an HTML dashboard.

Usage
-----
    python scripts/run_pipeline.py --input data/logs/cyber_logs_*.json
    python scripts/run_pipeline.py --input data/logs/cyber_logs_20260309_160310.json \\
        --threshold 51.0 --anomaly-threshold 0.75
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Ensure repo root is in sys.path so "src.*" imports resolve.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.validator.dataset_validator import validate_file
from src.features.feature_engineering import load_events, engineer_features
from src.ml.anomaly_demo import train_model, _feature_cols
from src.scoring.risk_scoring import compute_scores, summary as risk_summary_fn
from src.alerts.alert_manager import generate_alerts
from src.tracking.experiment_tracker import record_run
from src.reporting.report_generator import generate_report

import json
import pandas as pd

# ---------------------------------------------------------------------------
# Pretty printing helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_MUTED  = "\033[90m"


def _sep() -> None:
    print(f"{_MUTED}{'━' * 60}{_RESET}")


def _step_ok(n: int, name: str, detail: str, elapsed: float) -> None:
    print(f"  {_GREEN}✅{_RESET} [{n}/7] {_BOLD}{name}{_RESET}  "
          f"{_MUTED}{detail}  ({elapsed:.2f}s){_RESET}")


def _step_err(n: int, name: str, err: str) -> None:
    print(f"  {_RED}❌{_RESET} [{n}/7] {_BOLD}{name}{_RESET}  {_RED}{err}{_RESET}")


def _header(input_path: Path, threshold: float) -> None:
    print(f"\n{_CYAN}{_BOLD}{'━' * 60}")
    print("  🛡  CyberHealthGuard — Pipeline Orchestrator")
    print(f"{'━' * 60}{_RESET}")
    print(f"  Input     : {input_path}")
    print(f"  Threshold : {threshold}")
    _sep()


# ---------------------------------------------------------------------------
# Pipeline steps
# ---------------------------------------------------------------------------

def _step1_validate(input_path: Path) -> dict:
    report = validate_file(input_path)
    if report["error_count"] > 0:
        raise ValueError(
            f"{report['error_count']} validation error(s) — "
            "run with --input on a clean file or fix the dataset."
        )
    return report


def _step2_features(input_path: Path, features_path: Path) -> pd.DataFrame:
    events = load_events(input_path)
    df = engineer_features(events)
    features_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(features_path, index=False)
    return df


def _step3_ml(df: pd.DataFrame, anomaly_threshold: float) -> tuple[object, pd.DataFrame]:
    model = train_model(df)
    cols = _feature_cols(df)
    raw_scores = model.decision_function(df[cols])
    normalized = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() or 1)
    scored_df = df.copy()
    scored_df["anomaly_score"] = 1 - normalized  # 1 == max risk
    scored_df["is_anomaly"] = (scored_df["anomaly_score"] >= anomaly_threshold).astype(int)
    return model, scored_df


def _step4_risk(scored_df: pd.DataFrame, scores_path: Path) -> pd.DataFrame:
    df_risk = compute_scores(scored_df)
    scores_path.parent.mkdir(parents=True, exist_ok=True)
    df_risk.to_csv(scores_path, index=False)
    return df_risk


def _step5_alerts(df_risk: pd.DataFrame, alerts_path: Path, threshold: float) -> list[dict]:
    alerts = generate_alerts(df_risk, threshold=threshold)
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    alerts_path.write_text(json.dumps(alerts, indent=2, ensure_ascii=False), encoding="utf-8")
    return alerts


def _step6_track(
    features_path: Path,
    scores_path: Path,
    threshold: float,
    model_params: dict,
) -> dict:
    return record_run(features_path, scores_path, threshold, model_params)


def _step7_report(artifacts_dir: Path) -> Path:
    return generate_report(artifacts_dir)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_pipeline(
    input_path: Path,
    threshold: float = 51.0,
    anomaly_threshold: float = 0.75,
    no_report: bool = False,
) -> int:
    """Run the full CyberHealthGuard pipeline.

    Returns 0 on success, 1 on failure.
    """
    artifacts_dir  = _REPO_ROOT / "artifacts"
    features_path  = artifacts_dir / "features.csv"
    scores_path    = artifacts_dir / "risk_scores.csv"
    alerts_path    = artifacts_dir / "alerts.json"
    report_path    = artifacts_dir / "validation_report.json"

    _header(input_path, threshold)
    t_global = time.perf_counter()

    # ── Step 1 — Dataset Validation ─────────────────────────────────────────
    t0 = time.perf_counter()
    try:
        validation = _step1_validate(input_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(validation, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        _step_ok(1, "Dataset Validation",
                 f"{validation['total']:,} events — 0 errors", time.perf_counter() - t0)
    except (ValueError, FileNotFoundError, OSError) as exc:
        _step_err(1, "Dataset Validation", str(exc))
        return 1

    # ── Step 2 — Feature Engineering ────────────────────────────────────────
    t0 = time.perf_counter()
    try:
        df_feat = _step2_features(input_path, features_path)
        _step_ok(2, "Feature Engineering",
                 f"{len(df_feat):,} rows × {df_feat.shape[1]} features", time.perf_counter() - t0)
    except Exception as exc:  # noqa: BLE001
        _step_err(2, "Feature Engineering", str(exc))
        return 1

    # ── Step 3 — IsolationForest ─────────────────────────────────────────────
    t0 = time.perf_counter()
    try:
        model, scored_df = _step3_ml(df_feat, anomaly_threshold)
        anomaly_count = int(scored_df["is_anomaly"].sum()) if "is_anomaly" in scored_df.columns else "?"
        _step_ok(3, "IsolationForest",
                 f"{anomaly_count} anomalies detected (threshold={anomaly_threshold})",
                 time.perf_counter() - t0)
    except Exception as exc:  # noqa: BLE001
        _step_err(3, "IsolationForest", str(exc))
        return 1

    # ── Step 4 — Risk Scoring ────────────────────────────────────────────────
    t0 = time.perf_counter()
    try:
        df_risk = _step4_risk(scored_df, scores_path)
        rs = risk_summary_fn(df_risk)
        risk_sum_path = artifacts_dir / "risk_summary.json"
        risk_sum_path.write_text(
            json.dumps(rs, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        _step_ok(4, "Risk Scoring",
                 f"Critical={rs.get('Critical',0)}  High={rs.get('High',0)}  "
                 f"Mean={rs.get('mean_score',0):.1f}",
                 time.perf_counter() - t0)
    except Exception as exc:  # noqa: BLE001
        _step_err(4, "Risk Scoring", str(exc))
        return 1

    # ── Step 5 — Alert Generation ────────────────────────────────────────────
    t0 = time.perf_counter()
    try:
        alerts = _step5_alerts(df_risk, alerts_path, threshold)
        _step_ok(5, "Alert Generation",
                 f"{len(alerts)} alerts at threshold={threshold}", time.perf_counter() - t0)
    except Exception as exc:  # noqa: BLE001
        _step_err(5, "Alert Generation", str(exc))
        return 1

    # ── Step 6 — Experiment Tracking ─────────────────────────────────────────
    t0 = time.perf_counter()
    try:
        model_params = model.get_params() if hasattr(model, "get_params") else {}
        run = _step6_track(features_path, scores_path, threshold, model_params)
        metrics = run.get("metrics", {})
        _step_ok(6, "Experiment Tracking",
                 f"Run {run.get('run_id','')}  AUC={metrics.get('auc_roc',0):.4f}  "
                 f"F1={metrics.get('f1_score',0):.4f}",
                 time.perf_counter() - t0)
    except Exception as exc:  # noqa: BLE001
        _step_err(6, "Experiment Tracking", str(exc))
        return 1

    # ── Step 7 — Dashboard ───────────────────────────────────────────────────
    if no_report:
        print(f"  {_YELLOW}⏭{_RESET}  [7/7] Dashboard skipped (--no-report)")
    else:
        t0 = time.perf_counter()
        try:
            dash_path = _step7_report(artifacts_dir)
            _step_ok(7, "Dashboard Report", str(dash_path), time.perf_counter() - t0)
        except Exception as exc:  # noqa: BLE001
            _step_err(7, "Dashboard Report", str(exc))
            return 1

    _sep()
    elapsed = time.perf_counter() - t_global
    print(f"  {_GREEN}{_BOLD}Pipeline completed in {elapsed:.2f}s{_RESET}")
    if not no_report:
        print(f"  Dashboard → {artifacts_dir / 'dashboard.html'}")
    print()
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CyberHealthGuard — end-to-end pipeline orchestrator",
    )
    parser.add_argument(
        "--input", required=True,
        help="Path to the JSONL log file to process",
    )
    parser.add_argument(
        "--threshold", type=float, default=51.0,
        help="Risk score threshold for alert generation (default: 51.0)",
    )
    parser.add_argument(
        "--anomaly-threshold", type=float, default=0.75,
        help="IsolationForest anomaly score threshold (default: 0.75)",
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Skip HTML dashboard generation",
    )
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        parser.error(f"Input file not found: {input_path}")

    return run_pipeline(
        input_path=input_path,
        threshold=args.threshold,
        anomaly_threshold=args.anomaly_threshold,
        no_report=args.no_report,
    )


if __name__ == "__main__":
    raise SystemExit(main())
