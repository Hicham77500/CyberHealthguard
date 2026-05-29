"""Tests for src/scoring/risk_scoring.py — CHG-028"""
import pandas as pd
from src.scoring.risk_scoring import compute_scores, risk_level, summary


def _make_df(**kwargs):
    defaults = {
        "is_off_hours": 0,
        "severity": 1,
        "category_risk": 1,
        "role_risk_score": 1,
        "status_risk": 0,
        "bytes_zscore": 0.0,
        "is_anomaly": 0,
    }
    defaults.update(kwargs)
    return pd.DataFrame([defaults])


# ---------------------------------------------------------------------------
# risk_level function
# ---------------------------------------------------------------------------

def test_risk_level_critical():
    assert risk_level(81) == "Critical"
    assert risk_level(100) == "Critical"


def test_risk_level_high():
    assert risk_level(51) == "High"
    assert risk_level(80) == "High"


def test_risk_level_medium():
    assert risk_level(21) == "Medium"
    assert risk_level(50) == "Medium"


def test_risk_level_low():
    assert risk_level(0) == "Low"
    assert risk_level(20) == "Low"


# ---------------------------------------------------------------------------
# compute_scores
# ---------------------------------------------------------------------------

def test_output_columns_added():
    df = compute_scores(_make_df())
    assert "risk_score" in df.columns
    assert "risk_level" in df.columns


def test_min_score_all_low_features():
    df = compute_scores(_make_df(
        is_off_hours=0, severity=1, category_risk=1,
        role_risk_score=1, status_risk=0, bytes_zscore=0.0,
    ))
    assert df["risk_score"].iloc[0] == 0.0


def test_off_hours_adds_20():
    df_on  = compute_scores(_make_df(is_off_hours=0))
    df_off = compute_scores(_make_df(is_off_hours=1))
    diff = df_off["risk_score"].iloc[0] - df_on["risk_score"].iloc[0]
    assert abs(diff - 20.0) < 0.01


def test_max_severity_adds_20():
    df_min = compute_scores(_make_df(severity=1))
    df_max = compute_scores(_make_df(severity=5))
    diff = df_max["risk_score"].iloc[0] - df_min["risk_score"].iloc[0]
    assert abs(diff - 20.0) < 0.01


def test_score_capped_at_100():
    df = compute_scores(_make_df(
        is_off_hours=1, severity=5, category_risk=4,
        role_risk_score=4, status_risk=5, bytes_zscore=5.0,
    ))
    assert df["risk_score"].iloc[0] <= 100.0


def test_score_non_negative():
    df = compute_scores(_make_df(bytes_zscore=-100.0))
    assert df["risk_score"].iloc[0] >= 0.0


def test_all_max_factors_is_critical():
    df = compute_scores(_make_df(
        is_off_hours=1, severity=5, category_risk=4,
        role_risk_score=4, status_risk=5, bytes_zscore=3.0,
    ))
    assert df["risk_level"].iloc[0] == "Critical"


def test_all_min_factors_is_low():
    df = compute_scores(_make_df())
    assert df["risk_level"].iloc[0] == "Low"


def test_original_df_not_mutated():
    original = _make_df()
    original_cols = set(original.columns)
    compute_scores(original)
    assert set(original.columns) == original_cols


# ---------------------------------------------------------------------------
# summary function
# ---------------------------------------------------------------------------

def test_summary_totals():
    events = [
        {"is_off_hours": 1, "severity": 5, "category_risk": 4, "role_risk_score": 4,
         "status_risk": 5, "bytes_zscore": 3.0, "is_anomaly": 1},   # Critical
        {"is_off_hours": 0, "severity": 1, "category_risk": 1, "role_risk_score": 1,
         "status_risk": 0, "bytes_zscore": 0.0, "is_anomaly": 0},   # Low
    ]
    df = compute_scores(pd.DataFrame(events))
    stats = summary(df)
    assert stats["total"] == 2
    assert stats["Critical"] == 1
    assert stats["Low"] == 1
    assert "mean_score" in stats
    assert "max_score" in stats


# ---------------------------------------------------------------------------
# Graceful degradation on missing columns
# ---------------------------------------------------------------------------

def test_missing_column_defaults_to_zero():
    df = pd.DataFrame([{"severity": 3, "is_anomaly": 0}])
    scored = compute_scores(df)
    assert "risk_score" in scored.columns
    assert scored["risk_score"].iloc[0] >= 0
