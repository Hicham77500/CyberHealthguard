"""Tests for src/features/feature_engineering.py — CHG-028"""
import pandas as pd
from src.features.feature_engineering import (
    engineer_features,
    CATEGORY_RISK,
    ROLE_RISK_SCORE,
    STATUS_RISK,
    FEATURE_COLS,
)


def _make_event(**overrides):
    base = {
        "timestamp": "2026-05-29T02:30:00+00:00",  # 02:30 → is_off_hours=1
        "event_type": "login_success",
        "category": "user_access",
        "severity": 2,
        "user_id": "U-001",
        "user_role": "physician",
        "status": "success",
        "bytes_transferred": 1024,
        "is_anomaly": False,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

def test_output_columns_match_spec():
    df = engineer_features([_make_event()])
    for col in FEATURE_COLS + ["is_anomaly"]:
        assert col in df.columns, f"Missing column: {col}"


def test_no_extra_internal_columns():
    df = engineer_features([_make_event()])
    assert "_user_id" not in df.columns
    assert "_category" not in df.columns
    assert "_event_type" not in df.columns


def test_row_count_matches_input():
    events = [_make_event() for _ in range(10)]
    df = engineer_features(events)
    assert len(df) == 10


# ---------------------------------------------------------------------------
# Temporal features
# ---------------------------------------------------------------------------

def test_off_hours_detected():
    # hour=2 → is_off_hours=1
    df = engineer_features([_make_event(timestamp="2026-05-29T02:00:00+00:00")])
    assert df["is_off_hours"].iloc[0] == 1


def test_on_hours_not_flagged():
    # hour=10 → is_off_hours=0
    df = engineer_features([_make_event(timestamp="2026-05-29T10:00:00+00:00")])
    assert df["is_off_hours"].iloc[0] == 0


def test_hour_boundary_5_still_off():
    df = engineer_features([_make_event(timestamp="2026-05-29T05:30:00+00:00")])
    assert df["is_off_hours"].iloc[0] == 1


def test_hour_6_is_on_hours():
    df = engineer_features([_make_event(timestamp="2026-05-29T06:00:00+00:00")])
    assert df["is_off_hours"].iloc[0] == 0


def test_hour_of_day_range():
    df = engineer_features([_make_event(timestamp="2026-05-29T14:15:00+00:00")])
    assert df["hour_of_day"].iloc[0] == 14


def test_day_of_week():
    # 2026-05-29 is a Friday → weekday()=4
    df = engineer_features([_make_event(timestamp="2026-05-29T10:00:00+00:00")])
    assert df["day_of_week"].iloc[0] == 4


# ---------------------------------------------------------------------------
# Category risk
# ---------------------------------------------------------------------------

def test_patient_data_access_highest_risk():
    df = engineer_features([_make_event(category="patient_data_access")])
    assert df["category_risk"].iloc[0] == 4


def test_user_access_lowest_risk():
    df = engineer_features([_make_event(category="user_access")])
    assert df["category_risk"].iloc[0] == 1


# ---------------------------------------------------------------------------
# Role risk
# ---------------------------------------------------------------------------

def test_it_admin_highest_role_risk():
    df = engineer_features([_make_event(user_role="it_admin")])
    assert df["role_risk_score"].iloc[0] == 4


def test_receptionist_lowest_role_risk():
    df = engineer_features([_make_event(user_role="receptionist")])
    assert df["role_risk_score"].iloc[0] == 1


# ---------------------------------------------------------------------------
# Status risk
# ---------------------------------------------------------------------------

def test_alert_highest_status_risk():
    df = engineer_features([_make_event(status="alert")])
    assert df["status_risk"].iloc[0] == 5


def test_success_zero_status_risk():
    df = engineer_features([_make_event(status="success")])
    assert df["status_risk"].iloc[0] == 0


# ---------------------------------------------------------------------------
# Bytes z-score
# ---------------------------------------------------------------------------

def test_zscore_mean_event_near_zero():
    # If all events have same bytes, z-score should be 0
    events = [_make_event(bytes_transferred=1000) for _ in range(10)]
    df = engineer_features(events)
    assert df["bytes_zscore"].abs().max() == 0.0


def test_zscore_outlier_is_positive():
    events = [_make_event(bytes_transferred=100) for _ in range(9)]
    events.append(_make_event(bytes_transferred=100_000))  # outlier
    df = engineer_features(events)
    assert df["bytes_zscore"].iloc[-1] > 0  # last after sort? No — order preserved
    assert df["bytes_zscore"].max() > 1.0


# ---------------------------------------------------------------------------
# Behavioral aggregates
# ---------------------------------------------------------------------------

def test_user_event_count():
    events = [_make_event(user_id="U-001") for _ in range(5)]
    events += [_make_event(user_id="U-002") for _ in range(3)]
    df = engineer_features(events)
    u1_counts = df["user_event_count"].iloc[:5]
    assert (u1_counts == 5).all()


def test_user_patient_access_count():
    events = [
        _make_event(user_id="U-001", category="patient_data_access"),
        _make_event(user_id="U-001", category="patient_data_access"),
        _make_event(user_id="U-001", category="user_access"),
    ]
    df = engineer_features(events)
    assert df["user_patient_access_count"].iloc[0] == 2
    assert df["user_patient_access_count"].iloc[2] == 2  # still same user


def test_user_failed_login_count():
    events = [
        _make_event(user_id="U-001", event_type="login_failure"),
        _make_event(user_id="U-001", event_type="login_failure"),
        _make_event(user_id="U-001", event_type="login_success"),
    ]
    df = engineer_features(events)
    assert df["user_failed_login_count"].iloc[0] == 2
