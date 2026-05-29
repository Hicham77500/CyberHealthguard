"""Tests for src/alerts/alert_manager.py — CHG-028"""
import pandas as pd
from src.alerts.alert_manager import _infer_alert_type, generate_alerts


def _make_scored_row(**kwargs):
    defaults = {
        "is_off_hours": 0,
        "severity": 2,
        "category_risk": 1,
        "role_risk_score": 1,
        "status_risk": 0,
        "bytes_zscore": 0.0,
        "user_event_count": 10,
        "user_patient_access_count": 0,
        "user_failed_login_count": 0,
        "risk_score": 30.0,
        "risk_level": "Medium",
        "is_anomaly": 0,
    }
    defaults.update(kwargs)
    return defaults


def _make_df(*rows):
    return pd.DataFrame([_make_scored_row(**r) for r in rows])


# ---------------------------------------------------------------------------
# _infer_alert_type
# ---------------------------------------------------------------------------

def test_off_hours_patient_access():
    row = pd.Series(_make_scored_row(is_off_hours=1, category_risk=4))
    assert _infer_alert_type(row) == "off_hours_patient_access"


def test_mass_data_exfiltration():
    row = pd.Series(_make_scored_row(bytes_zscore=2.5, category_risk=4, is_off_hours=0))
    assert _infer_alert_type(row) == "mass_data_exfiltration"


def test_privilege_abuse():
    row = pd.Series(_make_scored_row(role_risk_score=4, status_risk=3, bytes_zscore=0.0))
    assert _infer_alert_type(row) == "privilege_abuse"


def test_suspicious_network():
    row = pd.Series(_make_scored_row(category_risk=3, status_risk=4, bytes_zscore=0.0))
    assert _infer_alert_type(row) == "suspicious_network_activity"


def test_repeated_login_failure():
    row = pd.Series(_make_scored_row(user_failed_login_count=5))
    assert _infer_alert_type(row) == "repeated_login_failure"


def test_fallback_anomalous_activity():
    row = pd.Series(_make_scored_row())
    assert _infer_alert_type(row) == "anomalous_activity"


def test_off_hours_takes_priority_over_exfiltration():
    # off_hours_patient_access is higher priority than mass_data_exfiltration
    row = pd.Series(_make_scored_row(is_off_hours=1, category_risk=4, bytes_zscore=3.0))
    assert _infer_alert_type(row) == "off_hours_patient_access"


# ---------------------------------------------------------------------------
# generate_alerts
# ---------------------------------------------------------------------------

def test_no_alerts_below_threshold():
    df = _make_df({"risk_score": 10.0}, {"risk_score": 49.9})
    alerts = generate_alerts(df, threshold=51.0)
    assert alerts == []


def test_alerts_generated_above_threshold():
    df = _make_df({"risk_score": 75.0, "risk_level": "High"})
    alerts = generate_alerts(df, threshold=51.0)
    assert len(alerts) == 1


def test_alert_sorted_by_score_descending():
    df = _make_df(
        {"risk_score": 60.0, "risk_level": "High"},
        {"risk_score": 85.0, "risk_level": "Critical"},
        {"risk_score": 70.0, "risk_level": "High"},
    )
    alerts = generate_alerts(df, threshold=51.0)
    scores = [a["risk_score"] for a in alerts]
    assert scores == sorted(scores, reverse=True)


def test_alert_structure():
    df = _make_df({"risk_score": 80.0, "risk_level": "High"})
    alerts = generate_alerts(df, threshold=51.0)
    a = alerts[0]
    assert "alert_id" in a
    assert "timestamp" in a
    assert "severity" in a
    assert "alert_type" in a
    assert "risk_score" in a
    assert "details" in a


def test_alert_id_prefix():
    df = _make_df({"risk_score": 80.0, "risk_level": "High"})
    alerts = generate_alerts(df, threshold=51.0)
    assert alerts[0]["alert_id"].startswith("ALT-")


def test_threshold_zero_includes_all():
    df = _make_df({"risk_score": 0.0}, {"risk_score": 50.0}, {"risk_score": 99.0})
    alerts = generate_alerts(df, threshold=0.0)
    assert len(alerts) == 3


def test_raises_without_risk_score_column():
    df = pd.DataFrame([{"severity": 3}])
    with pytest.raises(ValueError, match="risk_score"):
        generate_alerts(df, threshold=51.0)


import pytest
