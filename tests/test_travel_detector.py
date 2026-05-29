"""Tests for src/detector/travel_detector.py — CHG-032"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.detector.travel_detector import (
    detect,
    summary,
    _detect_impossible_travel,
    _detect_new_ip,
    _detect_off_hours_external,
    _ip_location_bucket,
    _is_internal,
    _is_off_hours,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(offset_seconds: float = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return dt.isoformat()


def _login(user: str, ip: str, offset: float = 0, action: str = "login_success") -> dict:
    return {
        "event_id":   f"EVT-{user}-{ip}-{int(offset)}",
        "event_type": action,
        "action":     action,
        "timestamp":  _ts(offset),
        "user_id":    user,
        "source_ip":  ip,
    }


# ---------------------------------------------------------------------------
# _ip_location_bucket helpers
# ---------------------------------------------------------------------------

def test_internal_10():
    assert _ip_location_bucket("10.0.1.5").startswith("internal:")


def test_internal_172():
    assert _ip_location_bucket("172.16.0.1").startswith("internal:")


def test_internal_192():
    assert _ip_location_bucket("192.168.1.1").startswith("internal:")


def test_external():
    assert _ip_location_bucket("8.8.8.8").startswith("external:")


def test_is_internal_true():
    assert _is_internal("10.1.2.3") is True


def test_is_internal_false():
    assert _is_internal("203.0.113.5") is False


def test_is_off_hours_night():
    ts = "2026-03-09T02:30:00+00:00"
    assert _is_off_hours(ts) is True


def test_is_off_hours_day():
    ts = "2026-03-09T10:00:00+00:00"
    assert _is_off_hours(ts) is False


# ---------------------------------------------------------------------------
# _detect_impossible_travel
# ---------------------------------------------------------------------------

def test_impossible_travel_triggers_different_buckets():
    e1 = _login("u1", "8.8.8.8", offset=600)
    e2 = _login("u1", "93.184.216.34", offset=0)  # different external bucket
    incidents = _detect_impossible_travel([e1, e2], window_seconds=1800)
    assert len(incidents) >= 1
    assert incidents[0]["incident_type"] == "impossible_travel"


def test_impossible_travel_no_trigger_same_location():
    e1 = _login("u1", "10.0.0.1", offset=300)
    e2 = _login("u1", "10.0.0.2", offset=0)  # same bucket (internal:10.0)
    incidents = _detect_impossible_travel([e1, e2], window_seconds=1800)
    assert incidents == []


def test_impossible_travel_no_trigger_beyond_window():
    e1 = _login("u1", "8.8.8.8", offset=7200)  # 2h ago
    e2 = _login("u1", "93.184.216.34", offset=0)
    incidents = _detect_impossible_travel([e1, e2], window_seconds=1800)
    assert incidents == []


def test_impossible_travel_evidence_has_two_entries():
    e1 = _login("u1", "8.8.8.8", offset=600)
    e2 = _login("u1", "93.184.216.34", offset=0)
    incidents = _detect_impossible_travel([e1, e2], window_seconds=1800)
    assert len(incidents[0]["evidence"]) == 2


def test_impossible_travel_risk_score_range():
    e1 = _login("u1", "8.8.8.8", offset=300)
    e2 = _login("u1", "93.184.216.34", offset=0)
    incidents = _detect_impossible_travel([e1, e2], window_seconds=1800)
    assert 0 <= incidents[0]["risk_score"] <= 100


# ---------------------------------------------------------------------------
# _detect_new_ip
# ---------------------------------------------------------------------------

def test_new_ip_triggers_for_unknown_ip():
    events = [_login("u2", "203.0.113.10")]
    incidents = _detect_new_ip(events, lookback_days=30, reference_events=[])
    assert len(incidents) >= 1
    assert incidents[0]["incident_type"] == "new_ip_for_user"


def test_new_ip_no_trigger_for_known_ip():
    old_event = _login("u2", "203.0.113.10", offset=60 * 60 * 24 * 35)  # 35 days ago
    recent = _login("u2", "203.0.113.10", offset=0)
    events = [old_event, recent]
    incidents = _detect_new_ip(events, lookback_days=30, reference_events=[])
    # old IP is in known set, recent login from same IP should not re-trigger
    assert not any(i["evidence"][0]["ip"] == "203.0.113.10" and
                   i["evidence"][0]["event_id"] == recent["event_id"]
                   for i in incidents)


def test_new_ip_internal_lower_risk():
    events = [_login("u3", "10.99.0.5")]
    incidents = _detect_new_ip(events, lookback_days=30, reference_events=[])
    if incidents:
        assert incidents[0]["risk_score"] < 80  # internal IP → lower risk


def test_new_ip_external_high_confidence():
    events = [_login("u4", "1.2.3.4")]
    incidents = _detect_new_ip(events, lookback_days=30, reference_events=[])
    assert incidents[0]["confidence"] == "high"


# ---------------------------------------------------------------------------
# _detect_off_hours_external
# ---------------------------------------------------------------------------

def test_off_hours_external_triggers():
    e = _login("u5", "8.8.8.8")
    e["timestamp"] = "2026-03-09T03:00:00+00:00"
    incidents = _detect_off_hours_external([e])
    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "off_hours_external"


def test_off_hours_internal_no_trigger():
    e = _login("u5", "10.0.0.1")
    e["timestamp"] = "2026-03-09T03:00:00+00:00"
    incidents = _detect_off_hours_external([e])
    assert incidents == []


def test_business_hours_external_no_trigger():
    e = _login("u5", "8.8.8.8")
    e["timestamp"] = "2026-03-09T10:00:00+00:00"
    incidents = _detect_off_hours_external([e])
    assert incidents == []


# ---------------------------------------------------------------------------
# detect() + summary()
# ---------------------------------------------------------------------------

def test_detect_empty():
    assert detect([]) == []


def test_detect_sorted_by_score():
    events = [
        _login("u1", "8.8.8.8", offset=600),
        _login("u1", "93.184.216.34", offset=0),
        _login("u2", "203.0.113.5"),
    ]
    incidents = detect(events, window_seconds=1800, lookback_days=30)
    scores = [i["risk_score"] for i in incidents]
    assert scores == sorted(scores, reverse=True)


def test_summary_empty():
    s = summary([])
    assert s["total"] == 0


def test_summary_counts():
    incidents = [
        {"incident_type": "impossible_travel", "risk_score": 85},
        {"incident_type": "new_ip_for_user", "risk_score": 75},
        {"incident_type": "impossible_travel", "risk_score": 70},
    ]
    s = summary(incidents)
    assert s["total"] == 3
    assert s["by_type"]["impossible_travel"] == 2
    assert s["max_risk_score"] == 85
