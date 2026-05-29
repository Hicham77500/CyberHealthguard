"""Tests for src/features/behavioral_baseline.py — CHG-034"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.features.behavioral_baseline import (
    build_baselines,
    build_peer_groups,
    score_all,
    score_peer_deviation,
    score_user,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(days_ago: float = 0, hour: int = 10) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.replace(hour=hour, minute=0, second=0, microsecond=0).isoformat()


def _event(
    user: str = "u1",
    role: str = "nurse",
    dept: str = "emergency",
    category: str = "user_access",
    etype: str = "login_success",
    days_ago: float = 0,
    hour: int = 10,
    bytes_val: int = 1000,
    severity: int = 1,
) -> dict:
    return {
        "event_id":         f"EVT-{user}-{int(days_ago*100)}-{hour}",
        "event_type":       etype,
        "category":         category,
        "user_id":          user,
        "user_role":        role,
        "department":       dept,
        "timestamp":        _ts(days_ago, hour),
        "source_ip":        "10.0.0.1",
        "bytes_transferred": bytes_val,
        "severity":         severity,
        "status":           "success",
        "is_anomaly":       False,
    }


def _make_history(user: str, role: str, n_days: int = 10, events_per_day: int = 5) -> list[dict]:
    """Generate a stable history for a user over n_days."""
    events = []
    for d in range(1, n_days + 1):
        for h in range(events_per_day):
            events.append(_event(user=user, role=role, days_ago=d, hour=9 + h))
    return events


# ---------------------------------------------------------------------------
# build_baselines
# ---------------------------------------------------------------------------

def test_build_baselines_returns_dict():
    events = _make_history("u1", "nurse", n_days=5)
    baselines = build_baselines(events, lookback_days=30)
    assert isinstance(baselines, dict)


def test_build_baselines_user_present():
    events = _make_history("u1", "nurse", n_days=5)
    baselines = build_baselines(events, lookback_days=30)
    assert "u1" in baselines


def test_build_baselines_computes_avg_events():
    events = _make_history("u1", "nurse", n_days=5, events_per_day=4)
    baselines = build_baselines(events, lookback_days=30)
    b = baselines["u1"]
    # 4 events per day → avg_events_per_day should be close to 4
    assert 3.5 <= b["avg_events_per_day"] <= 4.5


def test_build_baselines_empty():
    assert build_baselines([]) == {}


def test_build_baselines_min_days_skipped():
    # Only 2 days → below _MIN_DAYS_FOR_BASELINE=3 → should be absent
    events = _make_history("u1", "nurse", n_days=2)
    baselines = build_baselines(events, lookback_days=30)
    assert "u1" not in baselines


def test_build_baselines_typical_hours_populated():
    events = _make_history("u1", "nurse", n_days=5)
    baselines = build_baselines(events, lookback_days=30)
    assert len(baselines["u1"]["typical_hours"]) > 0


def test_build_baselines_role_stored():
    events = _make_history("u1", "physician", n_days=5)
    baselines = build_baselines(events, lookback_days=30)
    assert baselines["u1"]["user_role"] == "physician"


def test_build_baselines_multiple_users():
    events = _make_history("u1", "nurse") + _make_history("u2", "physician")
    baselines = build_baselines(events, lookback_days=30)
    assert "u1" in baselines
    assert "u2" in baselines


# ---------------------------------------------------------------------------
# score_user
# ---------------------------------------------------------------------------

def test_score_user_returns_dict():
    history = _make_history("u1", "nurse", n_days=5)
    baselines = build_baselines(history, lookback_days=30)
    current = [_event("u1", days_ago=0)]
    result = score_user("u1", current, baselines["u1"])
    assert "deviation_score" in result
    assert "flags" in result


def test_score_user_no_flags_for_normal_behaviour():
    history = _make_history("u1", "nurse", n_days=7, events_per_day=5)
    baselines = build_baselines(history, lookback_days=30)
    # Current behaviour same as history
    current = [_event("u1", days_ago=0, hour=10) for _ in range(5)]
    result = score_user("u1", current, baselines["u1"])
    # z-scores should be low → no abnormal_event_volume flag
    assert "abnormal_event_volume" not in result["flags"]


def test_score_user_flags_excessive_patient_access():
    history = _make_history("u1", "nurse", n_days=7, events_per_day=3)
    baselines = build_baselines(history, lookback_days=30)
    # Flood the current period with patient_data_access
    current = [
        _event("u1", days_ago=0, category="patient_data_access")
        for _ in range(50)
    ]
    result = score_user("u1", current, baselines["u1"])
    assert "excessive_patient_access" in result["flags"]


def test_score_user_new_active_hours_flagged():
    history = [_event("u1", days_ago=d, hour=9) for d in range(1, 8)]
    baselines = build_baselines(history, lookback_days=30)
    # New hour: 3 AM
    current = [_event("u1", days_ago=0, hour=3)]
    result = score_user("u1", current, baselines["u1"])
    assert "new_active_hours" in result["flags"]


def test_score_user_empty_events():
    history = _make_history("u1", "nurse", n_days=5)
    baselines = build_baselines(history, lookback_days=30)
    result = score_user("u1", [], baselines["u1"])
    assert result["deviation_score"] == 0


def test_score_user_deviation_score_range():
    history = _make_history("u1", "nurse", n_days=5)
    baselines = build_baselines(history, lookback_days=30)
    current = [_event("u1", days_ago=0)]
    result = score_user("u1", current, baselines["u1"])
    assert 0 <= result["deviation_score"] <= 100


# ---------------------------------------------------------------------------
# score_all
# ---------------------------------------------------------------------------

def test_score_all_returns_sorted():
    events = _make_history("u1", "nurse") + _make_history("u2", "physician")
    baselines = build_baselines(events, lookback_days=30)
    results = score_all(events, baselines, evaluation_days=1)
    scores = [r["deviation_score"] for r in results]
    assert scores == sorted(scores, reverse=True)


def test_score_all_empty():
    assert score_all([], {}) == []


def test_score_all_each_user_present():
    events = _make_history("u1", "nurse") + _make_history("u2", "physician")
    baselines = build_baselines(events, lookback_days=30)
    results = score_all(events, baselines, evaluation_days=1)
    user_ids = {r["user_id"] for r in results}
    assert "u1" in user_ids
    assert "u2" in user_ids


# ---------------------------------------------------------------------------
# build_peer_groups
# ---------------------------------------------------------------------------

def test_build_peer_groups_groups_by_role():
    events = (
        _make_history("u1", "nurse")
        + _make_history("u2", "nurse")
        + _make_history("u3", "physician")
        + _make_history("u4", "physician")
    )
    baselines = build_baselines(events, lookback_days=30)
    peer_groups = build_peer_groups(baselines)
    assert "nurse" in peer_groups
    assert "physician" in peer_groups


def test_build_peer_groups_requires_two_members():
    events = _make_history("u1", "nurse", n_days=5)
    baselines = build_baselines(events, lookback_days=30)
    peer_groups = build_peer_groups(baselines)
    # Only one nurse → no peer group for nurse
    assert "nurse" not in peer_groups


def test_build_peer_groups_n_members_correct():
    events = (
        _make_history("u1", "nurse")
        + _make_history("u2", "nurse")
        + _make_history("u3", "nurse")
    )
    baselines = build_baselines(events, lookback_days=30)
    peer_groups = build_peer_groups(baselines)
    assert peer_groups["nurse"]["n_members"] == 3


# ---------------------------------------------------------------------------
# score_peer_deviation
# ---------------------------------------------------------------------------

def test_score_peer_deviation_returns_score():
    events = (
        _make_history("u1", "nurse")
        + _make_history("u2", "nurse")
    )
    baselines = build_baselines(events, lookback_days=30)
    peer_groups = build_peer_groups(baselines)
    result = score_peer_deviation("u1", baselines["u1"], peer_groups["nurse"])
    assert "peer_deviation_score" in result
    assert 0 <= result["peer_deviation_score"] <= 100


def test_score_peer_deviation_empty_peer_group():
    events = _make_history("u1", "nurse", n_days=5)
    baselines = build_baselines(events, lookback_days=30)
    result = score_peer_deviation("u1", baselines["u1"], {})
    assert result["peer_deviation_score"] == 0


def test_score_peer_deviation_outlier_flagged():
    # u1 has 14 events/day, u2 has 2 events/day → u1 is a peer outlier
    events = (
        _make_history("u1", "nurse", n_days=5, events_per_day=14)
        + _make_history("u2", "nurse", n_days=5, events_per_day=2)
    )
    baselines = build_baselines(events, lookback_days=30)
    peer_groups = build_peer_groups(baselines)
    result = score_peer_deviation("u1", baselines["u1"], peer_groups["nurse"])
    # u1 is far above peer average → should be flagged
    assert result["peer_deviation_score"] > 0
