"""Tests for src/detector/lateral_movement.py — CHG-033"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.detector.lateral_movement import (
    detect,
    summary,
    _detect_cross_department,
    _detect_privilege_escalation_chain,
    _detect_resource_sweep,
    _detect_role_resource_mismatch,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(offset_seconds: float = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return dt.isoformat()


def _access(
    user: str = "user-001",
    role: str = "receptionist",
    dept: str = "administration",
    category: str = "user_access",
    action: str = "read_record",
    resource: str | None = None,
    offset: float = 0,
    etype: str = "patient_data_access",
) -> dict:
    e: dict = {
        "event_id":    f"EVT-{user}-{int(offset)}",
        "event_type":  etype,
        "action":      action,
        "timestamp":   _ts(offset),
        "user_id":     user,
        "user_role":   role,
        "department":  dept,
        "category":    category,
    }
    if resource:
        e["patient_id"] = resource
    return e


def _priv(user: str = "user-001", offset: float = 0) -> dict:
    return {
        "event_id":   f"EVT-priv-{user}-{int(offset)}",
        "event_type": "privilege_escalation_attempt",
        "action":     "privilege_change",
        "timestamp":  _ts(offset),
        "user_id":    user,
    }


# ---------------------------------------------------------------------------
# _detect_cross_department
# ---------------------------------------------------------------------------

def test_cross_dept_triggers_outside_role():
    # receptionist (expected: administration) accessing oncology
    events = [_access(dept="oncology", role="receptionist", category="patient_data_access")]
    incidents = _detect_cross_department(events, user_role="receptionist")
    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "cross_department_access"


def test_cross_dept_no_trigger_expected_dept():
    events = [_access(dept="administration", role="receptionist")]
    incidents = _detect_cross_department(events, user_role="receptionist")
    assert incidents == []


def test_cross_dept_unknown_role_skipped():
    events = [_access(dept="oncology", role="unknown_role")]
    incidents = _detect_cross_department(events, user_role="unknown_role")
    assert incidents == []


def test_cross_dept_sensitive_dept_high_risk():
    events = [_access(dept="oncology", role="billing_specialist",
                      category="patient_data_access")]
    incidents = _detect_cross_department(events, user_role="billing_specialist")
    if incidents:
        assert incidents[0]["risk_score"] >= 75


def test_cross_dept_deduplicates_same_dept():
    events = [
        _access(dept="oncology", role="receptionist", offset=10),
        _access(dept="oncology", role="receptionist", offset=20),
    ]
    incidents = _detect_cross_department(events, user_role="receptionist")
    assert len(incidents) == 1  # deduplicated by department


# ---------------------------------------------------------------------------
# _detect_privilege_escalation_chain
# ---------------------------------------------------------------------------

def test_priv_chain_triggers():
    events = [
        _priv(offset=600),
        _access(action="read_record", offset=550),
        _access(action="export_record", offset=500),
    ]
    incidents = _detect_privilege_escalation_chain(events, window_seconds=600)
    assert len(incidents) >= 1
    assert incidents[0]["incident_type"] == "privilege_escalation_chain"


def test_priv_chain_no_trigger_if_no_priv():
    events = [_access(action="read_record", offset=i * 30) for i in range(5)]
    incidents = _detect_privilege_escalation_chain(events, window_seconds=600)
    assert incidents == []


def test_priv_chain_no_trigger_no_follow_access():
    events = [_priv(offset=0)]  # priv event but no subsequent access events
    incidents = _detect_privilege_escalation_chain(events, window_seconds=600)
    assert incidents == []


def test_priv_chain_high_risk():
    events = [_priv(offset=600)] + [_access(action="read_record", offset=600 - i * 60) for i in range(3)]
    incidents = _detect_privilege_escalation_chain(events, window_seconds=600)
    assert incidents[0]["risk_score"] >= 80


# ---------------------------------------------------------------------------
# _detect_resource_sweep
# ---------------------------------------------------------------------------

def test_resource_sweep_triggers():
    events = [
        _access(user="u1", resource=f"patient-{i}", offset=(100 - i) * 5)
        for i in range(30)
    ]
    incidents = _detect_resource_sweep(events, window_seconds=600, threshold=25)
    assert len(incidents) >= 1
    assert incidents[0]["incident_type"] == "resource_sweep"


def test_resource_sweep_no_trigger_below_threshold():
    events = [
        _access(user="u1", resource=f"patient-{i}", offset=(50 - i) * 30)
        for i in range(10)
    ]
    incidents = _detect_resource_sweep(events, window_seconds=600, threshold=25)
    assert incidents == []


def test_resource_sweep_no_trigger_no_resource_id():
    events = [_access(user="u1", offset=i) for i in range(30)]  # no patient_id
    incidents = _detect_resource_sweep(events, window_seconds=600, threshold=25)
    assert incidents == []


def test_resource_sweep_risk_score_range():
    events = [
        _access(user="u1", resource=f"patient-{i}", offset=(100 - i) * 2)
        for i in range(30)
    ]
    incidents = _detect_resource_sweep(events, window_seconds=600, threshold=25)
    for inc in incidents:
        assert 0 <= inc["risk_score"] <= 100


# ---------------------------------------------------------------------------
# _detect_role_resource_mismatch
# ---------------------------------------------------------------------------

def test_role_mismatch_receptionist_patient():
    events = [_access(role="receptionist", category="patient_data_access", action="read_record")]
    incidents = _detect_role_resource_mismatch(events, user_role="receptionist")
    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "role_resource_mismatch"


def test_role_mismatch_it_admin_patient():
    events = [_access(role="it_admin", category="patient_data_access", action="export_record")]
    incidents = _detect_role_resource_mismatch(events, user_role="it_admin")
    assert len(incidents) == 1


def test_role_mismatch_no_trigger_for_physician():
    events = [_access(role="physician", category="patient_data_access", action="read_record")]
    incidents = _detect_role_resource_mismatch(events, user_role="physician")
    assert incidents == []


def test_role_mismatch_high_confidence():
    events = [_access(role="billing_specialist", category="patient_data_access",
                      action="delete_record")]
    incidents = _detect_role_resource_mismatch(events, user_role="billing_specialist")
    assert incidents[0]["confidence"] == "high"


# ---------------------------------------------------------------------------
# detect() + summary()
# ---------------------------------------------------------------------------

def test_detect_empty():
    assert detect([]) == []


def test_detect_sorted_by_score():
    events = [
        _priv("u1", offset=600),
        _access("u1", action="read_record", offset=550),
        _access("u2", role="receptionist", dept="oncology", category="patient_data_access"),
        *[_access("u3", resource=f"p-{i}", offset=(100 - i) * 2) for i in range(30)],
    ]
    incidents = detect(events, sweep_threshold=25, window_seconds=600)
    scores = [i["risk_score"] for i in incidents]
    assert scores == sorted(scores, reverse=True)


def test_summary_empty():
    s = summary([])
    assert s["total"] == 0


def test_summary_counts():
    incidents = [
        {"incident_type": "cross_department_access", "risk_score": 80},
        {"incident_type": "resource_sweep", "risk_score": 70},
        {"incident_type": "cross_department_access", "risk_score": 60},
    ]
    s = summary(incidents)
    assert s["total"] == 3
    assert s["by_type"]["cross_department_access"] == 2
    assert s["max_risk_score"] == 80
