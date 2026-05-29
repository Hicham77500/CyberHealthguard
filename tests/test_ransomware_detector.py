"""Tests for src/detector/ransomware_detector.py — CHG-031"""
from __future__ import annotations

import json
import pytest
from datetime import datetime, timedelta, timezone

from src.detector.ransomware_detector import (
    detect,
    summary,
    load_events,
    _detect_mass_file_modification,
    _detect_backup_tampering,
    _detect_ioc_matches,
    _detect_mass_exfiltration_burst,
    _detect_privilege_then_filesystem,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(offset_seconds: float = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return dt.isoformat()


def _fs_event(offset: float = 0, etype: str = "file_created") -> dict:
    return {
        "event_id":   f"EVT-{etype}-{int(offset)}",
        "event_type": etype,
        "action":     "filesystem",
        "timestamp":  _ts(offset),
        "user_id":    "user-001",
    }


def _exfil_event(offset: float = 0) -> dict:
    return {
        "event_id":   f"EVT-exfil-{int(offset)}",
        "event_type": "large_data_transfer",
        "action":     "data_transfer",
        "timestamp":  _ts(offset),
        "user_id":    "user-001",
    }


def _priv_event(offset: float = 0) -> dict:
    return {
        "event_id":   f"EVT-priv-{int(offset)}",
        "event_type": "privilege_escalation_attempt",
        "action":     "privilege_change",
        "timestamp":  _ts(offset),
        "user_id":    "user-001",
    }


# ---------------------------------------------------------------------------
# _detect_mass_file_modification
# ---------------------------------------------------------------------------

def test_mass_file_triggers_above_threshold():
    events = [_fs_event(i * 5) for i in range(25)]  # 25 events in 120s window
    incidents = _detect_mass_file_modification(events, window_seconds=300, threshold=20)
    assert len(incidents) >= 1
    assert incidents[0]["incident_type"] == "mass_file_modification"


def test_mass_file_no_trigger_below_threshold():
    events = [_fs_event(i * 20) for i in range(5)]  # only 5 events
    incidents = _detect_mass_file_modification(events, window_seconds=300, threshold=20)
    assert incidents == []


def test_mass_file_risk_score_range():
    events = [_fs_event(i * 2) for i in range(30)]
    incidents = _detect_mass_file_modification(events, window_seconds=300, threshold=20)
    for inc in incidents:
        assert 0 <= inc["risk_score"] <= 100


def test_mass_file_affected_events_not_empty():
    events = [_fs_event(i * 5) for i in range(25)]
    incidents = _detect_mass_file_modification(events, window_seconds=300, threshold=20)
    assert len(incidents[0]["affected_events"]) >= 20


# ---------------------------------------------------------------------------
# _detect_backup_tampering
# ---------------------------------------------------------------------------

def test_backup_tampering_detects_backup_deletion():
    events = [{
        "event_id":   "EVT-bak-01",
        "event_type": "file_deleted",
        "action":     "filesystem",
        "timestamp":  _ts(),
        "user_id":    "user-001",
        "metadata":   {"notes": "backup archive deleted"},
    }]
    incidents = _detect_backup_tampering(events)
    assert len(incidents) == 1
    assert incidents[0]["incident_type"] == "backup_tampering"


def test_backup_tampering_ignores_non_backup():
    events = [_fs_event()]
    incidents = _detect_backup_tampering(events)
    assert incidents == []


def test_backup_tampering_risk_high():
    events = [{
        "event_id":   "EVT-bak-02",
        "event_type": "file_deleted",
        "action":     "filesystem",
        "timestamp":  _ts(),
        "user_id":    "user-001",
        "metadata":   {"notes": "veeam snapshot removed"},
    }]
    incidents = _detect_backup_tampering(events)
    assert incidents[0]["risk_score"] >= 70


# ---------------------------------------------------------------------------
# _detect_ioc_matches
# ---------------------------------------------------------------------------

def test_ioc_match_lockbit():
    events = [{
        "event_id":  "EVT-ioc-01",
        "timestamp": _ts(),
        "user_id":   "user-001",
        "metadata":  {"notes": "lockbit file dropped"},
    }]
    incidents = _detect_ioc_matches(events)
    assert len(incidents) == 1
    assert "LockBit" in incidents[0]["ioc_matched"]
    assert incidents[0]["confidence"] == "high"


def test_ioc_match_no_match():
    incidents = _detect_ioc_matches([_fs_event()])
    assert incidents == []


def test_ioc_multiple_campaigns():
    events = [
        {"event_id": "e1", "timestamp": _ts(), "metadata": {"notes": "lockbit dropper"}},
        {"event_id": "e2", "timestamp": _ts(), "metadata": {"notes": "rhysida_ransom note found"}},
    ]
    incidents = _detect_ioc_matches(events)
    campaign_names = [i["ioc_matched"][0] for i in incidents]
    assert "LockBit" in campaign_names
    assert "Rhysida" in campaign_names


# ---------------------------------------------------------------------------
# _detect_mass_exfiltration_burst
# ---------------------------------------------------------------------------

def test_exfil_burst_triggers():
    events = [_exfil_event(i * 10) for i in range(8)]
    incidents = _detect_mass_exfiltration_burst(events, window_seconds=300, threshold=5)
    assert len(incidents) >= 1
    assert incidents[0]["incident_type"] == "mass_exfiltration_burst"


def test_exfil_burst_no_trigger():
    events = [_exfil_event(i * 120) for i in range(3)]  # spread out
    incidents = _detect_mass_exfiltration_burst(events, window_seconds=300, threshold=5)
    assert incidents == []


# ---------------------------------------------------------------------------
# _detect_privilege_then_filesystem
# ---------------------------------------------------------------------------

def test_priv_then_fs_triggers():
    events = [_priv_event(600)] + [_fs_event(600 - i * 60) for i in range(5)]
    incidents = _detect_privilege_then_filesystem(events, grace_seconds=600)
    assert len(incidents) >= 1
    assert incidents[0]["incident_type"] == "privilege_then_filesystem"


def test_priv_then_fs_no_trigger_if_no_priv():
    events = [_fs_event(i * 10) for i in range(10)]
    incidents = _detect_privilege_then_filesystem(events, grace_seconds=600)
    assert incidents == []


# ---------------------------------------------------------------------------
# detect() + summary()
# ---------------------------------------------------------------------------

def test_detect_returns_sorted_by_score():
    events = (
        [_fs_event(i * 5) for i in range(30)]
        + [_exfil_event(i * 10) for i in range(10)]
    )
    incidents = detect(events, window_seconds=300, mass_file_threshold=20, exfil_threshold=5)
    scores = [i["risk_score"] for i in incidents]
    assert scores == sorted(scores, reverse=True)


def test_detect_empty_events():
    assert detect([]) == []


def test_summary_empty():
    s = summary([])
    assert s["total"] == 0


def test_summary_counts():
    incidents = [
        {"incident_type": "mass_file_modification", "risk_score": 70, "confidence": "medium"},
        {"incident_type": "ioc_match", "risk_score": 90, "confidence": "high"},
        {"incident_type": "ioc_match", "risk_score": 85, "confidence": "high"},
    ]
    s = summary(incidents)
    assert s["total"] == 3
    assert s["by_type"]["ioc_match"] == 2
    assert s["max_risk_score"] == 90
    assert s["high_confidence"] == 2


def test_load_events(tmp_path):
    events = [{"event_id": f"E{i}", "timestamp": _ts(i)} for i in range(5)]
    p = tmp_path / "test.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events))
    loaded = load_events(p)
    assert len(loaded) == 5
