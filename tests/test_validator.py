"""Tests for src/validator/dataset_validator.py — CHG-028"""
import json
import pytest
from src.validator.dataset_validator import _validate_event, validate_file

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_event(**overrides):
    base = {
        "event_id": "abc123def456",
        "timestamp": "2026-05-29T12:00:00+00:00",
        "event_type": "login_success",
        "category": "user_access",
        "severity": 2,
        "user_id": "P-EME-01",
        "user_role": "physician",
        "source_ip": "10.1.2.3",
        "destination_ip": "192.168.1.4",
        "device_id": "DEV-0001",
        "department": "emergency",
        "action": "user_login",
        "status": "success",
        "bytes_transferred": 1024,
        "is_anomaly": False,
        "metadata": {"application": "EHR"},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Valid event
# ---------------------------------------------------------------------------

def test_valid_event_no_errors():
    errors, warnings = _validate_event(_make_event(), 1, set())
    assert errors == []


# ---------------------------------------------------------------------------
# Required field checks
# ---------------------------------------------------------------------------

def test_missing_required_field():
    event = _make_event()
    del event["event_id"]
    errors, _ = _validate_event(event, 1, set())
    assert any("event_id" in e for e in errors)


def test_wrong_type_severity():
    errors, _ = _validate_event(_make_event(severity="high"), 1, set())
    assert any("severity" in e for e in errors)


def test_wrong_type_is_anomaly():
    # is_anomaly must be bool, not int
    errors, _ = _validate_event(_make_event(is_anomaly=1), 1, set())
    assert any("is_anomaly" in e for e in errors)


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

def test_invalid_timestamp():
    errors, _ = _validate_event(_make_event(timestamp="not-a-date"), 1, set())
    assert any("timestamp" in e for e in errors)


def test_valid_timestamp_utc_z():
    # Z suffix is handled
    errors, _ = _validate_event(_make_event(timestamp="2026-05-29T12:00:00Z"), 1, set())
    assert not any("timestamp" in e for e in errors)


# ---------------------------------------------------------------------------
# Category
# ---------------------------------------------------------------------------

def test_unknown_category():
    errors, _ = _validate_event(_make_event(category="unknown_cat"), 1, set())
    assert any("category" in e for e in errors)


def test_valid_categories():
    for cat in ("user_access", "patient_data_access", "network_activity", "system_event"):
        errors, _ = _validate_event(_make_event(category=cat), 1, set())
        assert not any("category" in e for e in errors), f"Unexpected error for category={cat}"


# ---------------------------------------------------------------------------
# Severity range
# ---------------------------------------------------------------------------

def test_severity_out_of_range_low():
    errors, _ = _validate_event(_make_event(severity=0), 1, set())
    assert any("severity" in e for e in errors)


def test_severity_out_of_range_high():
    errors, _ = _validate_event(_make_event(severity=6), 1, set())
    assert any("severity" in e for e in errors)


def test_severity_boundary_valid():
    for s in (1, 3, 5):
        errors, _ = _validate_event(_make_event(severity=s), 1, set())
        assert not any("severity" in e for e in errors)


# ---------------------------------------------------------------------------
# bytes_transferred
# ---------------------------------------------------------------------------

def test_negative_bytes():
    errors, _ = _validate_event(_make_event(bytes_transferred=-1), 1, set())
    assert any("bytes_transferred" in e for e in errors)


# ---------------------------------------------------------------------------
# Duplicate event_id
# ---------------------------------------------------------------------------

def test_duplicate_event_id():
    seen = {"abc123def456"}
    errors, _ = _validate_event(_make_event(), 2, seen)
    assert any("duplicate" in e.lower() for e in errors)


def test_no_duplicate_on_first_occurrence():
    seen: set = set()
    errors, _ = _validate_event(_make_event(), 1, seen)
    assert not any("duplicate" in e.lower() for e in errors)
    assert "abc123def456" in seen


# ---------------------------------------------------------------------------
# IP warnings (not errors)
# ---------------------------------------------------------------------------

def test_invalid_ip_raises_warning_not_error():
    errors, warnings = _validate_event(_make_event(source_ip="not-an-ip"), 1, set())
    assert not any("source_ip" in e for e in errors)
    assert any("source_ip" in w for w in warnings)


# ---------------------------------------------------------------------------
# File-level validation (uses tmp_path)
# ---------------------------------------------------------------------------

def test_validate_file_valid(tmp_path):
    f = tmp_path / "logs.jsonl"
    event = _make_event()
    f.write_text(json.dumps(event) + "\n")
    report = validate_file(f)
    assert report["error_count"] == 0
    assert report["total"] == 1


def test_validate_file_bad_json(tmp_path):
    f = tmp_path / "logs.jsonl"
    f.write_text("{not valid json}\n")
    report = validate_file(f)
    assert report["error_count"] > 0


def test_validate_file_duplicate_ids(tmp_path):
    f = tmp_path / "logs.jsonl"
    event = _make_event()
    f.write_text(json.dumps(event) + "\n" + json.dumps(event) + "\n")
    report = validate_file(f)
    assert report["error_count"] > 0
