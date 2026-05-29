"""Tests for src/compliance/audit_trail.py — CHG-030"""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from src.compliance.audit_trail import AuditTrail, _hash_entry, _GENESIS_HASH


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def trail(tmp_path):
    return AuditTrail(tmp_path / "audit_trail.jsonl")


# ---------------------------------------------------------------------------
# log()
# ---------------------------------------------------------------------------

def test_log_creates_file(trail):
    trail.log("pipeline_run", "pipeline", "Test run", "artifacts/")
    assert trail._path.exists()


def test_log_entry_structure(trail):
    e = trail.log("pipeline_run", "pipeline", "Test run", "artifacts/")
    assert e["seq"] == 1
    assert e["event_type"] == "pipeline_run"
    assert e["actor"] == "pipeline"
    assert e["action"] == "Test run"
    assert e["object"] == "artifacts/"
    assert "timestamp" in e
    assert "pgssi_control" in e
    assert "entry_hash" in e
    assert "prev_hash" in e


def test_first_entry_genesis_hash(trail):
    e = trail.log("pipeline_run", "pipeline", "First entry")
    assert e["prev_hash"] == _GENESIS_HASH


def test_second_entry_links_first(trail):
    e1 = trail.log("pipeline_run", "pipeline", "First")
    e2 = trail.log("alert_generated", "pipeline", "Second")
    assert e2["prev_hash"] == e1["entry_hash"]


def test_sequential_numbering(trail):
    for i in range(5):
        e = trail.log("pipeline_run", "pipeline", f"Entry {i}")
        assert e["seq"] == i + 1


def test_entry_hash_correct(trail):
    e = trail.log("pipeline_run", "pipeline", "Check hash")
    recomputed = _hash_entry(e)
    assert e["entry_hash"] == recomputed


def test_pgssi_control_mapped(trail):
    e = trail.log("alert_generated", "pipeline", "Alert fired")
    assert "PGSSI-S" in e["pgssi_control"]


def test_metadata_stored(trail):
    meta = {"run_id": "RUN-ABC", "score": 84.0}
    e = trail.log("pipeline_run", "pipeline", "With meta", metadata=meta)
    assert e["metadata"]["run_id"] == "RUN-ABC"


def test_unknown_event_type_allowed(trail):
    e = trail.log("custom_event", "user:alice", "Custom action")
    assert e["event_type"] == "custom_event"


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------

def test_verify_empty_trail_ok(trail):
    ok, errors = trail.verify()
    assert ok
    assert errors == []


def test_verify_intact_chain(trail):
    for i in range(10):
        trail.log("pipeline_run", "pipeline", f"Entry {i}")
    ok, errors = trail.verify()
    assert ok
    assert errors == []


def test_verify_detects_tampering(trail):
    trail.log("pipeline_run", "pipeline", "Entry 1")
    trail.log("pipeline_run", "pipeline", "Entry 2")

    # Tamper with first entry
    lines = trail._path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["action"] = "TAMPERED"
    lines[0] = json.dumps(entry)
    trail._path.write_text("\n".join(lines) + "\n")

    ok, errors = trail.verify()
    assert not ok
    assert len(errors) >= 1


def test_verify_detects_hash_chain_break(trail):
    trail.log("pipeline_run", "pipeline", "Entry 1")
    trail.log("pipeline_run", "pipeline", "Entry 2")

    # Replace prev_hash of second entry with garbage
    lines = trail._path.read_text().splitlines()
    entry2 = json.loads(lines[1])
    entry2["prev_hash"] = "a" * 64
    entry2["entry_hash"] = _hash_entry(entry2)
    lines[1] = json.dumps(entry2)
    trail._path.write_text("\n".join(lines) + "\n")

    ok, errors = trail.verify()
    assert not ok


# ---------------------------------------------------------------------------
# list_entries()
# ---------------------------------------------------------------------------

def test_list_entries_limit(trail):
    for i in range(20):
        trail.log("pipeline_run", "pipeline", f"Entry {i}")
    entries = trail.list_entries(limit=5)
    assert len(entries) == 5


def test_list_entries_filter_by_type(trail):
    trail.log("pipeline_run", "pipeline", "Run")
    trail.log("alert_generated", "pipeline", "Alert")
    trail.log("pipeline_run", "pipeline", "Run 2")
    entries = trail.list_entries(event_type="pipeline_run")
    assert all(e["event_type"] == "pipeline_run" for e in entries)
    assert len(entries) == 2


# ---------------------------------------------------------------------------
# stats()
# ---------------------------------------------------------------------------

def test_stats_total(trail):
    for i in range(7):
        trail.log("pipeline_run", "pipeline", f"Entry {i}")
    s = trail.stats()
    assert s["total_entries"] == 7
    assert s["chain_intact"] is True
    assert s["integrity_errors"] == 0
    assert "pipeline_run" in s["by_event_type"]


def test_stats_empty_trail(trail):
    s = trail.stats()
    assert s["total_entries"] == 0
    assert s["chain_intact"] is True
