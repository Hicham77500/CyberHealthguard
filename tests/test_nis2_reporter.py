"""Tests for src/compliance/nis2_reporter.py — CHG-029"""
from __future__ import annotations

import json
import pytest
from pathlib import Path

from src.compliance.nis2_reporter import (
    build_report,
    sign_report,
    generate_html_report,
    generate_report,
    _detect_affected_data,
    _pgssi_controls,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_alert(alert_type: str = "anomalous_activity", severity: str = "High",
                score: float = 65.0) -> dict:
    return {
        "alert_id":   f"ALT-{alert_type[:4].upper()}",
        "timestamp":  "2026-05-29T10:00:00+00:00",
        "severity":   severity,
        "alert_type": alert_type,
        "risk_score": score,
        "details":    {},
    }


@pytest.fixture()
def critical_alerts():
    return [_make_alert("off_hours_patient_access", "Critical", 84.0),
            _make_alert("mass_data_exfiltration", "High", 72.0)]


@pytest.fixture()
def single_alert():
    return [_make_alert()]


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------

def test_report_has_required_nis2_fields(critical_alerts):
    r = build_report(critical_alerts)
    assert "incident_id" in r
    assert "organisation" in r
    assert "incident" in r
    assert "affected_data" in r
    assert "nis2_deadlines" in r
    assert "containment_measures" in r
    assert "evidence" in r
    assert "integrity" in r


def test_incident_id_prefix(single_alert):
    r = build_report(single_alert)
    assert r["incident_id"].startswith("INC-")


def test_critical_alert_triggers_significant(critical_alerts):
    r = build_report(critical_alerts)
    assert r["incident"]["nis2_severity"] == "Significant"


def test_low_alerts_non_significant():
    alerts = [_make_alert("anomalous_activity", "Medium", 35.0) for _ in range(3)]
    r = build_report(alerts)
    assert r["incident"]["nis2_severity"] == "Non-significant"


def test_alert_counts(critical_alerts):
    r = build_report(critical_alerts)
    assert r["incident"]["total_alerts"] == 2
    assert r["incident"]["critical_count"] == 1
    assert r["incident"]["high_count"] == 1


def test_max_risk_score(critical_alerts):
    r = build_report(critical_alerts)
    assert r["incident"]["max_risk_score"] == 84.0


def test_organisation_defaults(single_alert):
    r = build_report(single_alert)
    assert "contact_email" in r["organisation"]
    assert "notify_to" in r["organisation"]
    assert len(r["organisation"]["notify_to"]) >= 2


def test_organisation_custom(single_alert):
    r = build_report(single_alert, org_name="CHU Test", contact_email="rssi@chu.fr")
    assert r["organisation"]["name"] == "CHU Test"
    assert r["organisation"]["contact_email"] == "rssi@chu.fr"


def test_evidence_max_5(critical_alerts):
    alerts = [_make_alert() for _ in range(10)]
    r = build_report(alerts)
    assert len(r["evidence"]) <= 5


def test_evidence_sorted_by_score_desc():
    alerts = [
        _make_alert(score=50.0),
        _make_alert(score=90.0),
        _make_alert(score=70.0),
    ]
    r = build_report(alerts)
    scores = [e["risk_score"] for e in r["evidence"]]
    assert scores == sorted(scores, reverse=True)


def test_nis2_deadlines_present(single_alert):
    r = build_report(single_alert)
    assert "early_warning_deadline" in r["nis2_deadlines"]
    assert "initial_report_deadline" in r["nis2_deadlines"]


def test_empty_alerts_raises():
    with pytest.raises(ValueError):
        build_report([])


def test_pipeline_run_id(single_alert):
    r = build_report(single_alert, pipeline_run_id="RUN-ABCD1234")
    assert r["incident"]["pipeline_run_id"] == "RUN-ABCD1234"


# ---------------------------------------------------------------------------
# sign_report
# ---------------------------------------------------------------------------

def test_sign_adds_sha256(single_alert):
    r = sign_report(build_report(single_alert))
    assert len(r["integrity"]["sha256"]) == 64


def test_sign_is_deterministic(single_alert):
    r = build_report(single_alert)
    r["generated_at"] = "2026-05-29T12:00:00+00:00"  # freeze timestamp
    signed1 = sign_report(dict(r))
    signed2 = sign_report(dict(r))
    assert signed1["integrity"]["sha256"] == signed2["integrity"]["sha256"]


# ---------------------------------------------------------------------------
# _detect_affected_data / _pgssi_controls
# ---------------------------------------------------------------------------

def test_detect_patient_data():
    alerts = [_make_alert("off_hours_patient_access")]
    cats = _detect_affected_data(alerts)
    assert any("santé" in c.lower() or "DMP" in c for c in cats)


def test_pgssi_controls_mapped(critical_alerts):
    controls = _pgssi_controls(critical_alerts)
    assert len(controls) >= 1
    assert all("PGSSI-S" in c for c in controls)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def test_html_contains_incident_id(single_alert):
    r = sign_report(build_report(single_alert))
    html = generate_html_report(r)
    assert r["incident_id"] in html


def test_html_contains_nis2_reference(single_alert):
    r = sign_report(build_report(single_alert))
    html = generate_html_report(r)
    assert "NIS2" in html


def test_html_contains_sha256(single_alert):
    r = sign_report(build_report(single_alert))
    html = generate_html_report(r)
    assert r["integrity"]["sha256"][:16] in html


# ---------------------------------------------------------------------------
# generate_report (integration)
# ---------------------------------------------------------------------------

def test_generate_report_creates_files(tmp_path, critical_alerts):
    alerts_path = tmp_path / "alerts.json"
    alerts_path.write_text(json.dumps(critical_alerts), encoding="utf-8")

    json_p, html_p = generate_report(alerts_path, tmp_path)
    assert json_p.exists()
    assert html_p.exists()
    assert json_p.suffix == ".json"
    assert html_p.suffix == ".html"


def test_generate_report_json_valid(tmp_path, single_alert):
    alerts_path = tmp_path / "alerts.json"
    alerts_path.write_text(json.dumps(single_alert), encoding="utf-8")
    json_p, _ = generate_report(alerts_path, tmp_path)
    data = json.loads(json_p.read_text())
    assert data["incident_id"].startswith("INC-")
