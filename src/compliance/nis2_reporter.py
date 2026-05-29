"""CHG-029 — NIS2 / PGSSI-S Incident Reporter.

Generates a structured incident notification compliant with:
- NIS2 Directive (EU 2022/2555) — 24h notification to ANSSI
- PGSSI-S v2 (ANSSI) — healthcare IS security policy
- CERT Santé reporting format

The report covers the mandatory fields for an early-warning notification
(Article 23 NIS2) and an initial incident report.

Output
------
- artifacts/nis2_incident_<id>.json   Machine-readable report
- artifacts/nis2_incident_<id>.html   Human-readable PDF-ready report

Usage
-----
    python -m src.compliance.nis2_reporter --alerts artifacts/alerts.json
    python -m src.compliance.nis2_reporter --alerts artifacts/alerts.json \\
        --org "CHU Exemple" --contact "rssi@chu-exemple.fr" --output artifacts/
"""
from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# NIS2 mandatory field mapping (Article 23 — early warning + initial report)
# ---------------------------------------------------------------------------

_PGSSI_S_CONTROLS: dict[str, str] = {
    "off_hours_patient_access":    "PGSSI-S 9.1 — Contrôle d'accès aux données de santé",
    "mass_data_exfiltration":      "PGSSI-S 10.3 — Protection contre la fuite de données",
    "privilege_abuse":             "PGSSI-S 9.2 — Gestion des privilèges",
    "suspicious_network_activity": "PGSSI-S 11.1 — Sécurité des réseaux",
    "repeated_login_failure":      "PGSSI-S 9.3 — Authentification et traçabilité",
    "anomalous_activity":          "PGSSI-S 12.4 — Surveillance et détection",
}

_SEVERITY_IMPACT: dict[str, str] = {
    "Critical": "Majeur — interruption ou compromission significative probable",
    "High":     "Significatif — impact avéré sur la confidentialité ou l'intégrité",
    "Medium":   "Modéré — impact limité, surveillance renforcée requise",
    "Low":      "Mineur — événement de sécurité sans impact métier immédiat",
}

_NIS2_NOTIFICATION_DEADLINE_HOURS = 24   # early warning
_NIS2_FULL_REPORT_DEADLINE_HOURS  = 72   # initial report


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def _incident_id() -> str:
    return f"INC-{uuid.uuid4().hex[:8].upper()}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _deadline(hours: int) -> str:
    from datetime import timedelta
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")


def _detect_affected_data(alerts: list[dict]) -> list[str]:
    """Infer categories of affected data from alert types."""
    categories: set[str] = set()
    for a in alerts:
        atype = a.get("alert_type", "")
        if "patient" in atype or "data" in atype:
            categories.add("Données de santé (DMP / DSP)")
        if "login" in atype or "privilege" in atype:
            categories.add("Données d'authentification")
        if "network" in atype:
            categories.add("Données de trafic réseau")
        categories.add("Journaux d'activité (logs)")
    return sorted(categories)


def _pgssi_controls(alerts: list[dict]) -> list[str]:
    """Return unique PGSSI-S controls triggered by alert types."""
    controls: set[str] = set()
    for a in alerts:
        atype = a.get("alert_type", "")
        if atype in _PGSSI_S_CONTROLS:
            controls.add(_PGSSI_S_CONTROLS[atype])
    return sorted(controls)


def build_report(
    alerts: list[dict],
    org_name: str = "Organisation non renseignée",
    contact_email: str = "rssi@organisation.fr",
    pipeline_run_id: Optional[str] = None,
) -> dict:
    """Build the structured NIS2-compliant incident report.

    Parameters
    ----------
    alerts:
        List of alert dicts from alert_manager.generate_alerts().
    org_name:
        Name of the reporting organisation (required by NIS2 Art. 23).
    contact_email:
        RSSI / CISO contact email for ANSSI follow-up.
    pipeline_run_id:
        Optional ML experiment run ID for traceability.

    Returns
    -------
    dict
        Full structured report ready for JSON serialisation.
    """
    if not alerts:
        raise ValueError("No alerts to report — cannot generate NIS2 incident report.")

    incident_id = _incident_id()
    detected_at = _now_iso()

    critical = [a for a in alerts if a.get("severity") == "Critical"]
    high      = [a for a in alerts if a.get("severity") == "High"]
    alert_types = sorted({a.get("alert_type", "unknown") for a in alerts})

    scores = [a.get("risk_score", 0.0) for a in alerts]
    max_score = max(scores) if scores else 0.0

    # NIS2 Art.23 §3 — severity classification
    if critical:
        nis2_severity = "Significant"          # → mandatory notification
        impact_fr = _SEVERITY_IMPACT["Critical"]
    elif len(high) >= 10:
        nis2_severity = "Significant"
        impact_fr = _SEVERITY_IMPACT["High"]
    else:
        nis2_severity = "Non-significant"
        impact_fr = _SEVERITY_IMPACT["Medium"]

    return {
        # ── Identification ────────────────────────────────────────────────
        "incident_id":          incident_id,
        "report_version":       "1.0",
        "generated_at":         detected_at,
        "reporting_framework":  ["NIS2 Art.23", "PGSSI-S v2", "CERT Santé"],

        # ── Organisation ─────────────────────────────────────────────────
        "organisation": {
            "name":          org_name,
            "sector":        "Santé / Médico-social",
            "contact_email": contact_email,
            "notify_to":     ["cert-sante@esante.gouv.fr", "cert@ssi.gouv.fr"],
        },

        # ── Incident classification ───────────────────────────────────────
        "incident": {
            "nis2_severity":         nis2_severity,
            "impact_description":    impact_fr,
            "detected_at":           detected_at,
            "detection_method":      "Automated ML pipeline — IsolationForest + Risk Scoring",
            "pipeline_run_id":       pipeline_run_id or "N/A",
            "alert_types_triggered": alert_types,
            "total_alerts":          len(alerts),
            "critical_count":        len(critical),
            "high_count":            len(high),
            "max_risk_score":        round(max_score, 2),
        },

        # ── Affected data (RGPD / HDS) ────────────────────────────────────
        "affected_data": {
            "categories":          _detect_affected_data(alerts),
            "personal_data":       True,
            "health_data":         True,
            "estimated_subjects":  "Indéterminé — investigation en cours",
            "hds_scope":           True,
        },

        # ── PGSSI-S controls triggered ────────────────────────────────────
        "pgssi_s_controls": _pgssi_controls(alerts),

        # ── NIS2 notification deadlines ───────────────────────────────────
        "nis2_deadlines": {
            "early_warning_deadline": _deadline(_NIS2_NOTIFICATION_DEADLINE_HOURS),
            "initial_report_deadline": _deadline(_NIS2_FULL_REPORT_DEADLINE_HOURS),
            "note": (
                f"Early warning must reach ANSSI/CERT Santé within "
                f"{_NIS2_NOTIFICATION_DEADLINE_HOURS}h of detection."
            ),
        },

        # ── Immediate containment measures ────────────────────────────────
        "containment_measures": [
            "Isolation des comptes utilisateurs impliqués dans les alertes Critical",
            "Révocation des sessions actives pour les comptes à risque élevé",
            "Activation du plan de réponse aux incidents (PRI)",
            "Notification de la DPO et du RSSI",
            "Préservation des preuves (logs figés en lecture seule)",
            "Scan antiviral sur les postes concernés",
        ],

        # ── Top 5 alerts (evidence) ───────────────────────────────────────
        "evidence": [
            {
                "alert_id":   a.get("alert_id"),
                "alert_type": a.get("alert_type"),
                "severity":   a.get("severity"),
                "risk_score": a.get("risk_score"),
                "timestamp":  a.get("timestamp"),
            }
            for a in sorted(alerts, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]
        ],

        # ── Report integrity ──────────────────────────────────────────────
        "integrity": {
            "sha256": "",   # filled after serialisation
        },
    }


def sign_report(report: dict) -> dict:
    """Compute SHA-256 of the report (excluding the integrity field) and embed it."""
    report_copy = {k: v for k, v in report.items() if k != "integrity"}
    raw = json.dumps(report_copy, sort_keys=True, ensure_ascii=False).encode()
    report["integrity"]["sha256"] = hashlib.sha256(raw).hexdigest()
    return report


# ---------------------------------------------------------------------------
# HTML export (PDF-ready)
# ---------------------------------------------------------------------------

_HTML_CSS = """
body { font-family: Arial, sans-serif; margin: 40px; color: #1a1a2e; font-size: 13px; }
h1   { color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 8px; }
h2   { color: #1a1a2e; margin-top: 28px; border-left: 4px solid #c0392b; padding-left: 10px; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th    { background: #1a1a2e; color: white; padding: 8px 10px; text-align: left; font-size: 12px; }
td    { padding: 8px 10px; border-bottom: 1px solid #ddd; }
tr:nth-child(even) td { background: #f5f5f5; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
.badge-Critical { background: #fee; color: #c0392b; }
.badge-High     { background: #fef3e2; color: #e67e22; }
.badge-Significant { background: #fee; color: #c0392b; }
.badge-Non-significant { background: #eafaf1; color: #27ae60; }
.deadline { background: #fff3cd; border: 1px solid #ffc107; padding: 10px 14px;
             border-radius: 4px; margin-top: 8px; font-size: 12px; }
.integrity { font-family: monospace; font-size: 11px; color: #555; word-break: break-all; }
.footer { margin-top: 40px; font-size: 11px; color: #888; border-top: 1px solid #ddd; padding-top: 10px; }
ul { margin: 6px 0; padding-left: 20px; }
li { margin-bottom: 4px; }
"""

def _badge_html(text: str, extra_class: str = "") -> str:
    cls = f"badge badge-{text.replace(' ', '-')} {extra_class}".strip()
    return f'<span class="{cls}">{text}</span>'


def generate_html_report(report: dict) -> str:
    """Render the incident report as a self-contained HTML string."""
    inc   = report["incident"]
    org   = report["organisation"]
    dead  = report["nis2_deadlines"]
    integ = report["integrity"]

    measures_html = "".join(f"<li>{m}</li>" for m in report["containment_measures"])
    controls_html = "".join(f"<li>{c}</li>" for c in report["pgssi_s_controls"])
    data_html     = "".join(f"<li>{d}</li>" for d in report["affected_data"]["categories"])

    evidence_rows = ""
    for e in report["evidence"]:
        atype_fmt = e["alert_type"].replace("_", " ").title()
        evidence_rows += (
            f"<tr>"
            f"<td>{e['alert_id']}</td>"
            f"<td>{_badge_html(e['severity'])}</td>"
            f"<td>{atype_fmt}</td>"
            f"<td><strong>{e['risk_score']:.1f}</strong></td>"
            f"<td>{str(e['timestamp'])[:19].replace('T',' ')}</td>"
            f"</tr>"
        )

    notify_to = ", ".join(org["notify_to"])
    frameworks = " | ".join(report["reporting_framework"])

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport d'incident NIS2 — {report['incident_id']}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<h1>&#x26A0; Rapport d'Incident de Sécurité — {report['incident_id']}</h1>
<p><strong>Cadre réglementaire :</strong> {frameworks}</p>
<p><strong>Généré le :</strong> {report['generated_at']} &nbsp;|&nbsp;
   <strong>Version :</strong> {report['report_version']}</p>

<h2>1. Organisation déclarante</h2>
<table>
  <tr><th>Champ</th><th>Valeur</th></tr>
  <tr><td>Nom</td><td>{org['name']}</td></tr>
  <tr><td>Secteur</td><td>{org['sector']}</td></tr>
  <tr><td>Contact RSSI</td><td>{org['contact_email']}</td></tr>
  <tr><td>Destinataires notification</td><td>{notify_to}</td></tr>
</table>

<h2>2. Classification NIS2</h2>
<table>
  <tr><th>Champ</th><th>Valeur</th></tr>
  <tr><td>Sévérité NIS2</td><td>{_badge_html(inc['nis2_severity'])}</td></tr>
  <tr><td>Description impact</td><td>{inc['impact_description']}</td></tr>
  <tr><td>Détecté le</td><td>{inc['detected_at']}</td></tr>
  <tr><td>Méthode de détection</td><td>{inc['detection_method']}</td></tr>
  <tr><td>Run ML associé</td><td>{inc['pipeline_run_id']}</td></tr>
  <tr><td>Total alertes</td><td>{inc['total_alerts']}</td></tr>
  <tr><td>Alertes Critical</td><td>{inc['critical_count']}</td></tr>
  <tr><td>Alertes High</td><td>{inc['high_count']}</td></tr>
  <tr><td>Score de risque max</td><td><strong>{inc['max_risk_score']}</strong>/100</td></tr>
</table>

<h2>3. Délais réglementaires NIS2 (Art. 23)</h2>
<div class="deadline">
  ⏰ <strong>Signalement précoce (24h) :</strong> avant le <strong>{dead['early_warning_deadline']}</strong><br>
  ⏰ <strong>Rapport initial (72h) :</strong> avant le <strong>{dead['initial_report_deadline']}</strong><br>
  <em>{dead['note']}</em>
</div>

<h2>4. Données affectées (RGPD / HDS)</h2>
<ul>{data_html}</ul>
<p>
  <strong>Données personnelles :</strong> Oui &nbsp;|&nbsp;
  <strong>Données de santé :</strong> Oui &nbsp;|&nbsp;
  <strong>Périmètre HDS :</strong> Oui &nbsp;|&nbsp;
  <strong>Personnes concernées :</strong> {report['affected_data']['estimated_subjects']}
</p>

<h2>5. Contrôles PGSSI-S concernés</h2>
<ul>{controls_html}</ul>

<h2>6. Preuves — Top 5 alertes</h2>
<table>
  <thead><tr><th>Alert ID</th><th>Sévérité</th><th>Type</th><th>Score</th><th>Horodatage</th></tr></thead>
  <tbody>{evidence_rows}</tbody>
</table>

<h2>7. Mesures de confinement immédiates</h2>
<ul>{measures_html}</ul>

<h2>8. Intégrité du rapport</h2>
<p class="integrity">SHA-256 : {integ['sha256']}</p>

<div class="footer">
  Rapport généré automatiquement par CyberHealthGuard Pipeline v1.0 —
  Ce document est confidentiel et destiné exclusivement aux autorités compétentes (ANSSI, CERT Santé, DPO).
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    alerts_path: Path,
    output_dir: Path,
    org_name: str = "Organisation non renseignée",
    contact_email: str = "rssi@organisation.fr",
    pipeline_run_id: Optional[str] = None,
) -> tuple[Path, Path]:
    """Read alerts, build and save NIS2 report (JSON + HTML).

    Returns
    -------
    tuple[Path, Path]
        (json_path, html_path)
    """
    alerts_path = Path(alerts_path).resolve()
    output_dir  = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    with alerts_path.open(encoding="utf-8") as f:
        alerts: list[dict] = json.load(f)

    report = build_report(alerts, org_name, contact_email, pipeline_run_id)
    report = sign_report(report)

    inc_id = report["incident_id"]
    json_path = output_dir / f"nis2_incident_{inc_id}.json"
    html_path = output_dir / f"nis2_incident_{inc_id}.html"

    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    html_path.write_text(generate_html_report(report), encoding="utf-8")

    return json_path, html_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a NIS2-compliant incident report from CyberHealthGuard alerts",
    )
    parser.add_argument("--alerts",  default="artifacts/alerts.json",
                        help="Path to alerts.json (default: artifacts/alerts.json)")
    parser.add_argument("--output",  default="artifacts",
                        help="Output directory (default: artifacts/)")
    parser.add_argument("--org",     default="Organisation non renseignée",
                        help="Organisation name")
    parser.add_argument("--contact", default="rssi@organisation.fr",
                        help="RSSI contact email")
    parser.add_argument("--run-id",  default=None,
                        help="ML pipeline run ID for traceability")
    args = parser.parse_args()

    try:
        json_p, html_p = generate_report(
            Path(args.alerts),
            Path(args.output),
            org_name=args.org,
            contact_email=args.contact,
            pipeline_run_id=args.run_id,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"[nis2_reporter] ERROR: {exc}", flush=True)
        return 1

    print(f"[nis2_reporter] JSON  → {json_p}")
    print(f"[nis2_reporter] HTML  → {html_p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
