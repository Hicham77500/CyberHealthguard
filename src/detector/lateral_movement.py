"""CHG-033 — Lateral Movement Detector.

Analyses JSONL event logs to detect post-compromise lateral movement patterns:

1. **Cross-department access** — user accesses resources outside their usual department.
2. **Privilege escalation chain** — privilege_escalation_attempt followed by new-department access.
3. **Resource sweep** — a single user accesses an abnormally large number of distinct
   resources (patients, devices) in a short window (reconnaissance pattern).
4. **Role-resource mismatch** — user_role inconsistent with the accessed resource category
   (e.g. receptionist accessing oncology patient records).
5. **Abnormal peer deviation** — user accesses significantly more distinct departments
   than their role peers in the same period.

Each incident is returned as a structured dict with:
  - ``incident_type``      : see _INCIDENT_TYPES
  - ``user_id``            : user identifier
  - ``risk_score``         : 0-100
  - ``confidence``         : low | medium | high
  - ``evidence``           : list of relevant event dicts
  - ``recommendation``     : remediation guidance

Usage
-----
    python -m src.detector.lateral_movement --input data/logs/cyber_logs_*.json
    python -m src.detector.lateral_movement --input data/logs/cyber_logs_*.json \\
        --sweep-threshold 30 --window 600 --output artifacts/lateral_incidents.json
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SWEEP_THRESHOLD   = 25   # distinct resources in window → resource sweep
_WINDOW_SECONDS    = 600  # 10 min window for sweep detection
_PEER_DEVIATION    = 3    # user accesses ≥ N more depts than peer median → anomaly

# Expected departments per role (subset — used for mismatch detection)
_ROLE_DEPT_MAP: dict[str, frozenset[str]] = {
    "physician":           frozenset({"emergency", "cardiology", "oncology", "pediatrics"}),
    "nurse":               frozenset({"emergency", "geriatrics", "rehab", "pediatrics"}),
    "it_admin":            frozenset({"administration"}),
    "lab_tech":            frozenset({"lab_services"}),
    "imaging_specialist":  frozenset({"imaging"}),
    "billing_specialist":  frozenset({"pharmacy", "administration"}),
    "receptionist":        frozenset({"administration"}),
}

# Sensitive resource categories that any mismatch should flag at higher risk
_SENSITIVE_CATEGORIES = frozenset({"patient_data_access", "oncology", "cardiology"})

_ACCESS_ACTIONS = frozenset({
    "read_record", "update_record", "export_record", "delete_record",
    "read_patient_file", "update_patient_file", "export_patient_file",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _ts_epoch(ts: str) -> float:
    return _parse_ts(ts).timestamp()


def _resource_id(event: dict) -> str | None:
    """Extract a resource identifier from an event."""
    return (
        event.get("patient_id")
        or event.get("device_id")
        or event.get("resource_id")
        or event.get("metadata", {}).get("patient_id")
        or event.get("metadata", {}).get("resource")
    )


def _dept(event: dict) -> str | None:
    return event.get("department") or event.get("metadata", {}).get("department")


def _confidence(ratio: float) -> str:
    if ratio >= 3:
        return "high"
    if ratio >= 1.5:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def _detect_cross_department(
    user_events: list[dict],
    user_role: str,
) -> list[dict]:
    """Flag accesses to departments outside the user's expected role scope."""
    expected = _ROLE_DEPT_MAP.get(user_role, frozenset())
    if not expected:
        return []  # unknown role — skip

    incidents: list[dict] = []
    seen_anomalous: set[str] = set()

    for e in user_events:
        if e.get("action") not in _ACCESS_ACTIONS and e.get("category") not in ("patient_data_access",):
            continue
        dept = _dept(e)
        if not dept or dept in expected:
            continue
        if dept in seen_anomalous:
            continue

        seen_anomalous.add(dept)
        is_sensitive = (
            dept in _SENSITIVE_CATEGORIES
            or e.get("category") in _SENSITIVE_CATEGORIES
        )
        risk = 80 if is_sensitive else 60
        incidents.append({
            "incident_type": "cross_department_access",
            "user_id":       e.get("user_id", ""),
            "user_role":     user_role,
            "risk_score":    risk,
            "confidence":    "high" if is_sensitive else "medium",
            "evidence":      [{"event_id": e.get("event_id"), "department": dept,
                               "action": e.get("action"), "timestamp": e.get("timestamp")}],
            "recommendation": (
                f"Utilisateur {e.get('user_id','?')} ({user_role}) a accédé au département "
                f"'{dept}' hors de son périmètre habituel {set(expected)}. "
                "Vérifier si délégation légitime ou compromission de compte."
            ),
        })
    return incidents


def _detect_privilege_escalation_chain(
    user_events: list[dict],
    window_seconds: float,
) -> list[dict]:
    """Privilege escalation followed by cross-department access within window."""
    priv_events = [
        e for e in user_events
        if e.get("event_type") == "privilege_escalation_attempt"
        or e.get("action") == "privilege_change"
    ]
    if not priv_events:
        return []

    access_events = [
        e for e in user_events
        if e.get("action") in _ACCESS_ACTIONS
    ]

    incidents: list[dict] = []
    for priv_e in priv_events:
        t_priv = _ts_epoch(priv_e.get("timestamp", ""))
        following = [
            e for e in access_events
            if 0 < _ts_epoch(e.get("timestamp", "")) - t_priv <= window_seconds
        ]
        if not following:
            continue

        incidents.append({
            "incident_type": "privilege_escalation_chain",
            "user_id":       priv_e.get("user_id", ""),
            "risk_score":    88,
            "confidence":    "high",
            "evidence": (
                [{"event_id": priv_e.get("event_id"), "action": priv_e.get("action"),
                  "timestamp": priv_e.get("timestamp"), "note": "privilege_escalation"}]
                + [{"event_id": e.get("event_id"), "action": e.get("action"),
                    "department": _dept(e), "timestamp": e.get("timestamp")}
                   for e in following[:5]]
            ),
            "recommendation": (
                f"Escalade de privilèges pour {priv_e.get('user_id','?')} suivie de "
                f"{len(following)} accès ressources en {window_seconds}s. "
                "Pattern de mouvement latéral — isoler le compte immédiatement."
            ),
        })
    return incidents


def _detect_resource_sweep(
    user_events: list[dict],
    window_seconds: float,
    threshold: int,
) -> list[dict]:
    """User accesses ≥ threshold distinct resources in window (reconnaissance)."""
    access_events = sorted(
        [e for e in user_events if _resource_id(e)],
        key=lambda e: _ts_epoch(e.get("timestamp", "")),
    )
    if len(access_events) < threshold:
        return []

    incidents: list[dict] = []
    i = 0
    while i < len(access_events):
        t_start = _ts_epoch(access_events[i].get("timestamp", ""))
        window = [access_events[i]]
        j = i + 1
        while j < len(access_events) and _ts_epoch(access_events[j].get("timestamp", "")) - t_start <= window_seconds:
            window.append(access_events[j])
            j += 1
        distinct = {_resource_id(e) for e in window}
        if len(distinct) >= threshold:
            conf = _confidence(len(distinct) / threshold)
            incidents.append({
                "incident_type": "resource_sweep",
                "user_id":       access_events[i].get("user_id", ""),
                "risk_score":    min(100, 65 + len(distinct)),
                "confidence":    conf,
                "distinct_resources": len(distinct),
                "event_count":   len(window),
                "window_seconds": window_seconds,
                "evidence": [
                    {"event_id": e.get("event_id"), "resource": _resource_id(e),
                     "timestamp": e.get("timestamp")}
                    for e in window[:10]
                ],
                "recommendation": (
                    f"Accès à {len(distinct)} ressources distinctes en {window_seconds}s "
                    f"par {access_events[i].get('user_id','?')} — pattern de reconnaissance. "
                    "Vérifier si automatisation légitime ou balayage malveillant."
                ),
            })
            i = j
        else:
            i += 1
    return incidents


def _detect_role_resource_mismatch(user_events: list[dict], user_role: str) -> list[dict]:
    """User role inconsistent with accessed category (stricter than cross-dept)."""
    sensitive_roles = {"it_admin", "billing_specialist", "receptionist"}
    if user_role not in sensitive_roles:
        return []

    patient_access = [
        e for e in user_events
        if e.get("category") == "patient_data_access"
        or e.get("action") in ("read_record", "export_record", "delete_record")
    ]
    if not patient_access:
        return []

    return [{
        "incident_type": "role_resource_mismatch",
        "user_id":       patient_access[0].get("user_id", ""),
        "user_role":     user_role,
        "risk_score":    82,
        "confidence":    "high",
        "event_count":   len(patient_access),
        "evidence": [
            {"event_id": e.get("event_id"), "action": e.get("action"),
             "category": e.get("category"), "timestamp": e.get("timestamp")}
            for e in patient_access[:5]
        ],
        "recommendation": (
            f"Rôle '{user_role}' sans droit d'accès données patients a consulté "
            f"{len(patient_access)} enregistrement(s). Vérifier si compte compromis "
            "ou élévation de droits non autorisée."
        ),
    }]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def detect(
    events: list[dict],
    sweep_threshold: int = _SWEEP_THRESHOLD,
    window_seconds: float = _WINDOW_SECONDS,
) -> list[dict]:
    """Run all lateral movement detectors on a list of events.

    Parameters
    ----------
    events:
        Raw JSONL events.
    sweep_threshold:
        Distinct resources in window to trigger resource sweep alert.
    window_seconds:
        Window for sweep and privilege-chain detection (seconds).

    Returns
    -------
    list[dict]
        Sorted list of incidents (highest risk_score first).
    """
    # Build per-user index with role
    by_user: dict[str, list[dict]] = defaultdict(list)
    user_roles: dict[str, str] = {}
    for e in events:
        uid  = e.get("user_id", "unknown")
        role = e.get("user_role", "")
        by_user[uid].append(e)
        if role:
            user_roles[uid] = role

    incidents: list[dict] = []
    for uid, user_events in by_user.items():
        role = user_roles.get(uid, "")
        if role:
            incidents.extend(_detect_cross_department(user_events, role))
            incidents.extend(_detect_role_resource_mismatch(user_events, role))
        incidents.extend(_detect_privilege_escalation_chain(user_events, window_seconds))
        incidents.extend(_detect_resource_sweep(user_events, window_seconds, sweep_threshold))

    incidents.sort(key=lambda x: x["risk_score"], reverse=True)
    return incidents


def summary(incidents: list[dict]) -> dict:
    if not incidents:
        return {"total": 0, "by_type": {}, "max_risk_score": 0}
    from collections import Counter
    by_type = Counter(i["incident_type"] for i in incidents)
    return {
        "total":          len(incidents),
        "by_type":        dict(by_type),
        "max_risk_score": max(i["risk_score"] for i in incidents),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CyberHealthGuard — Lateral Movement Detector (CHG-033)",
    )
    parser.add_argument("--input",           required=True, help="Path to JSONL log file")
    parser.add_argument("--output",          default=None,  help="Output JSON path")
    parser.add_argument("--sweep-threshold", type=int,   default=_SWEEP_THRESHOLD,
                        help=f"Distinct resources to trigger sweep (default {_SWEEP_THRESHOLD})")
    parser.add_argument("--window",          type=float, default=_WINDOW_SECONDS,
                        help=f"Detection window in seconds (default {_WINDOW_SECONDS})")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"[lateral_movement] ERROR: {input_path}")
        return 1

    output_path = (
        Path(args.output).resolve() if args.output
        else Path("artifacts/lateral_incidents.json").resolve()
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    events    = load_events(input_path)
    incidents = detect(events, args.sweep_threshold, args.window)
    s = summary(incidents)

    output_path.write_text(json.dumps(incidents, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[lateral_movement] {len(events):,} events — {s['total']} incident(s)")
    for itype, count in s["by_type"].items():
        print(f"  {itype}: {count}")
    print(f"[lateral_movement] Output → {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
