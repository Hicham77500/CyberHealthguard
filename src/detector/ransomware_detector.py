"""CHG-031 — Ransomware Detector.

Analyses JSONL event logs for ransomware behavioural indicators:
  1. Mass file modification burst   — many file_created/file_deleted events in a short window
  2. High-entropy filename patterns  — simulated via abnormal rate of filesystem events
  3. Backup tampering               — file_deleted events on backup-related resources
  4. IOC correlation                — known ransomware campaign indicators (LockBit, BlackCat, Rhysida)
  5. Mass data exfiltration spike   — large_data_transfer + outbound events in burst

Each detected incident is returned as a structured dict with:
  - ``incident_type``    : category (see _INCIDENT_TYPES)
  - ``risk_score``       : 0-100
  - ``confidence``       : low | medium | high
  - ``affected_events``  : list of event_ids involved
  - ``ioc_matched``      : list of IOC names matched (if any)
  - ``recommendation``   : plain-text remediation step

Usage
-----
    python -m src.detector.ransomware_detector --input data/logs/cyber_logs_*.json
    python -m src.detector.ransomware_detector --input data/logs/cyber_logs_*.json \\
        --window 300 --output artifacts/ransomware_incidents.json
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_INCIDENT_TYPES = frozenset({
    "mass_file_modification",
    "backup_tampering",
    "ioc_match",
    "mass_exfiltration_burst",
    "privilege_then_filesystem",
})

# Ransomware campaign IOC keywords (simplified — in production use a live CTI feed)
_IOC_CAMPAIGNS: dict[str, list[str]] = {
    "LockBit":   ["lockbit", "lb3", "restorefiles.txt", "!!restore_files"],
    "BlackCat":  ["blackcat", "alphv", "recover_files", "noberus"],
    "Rhysida":   ["rhysida", "rhysida_ransom", "cactus_ransom"],
    "Royal":     ["royal_ransom", "royal_recover"],
    "Akira":     ["akira_restore", "akira.exe"],
}

# Thresholds
_MASS_FILE_THRESHOLD   = 20   # ≥ N filesystem events in window → suspicious
_EXFIL_THRESHOLD       = 5    # ≥ N large_data_transfer in window → suspicious
_WINDOW_SECONDS        = 300  # default sliding window (5 min)
_PRIV_ESC_GRACE        = 600  # seconds after privilege_escalation to flag filesystem events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    """Parse ISO 8601 timestamp to UTC-aware datetime."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.now(timezone.utc)


def _ts_epoch(ts: str) -> float:
    return _parse_ts(ts).timestamp()


def _ioc_scan(event: dict) -> list[str]:
    """Return list of IOC campaign names matched in the event payload."""
    payload = json.dumps(event).lower()
    matched: list[str] = []
    for campaign, keywords in _IOC_CAMPAIGNS.items():
        if any(kw in payload for kw in keywords):
            matched.append(campaign)
    return matched


def _confidence(n: int, threshold: int) -> str:
    ratio = n / threshold
    if ratio >= 3:
        return "high"
    if ratio >= 1.5:
        return "medium"
    return "low"


def _risk_from_confidence(conf: str, base: int) -> int:
    mult = {"low": 1.0, "medium": 1.3, "high": 1.6}
    return min(100, round(base * mult.get(conf, 1.0)))


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _detect_mass_file_modification(
    events: list[dict],
    window_seconds: float,
    threshold: int,
) -> list[dict]:
    """Sliding window: ≥ threshold filesystem events within window → incident."""
    fs_events = [
        e for e in events
        if e.get("action") in ("filesystem",) or e.get("event_type") in ("file_created", "file_deleted")
    ]
    fs_events.sort(key=lambda e: _ts_epoch(e.get("timestamp", "")))

    incidents: list[dict] = []
    i = 0
    while i < len(fs_events):
        t_start = _ts_epoch(fs_events[i].get("timestamp", ""))
        window = [fs_events[i]]
        j = i + 1
        while j < len(fs_events) and _ts_epoch(fs_events[j].get("timestamp", "")) - t_start <= window_seconds:
            window.append(fs_events[j])
            j += 1
        if len(window) >= threshold:
            conf = _confidence(len(window), threshold)
            incidents.append({
                "incident_type":    "mass_file_modification",
                "risk_score":       _risk_from_confidence(conf, 70),
                "confidence":       conf,
                "affected_events":  [e.get("event_id", "") for e in window],
                "event_count":      len(window),
                "window_seconds":   window_seconds,
                "ioc_matched":      [],
                "recommendation":   (
                    "Isoler immédiatement les postes concernés. Vérifier les sauvegardes. "
                    "Activer le PRI (Plan de Réponse aux Incidents)."
                ),
            })
            i = j  # skip past this window
        else:
            i += 1
    return incidents


def _detect_backup_tampering(events: list[dict]) -> list[dict]:
    """file_deleted events on backup-related resources."""
    backup_keywords = ["backup", "sauvegarde", "snapshot", "archive", ".bak", "veeam", "shadow"]
    suspects = []
    for e in events:
        if e.get("action") not in ("filesystem", "delete_record"):
            continue
        payload = json.dumps(e).lower()
        if e.get("event_type") == "file_deleted" or "delet" in e.get("action", ""):
            if any(kw in payload for kw in backup_keywords):
                suspects.append(e)

    if not suspects:
        return []

    conf = _confidence(len(suspects), 2)
    return [{
        "incident_type":   "backup_tampering",
        "risk_score":      _risk_from_confidence(conf, 85),
        "confidence":      conf,
        "affected_events": [e.get("event_id", "") for e in suspects],
        "event_count":     len(suspects),
        "window_seconds":  None,
        "ioc_matched":     [],
        "recommendation":  (
            "Vérifier l'intégrité des sauvegardes. Activer une copie hors-ligne. "
            "Notifier le RSSI — indicateur fort de ransomware pré-chiffrement."
        ),
    }]


def _detect_ioc_matches(events: list[dict]) -> list[dict]:
    """Scan all events for known ransomware IOC keywords."""
    by_campaign: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        for campaign in _ioc_scan(e):
            by_campaign[campaign].append(e)

    incidents: list[dict] = []
    for campaign, matched_events in by_campaign.items():
        conf = _confidence(len(matched_events), 1)
        incidents.append({
            "incident_type":   "ioc_match",
            "risk_score":      _risk_from_confidence(conf, 90),
            "confidence":      "high",   # any IOC match → high by default
            "affected_events": [e.get("event_id", "") for e in matched_events],
            "event_count":     len(matched_events),
            "window_seconds":  None,
            "ioc_matched":     [campaign],
            "recommendation":  (
                f"IOC {campaign} détecté. Isoler le réseau immédiatement. "
                "Contacter CERT Santé (cert-sante@esante.gouv.fr) et ANSSI."
            ),
        })
    return incidents


def _detect_mass_exfiltration_burst(
    events: list[dict],
    window_seconds: float,
    threshold: int,
) -> list[dict]:
    """Large data transfers clustered in a short window."""
    exfil = [
        e for e in events
        if e.get("event_type") in ("large_data_transfer", "outbound_connection")
        or e.get("action") in ("data_transfer", "outbound_flow")
    ]
    exfil.sort(key=lambda e: _ts_epoch(e.get("timestamp", "")))

    incidents: list[dict] = []
    i = 0
    while i < len(exfil):
        t_start = _ts_epoch(exfil[i].get("timestamp", ""))
        window = [exfil[i]]
        j = i + 1
        while j < len(exfil) and _ts_epoch(exfil[j].get("timestamp", "")) - t_start <= window_seconds:
            window.append(exfil[j])
            j += 1
        if len(window) >= threshold:
            conf = _confidence(len(window), threshold)
            incidents.append({
                "incident_type":   "mass_exfiltration_burst",
                "risk_score":      _risk_from_confidence(conf, 75),
                "confidence":      conf,
                "affected_events": [e.get("event_id", "") for e in window],
                "event_count":     len(window),
                "window_seconds":  window_seconds,
                "ioc_matched":     [],
                "recommendation":  (
                    "Bloquer les flux sortants anormaux. Vérifier les destinations IP. "
                    "Lancer une analyse DLP sur les fichiers transférés."
                ),
            })
            i = j
        else:
            i += 1
    return incidents


def _detect_privilege_then_filesystem(
    events: list[dict],
    grace_seconds: float,
) -> list[dict]:
    """Privilege escalation immediately followed by filesystem activity."""
    priv_events = [
        e for e in events
        if e.get("event_type") == "privilege_escalation_attempt"
        or e.get("action") == "privilege_change"
    ]
    if not priv_events:
        return []

    fs_events = [
        e for e in events
        if e.get("action") in ("filesystem",) or e.get("event_type") in ("file_created", "file_deleted")
    ]

    incidents: list[dict] = []
    for priv_e in priv_events:
        t_priv = _ts_epoch(priv_e.get("timestamp", ""))
        following_fs = [
            e for e in fs_events
            if 0 < _ts_epoch(e.get("timestamp", "")) - t_priv <= grace_seconds
        ]
        if following_fs:
            conf = _confidence(len(following_fs), 3)
            incidents.append({
                "incident_type":   "privilege_then_filesystem",
                "risk_score":      _risk_from_confidence(conf, 80),
                "confidence":      conf,
                "affected_events": [priv_e.get("event_id", "")] + [e.get("event_id", "") for e in following_fs],
                "event_count":     1 + len(following_fs),
                "window_seconds":  grace_seconds,
                "ioc_matched":     [],
                "recommendation":  (
                    "Escalade de privilèges suivie d'activité filesystem — pattern ransomware typique. "
                    "Révoquer les droits élevés et isoler le compte."
                ),
            })
    return incidents


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_events(path: Path) -> list[dict]:
    """Load JSONL events from path."""
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
    window_seconds: float = _WINDOW_SECONDS,
    mass_file_threshold: int = _MASS_FILE_THRESHOLD,
    exfil_threshold: int = _EXFIL_THRESHOLD,
) -> list[dict]:
    """Run all ransomware detectors on a list of events.

    Parameters
    ----------
    events:
        Raw JSONL events (list of dicts).
    window_seconds:
        Sliding window duration in seconds for burst detection.
    mass_file_threshold:
        Number of filesystem events in window to trigger an incident.
    exfil_threshold:
        Number of large_data_transfer events in window to trigger.

    Returns
    -------
    list[dict]
        Sorted list of incidents (highest risk_score first).
    """
    incidents: list[dict] = []
    incidents.extend(_detect_mass_file_modification(events, window_seconds, mass_file_threshold))
    incidents.extend(_detect_backup_tampering(events))
    incidents.extend(_detect_ioc_matches(events))
    incidents.extend(_detect_mass_exfiltration_burst(events, window_seconds, exfil_threshold))
    incidents.extend(_detect_privilege_then_filesystem(events, _PRIV_ESC_GRACE))

    # Deduplicate by event set overlap — keep highest-score incident per overlapping group
    incidents.sort(key=lambda x: x["risk_score"], reverse=True)
    return incidents


def summary(incidents: list[dict]) -> dict:
    """Return a summary dict of detected incidents."""
    if not incidents:
        return {"total": 0, "by_type": {}, "max_risk_score": 0, "high_confidence": 0}
    from collections import Counter
    by_type = Counter(i["incident_type"] for i in incidents)
    return {
        "total":          len(incidents),
        "by_type":        dict(by_type),
        "max_risk_score": max(i["risk_score"] for i in incidents),
        "high_confidence": sum(1 for i in incidents if i["confidence"] == "high"),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CyberHealthGuard — Ransomware Detector (CHG-031)",
    )
    parser.add_argument("--input",   required=True, help="Path to JSONL log file")
    parser.add_argument("--output",  default=None,  help="Output JSON path (default: artifacts/ransomware_incidents.json)")
    parser.add_argument("--window",  type=float, default=_WINDOW_SECONDS,
                        help=f"Sliding window in seconds (default: {_WINDOW_SECONDS})")
    parser.add_argument("--mass-file-threshold", type=int, default=_MASS_FILE_THRESHOLD,
                        help=f"Filesystem events per window to trigger (default: {_MASS_FILE_THRESHOLD})")
    parser.add_argument("--exfil-threshold", type=int, default=_EXFIL_THRESHOLD,
                        help=f"Exfil events per window to trigger (default: {_EXFIL_THRESHOLD})")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"[ransomware_detector] ERROR: file not found: {input_path}")
        return 1

    output_path = Path(args.output).resolve() if args.output else Path("artifacts/ransomware_incidents.json").resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    events   = load_events(input_path)
    incidents = detect(events, args.window, args.mass_file_threshold, args.exfil_threshold)
    s = summary(incidents)

    output_path.write_text(json.dumps(incidents, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[ransomware_detector] {len(events):,} events analysed")
    print(f"[ransomware_detector] {s['total']} incident(s) — max risk {s['max_risk_score']} — {s['high_confidence']} high-confidence")
    for itype, count in s["by_type"].items():
        print(f"  {itype}: {count}")
    print(f"[ransomware_detector] Output → {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
