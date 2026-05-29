"""CHG-032 — Travel Detector (Impossible Travel + New IP).

Analyses JSONL event logs per user to detect:

1. **Impossible Travel** — same user authenticates from two geographically
   incompatible locations within a configurable time window (default 30 min).
   Uses IP prefix as a proxy for location (10.x → internal subnet,
   external IPs → approximate geolocation bucket via first two octets).

2. **New IP for User** — a user authenticates from an IP address never seen
   in a configurable lookback window (default 30 days).

3. **Off-hours External Access** — login from an external IP outside business
   hours (06:00-20:00 local time, assumed UTC).

Each incident is returned as a structured dict with:
  - ``incident_type`` : impossible_travel | new_ip_for_user | off_hours_external
  - ``user_id``       : user identifier
  - ``risk_score``    : 0-100
  - ``confidence``    : low | medium | high
  - ``evidence``      : relevant event pairs or single events
  - ``recommendation``: plain-text remediation step

Usage
-----
    python -m src.detector.travel_detector --input data/logs/cyber_logs_*.json
    python -m src.detector.travel_detector --input data/logs/cyber_logs_*.json \\
        --window 1800 --lookback-days 30 --output artifacts/travel_incidents.json
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WINDOW_SECONDS      = 1800   # 30 min — impossible travel window
_LOOKBACK_DAYS       = 30     # new-IP lookback period
_BUSINESS_HOUR_START = 6      # 06:00 UTC
_BUSINESS_HOUR_END   = 20     # 20:00 UTC

_LOGIN_ACTIONS = frozenset({"user_login", "login_success", "login_failure"})
_LOGIN_EVENTS  = frozenset({"login_success", "login_failure"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _ip_location_bucket(ip: str) -> str:
    """Return a coarse location bucket from IP.

    Internal IPs (10.x, 172.16-31.x, 192.168.x) → "internal:<subnet>"
    External IPs → "external:<first_two_octets>"
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return f"unknown:{ip}"
    a, b = int(parts[0]), int(parts[1])
    if a == 10:
        return f"internal:10.{b}"
    if a == 172 and 16 <= b <= 31:
        return f"internal:172.{b}"
    if a == 192 and b == 168:
        return f"internal:192.168"
    return f"external:{a}.{b}"


def _is_internal(ip: str) -> bool:
    return _ip_location_bucket(ip).startswith("internal:")


def _is_off_hours(ts: str) -> bool:
    hour = _parse_ts(ts).hour
    return hour < _BUSINESS_HOUR_START or hour >= _BUSINESS_HOUR_END


def _extract_ip(event: dict) -> str | None:
    return (
        event.get("source_ip")
        or event.get("ip_address")
        or event.get("metadata", {}).get("source_ip")
        or event.get("metadata", {}).get("ip")
    )


def _is_login_event(event: dict) -> bool:
    return (
        event.get("action") in _LOGIN_ACTIONS
        or event.get("event_type") in _LOGIN_EVENTS
    )


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def _detect_impossible_travel(
    user_events: list[dict],
    window_seconds: float,
) -> list[dict]:
    """Detect two logins from incompatible locations within window_seconds."""
    logins = [
        e for e in user_events
        if _is_login_event(e) and _extract_ip(e)
    ]
    logins.sort(key=lambda e: _parse_ts(e.get("timestamp", "")).timestamp())

    incidents: list[dict] = []
    for i in range(len(logins) - 1):
        e1 = logins[i]
        e2 = logins[i + 1]
        t1 = _parse_ts(e1.get("timestamp", "")).timestamp()
        t2 = _parse_ts(e2.get("timestamp", "")).timestamp()
        delta = t2 - t1
        if delta > window_seconds:
            continue
        ip1 = _extract_ip(e1) or ""
        ip2 = _extract_ip(e2) or ""
        loc1 = _ip_location_bucket(ip1)
        loc2 = _ip_location_bucket(ip2)
        if loc1 == loc2:
            continue  # same location — normal

        # Different location buckets within the window → impossible travel
        risk = 85 if (not _is_internal(ip1) and not _is_internal(ip2)) else 70
        incidents.append({
            "incident_type": "impossible_travel",
            "user_id":       e1.get("user_id", ""),
            "risk_score":    risk,
            "confidence":    "high",
            "delta_seconds": round(delta),
            "evidence": [
                {"event_id": e1.get("event_id"), "ip": ip1, "location": loc1,
                 "timestamp": e1.get("timestamp")},
                {"event_id": e2.get("event_id"), "ip": ip2, "location": loc2,
                 "timestamp": e2.get("timestamp")},
            ],
            "recommendation": (
                f"Utilisateur {e1.get('user_id','?')} connecté depuis deux localisations "
                f"incompatibles en {round(delta)}s. Invalider les sessions actives et "
                "vérifier si le compte est compromis."
            ),
        })
    return incidents


def _detect_new_ip(
    user_events: list[dict],
    lookback_days: int,
    reference_events: list[dict],
) -> list[dict]:
    """Detect login from an IP never seen in the lookback window."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    # Build known IP set from reference (older events)
    known_ips: set[str] = set()
    for e in reference_events:
        if _is_login_event(e):
            ip = _extract_ip(e)
            if ip and _parse_ts(e.get("timestamp", "")) < cutoff:
                known_ips.add(ip)

    # Also include IPs seen in the earlier part of the current dataset
    for e in user_events:
        if _is_login_event(e) and _parse_ts(e.get("timestamp", "")) < cutoff:
            ip = _extract_ip(e)
            if ip:
                known_ips.add(ip)

    incidents: list[dict] = []
    for e in user_events:
        if not _is_login_event(e):
            continue
        ip = _extract_ip(e)
        if not ip:
            continue
        if _parse_ts(e.get("timestamp", "")) < cutoff:
            continue  # older than lookback — skip
        if ip in known_ips:
            continue  # known IP — skip

        risk = 75 if not _is_internal(ip) else 45
        incidents.append({
            "incident_type": "new_ip_for_user",
            "user_id":       e.get("user_id", ""),
            "risk_score":    risk,
            "confidence":    "medium" if _is_internal(ip) else "high",
            "evidence": [{
                "event_id":  e.get("event_id"),
                "ip":        ip,
                "location":  _ip_location_bucket(ip),
                "timestamp": e.get("timestamp"),
            }],
            "recommendation": (
                f"Connexion depuis IP inconnue {ip} pour l'utilisateur {e.get('user_id','?')}. "
                "Vérifier avec l'utilisateur si la connexion est légitime. "
                "Si non confirmée, révoquer la session et forcer MFA."
            ),
        })
        known_ips.add(ip)  # prevent duplicates within the same batch
    return incidents


def _detect_off_hours_external(user_events: list[dict]) -> list[dict]:
    """Login from external IP outside business hours."""
    incidents: list[dict] = []
    for e in user_events:
        if not _is_login_event(e):
            continue
        ip = _extract_ip(e)
        if not ip or _is_internal(ip):
            continue
        if not _is_off_hours(e.get("timestamp", "")):
            continue
        incidents.append({
            "incident_type": "off_hours_external",
            "user_id":       e.get("user_id", ""),
            "risk_score":    65,
            "confidence":    "medium",
            "evidence": [{
                "event_id":  e.get("event_id"),
                "ip":        ip,
                "location":  _ip_location_bucket(ip),
                "timestamp": e.get("timestamp"),
            }],
            "recommendation": (
                f"Accès externe hors horaires pour {e.get('user_id','?')} depuis {ip}. "
                "Vérifier la légitimité de la connexion et activer l'authentification renforcée."
            ),
        })
    return incidents


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
    window_seconds: float = _WINDOW_SECONDS,
    lookback_days: int = _LOOKBACK_DAYS,
) -> list[dict]:
    """Run all travel detectors on a list of events.

    Parameters
    ----------
    events:
        Raw JSONL events (list of dicts).
    window_seconds:
        Impossible travel detection window in seconds.
    lookback_days:
        New-IP lookback period in days.

    Returns
    -------
    list[dict]
        Sorted list of incidents (highest risk_score first).
    """
    # Group by user
    by_user: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        uid = e.get("user_id", "unknown")
        by_user[uid].append(e)

    incidents: list[dict] = []
    for uid, user_events in by_user.items():
        incidents.extend(_detect_impossible_travel(user_events, window_seconds))
        incidents.extend(_detect_new_ip(user_events, lookback_days, []))
        incidents.extend(_detect_off_hours_external(user_events))

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
        description="CyberHealthGuard — Travel Detector (CHG-032)",
    )
    parser.add_argument("--input",        required=True,  help="Path to JSONL log file")
    parser.add_argument("--output",       default=None,   help="Output JSON path")
    parser.add_argument("--window",       type=float, default=_WINDOW_SECONDS,
                        help=f"Impossible travel window in seconds (default {_WINDOW_SECONDS})")
    parser.add_argument("--lookback-days", type=int, default=_LOOKBACK_DAYS,
                        help=f"New-IP lookback in days (default {_LOOKBACK_DAYS})")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"[travel_detector] ERROR: {input_path}")
        return 1

    output_path = (
        Path(args.output).resolve() if args.output
        else Path("artifacts/travel_incidents.json").resolve()
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    events   = load_events(input_path)
    incidents = detect(events, args.window, args.lookback_days)
    s = summary(incidents)

    output_path.write_text(json.dumps(incidents, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[travel_detector] {len(events):,} events — {s['total']} incident(s)")
    for itype, count in s["by_type"].items():
        print(f"  {itype}: {count}")
    print(f"[travel_detector] Output → {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
