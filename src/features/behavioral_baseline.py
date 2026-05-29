"""CHG-034 — Behavioral Baseline (UEBA).

Builds per-user and per-role-group behavioral baselines from JSONL event logs
using a rolling 30-day window. Computes deviation scores to detect:

- **Progressive drift**    : user's current behaviour deviates significantly
  from their own historical baseline (z-score approach).
- **Peer deviation**       : user deviates from their role-group peers
  (e.g., a nurse accessing far more patient records than other nurses).

Baseline features per user
--------------------------
  avg_events_per_day          float  average daily event count
  avg_bytes_per_day           float  average daily bytes transferred
  avg_patient_accesses_per_day float
  avg_failed_logins_per_day   float
  typical_hours               set    set of active hours (mode ± 2 h)
  typical_departments         set    departments accessed in baseline
  typical_ips                 set    source IPs seen in baseline

Output
------
  ``build_baselines(events, lookback_days) → dict[str, dict]``
  ``score_user(events_today, baseline) → dict``
  ``score_all(events, baselines) → list[dict]``
  ``build_peer_groups(baselines) → dict[str, dict]``
  ``score_peer_deviation(user_id, baseline, peer_group) → dict``

CLI
---
  python -m src.features.behavioral_baseline \\
      --input data/logs/cyber_logs_*.json \\
      --output artifacts/baselines.json \\
      --lookback 30
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOOKBACK_DAYS        = 30   # baseline window in days
_MIN_DAYS_FOR_BASELINE = 3   # user must have at least N days of history
_DRIFT_THRESHOLD_Z    = 2.5  # z-score beyond which a deviation is flagged
_PEER_THRESHOLD_Z     = 2.0  # peer-group z-score threshold


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _day_key(ts: str) -> str:
    """Return YYYY-MM-DD string for a timestamp."""
    return _parse_ts(ts).strftime("%Y-%m-%d")


def _zscore(value: float, mean: float, std: float) -> float:
    if std == 0:
        # No variance in baseline: any non-zero deviation is treated as extreme
        return 0.0 if value == mean else (3.0 if value > mean else -3.0)
    return (value - mean) / std


def _safe_mean(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


def _safe_stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


# ---------------------------------------------------------------------------
# Core baseline building
# ---------------------------------------------------------------------------

def build_baselines(
    events: list[dict],
    lookback_days: int = _LOOKBACK_DAYS,
) -> dict[str, dict]:
    """Compute per-user behavioral baselines from the events list.

    Parameters
    ----------
    events:
        Full list of raw event dicts (JSONL-parsed).
    lookback_days:
        Number of days to include in the baseline window (counting back from the
        latest event timestamp in the dataset).

    Returns
    -------
    dict[str, dict]
        Mapping user_id → baseline dict.
    """
    if not events:
        return {}

    # Determine cutoff: latest timestamp in dataset - lookback_days
    all_ts = [_parse_ts(e.get("timestamp", "")) for e in events]
    max_ts = max(all_ts)
    cutoff = max_ts - timedelta(days=lookback_days)

    baseline_events = [e for e in events if _parse_ts(e.get("timestamp", "")) <= max_ts]

    # Group by user
    by_user: dict[str, list[dict]] = defaultdict(list)
    roles: dict[str, str] = {}
    for e in baseline_events:
        uid = e.get("user_id", "unknown")
        by_user[uid].append(e)
        role = e.get("user_role", "")
        if role:
            roles[uid] = role

    baselines: dict[str, dict] = {}
    for uid, user_events in by_user.items():
        # Only use events in the lookback window
        window_events = [
            e for e in user_events
            if _parse_ts(e.get("timestamp", "")) >= cutoff
        ]
        if not window_events:
            continue

        # Aggregate by day
        days: dict[str, dict] = defaultdict(lambda: {
            "event_count": 0, "bytes": 0, "patient_accesses": 0,
            "failed_logins": 0, "hours": set(), "departments": set(), "ips": set(),
        })
        for e in window_events:
            dk = _day_key(e.get("timestamp", ""))
            d = days[dk]
            d["event_count"] += 1
            d["bytes"] += e.get("bytes_transferred", 0) or 0
            if e.get("category") == "patient_data_access":
                d["patient_accesses"] += 1
            if e.get("event_type") == "login_failure":
                d["failed_logins"] += 1
            d["hours"].add(_parse_ts(e.get("timestamp", "")).hour)
            dept = e.get("department", "")
            if dept:
                d["departments"].add(dept)
            ip = e.get("source_ip", "")
            if ip:
                d["ips"].add(ip)

        n_days = len(days)
        if n_days < _MIN_DAYS_FOR_BASELINE:
            continue

        counts        = [v["event_count"]      for v in days.values()]
        bytes_totals  = [v["bytes"]             for v in days.values()]
        pat_counts    = [v["patient_accesses"]  for v in days.values()]
        fail_counts   = [v["failed_logins"]     for v in days.values()]

        # Typical hours: union of all hours seen
        all_hours: set[int] = set()
        for v in days.values():
            all_hours.update(v["hours"])

        all_depts: set[str] = set()
        all_ips: set[str] = set()
        for v in days.values():
            all_depts.update(v["departments"])
            all_ips.update(v["ips"])

        baselines[uid] = {
            "user_id":                    uid,
            "user_role":                  roles.get(uid, ""),
            "baseline_days":              n_days,
            "baseline_window_days":       lookback_days,

            "avg_events_per_day":         _safe_mean(counts),
            "std_events_per_day":         _safe_stdev(counts),
            "avg_bytes_per_day":          _safe_mean(bytes_totals),
            "std_bytes_per_day":          _safe_stdev(bytes_totals),
            "avg_patient_accesses_per_day": _safe_mean(pat_counts),
            "std_patient_accesses_per_day": _safe_stdev(pat_counts),
            "avg_failed_logins_per_day":  _safe_mean(fail_counts),
            "std_failed_logins_per_day":  _safe_stdev(fail_counts),

            "typical_hours":              sorted(all_hours),
            "typical_departments":        sorted(all_depts),
            "typical_ips":                sorted(all_ips),
        }

    return baselines


# ---------------------------------------------------------------------------
# Deviation scoring
# ---------------------------------------------------------------------------

def score_user(
    user_id: str,
    current_events: list[dict],
    baseline: dict,
) -> dict:
    """Score a user's current-period events against their baseline.

    Parameters
    ----------
    user_id:
        User identifier.
    current_events:
        Events for the user in the period to evaluate.
    baseline:
        Baseline dict for this user (from ``build_baselines``).

    Returns
    -------
    dict with keys: user_id, deviation_score (0-100), flags, details.
    """
    if not current_events or not baseline:
        return {"user_id": user_id, "deviation_score": 0, "flags": [], "details": {}}

    n_days = max(1, len({_day_key(e.get("timestamp", "")) for e in current_events}))

    events_per_day   = len(current_events) / n_days
    bytes_per_day    = sum(e.get("bytes_transferred", 0) or 0 for e in current_events) / n_days
    pat_per_day      = sum(1 for e in current_events if e.get("category") == "patient_data_access") / n_days
    fail_per_day     = sum(1 for e in current_events if e.get("event_type") == "login_failure") / n_days

    current_hours = {_parse_ts(e.get("timestamp", "")).hour for e in current_events}
    current_depts = {e.get("department", "") for e in current_events if e.get("department")}
    current_ips   = {e.get("source_ip", "") for e in current_events if e.get("source_ip")}

    # z-scores
    z_events = _zscore(events_per_day,  baseline["avg_events_per_day"],  baseline["std_events_per_day"])
    z_bytes  = _zscore(bytes_per_day,   baseline["avg_bytes_per_day"],   baseline["std_bytes_per_day"])
    z_pat    = _zscore(pat_per_day,     baseline["avg_patient_accesses_per_day"], baseline["std_patient_accesses_per_day"])
    z_fail   = _zscore(fail_per_day,    baseline["avg_failed_logins_per_day"],    baseline["std_failed_logins_per_day"])

    flags: list[str] = []
    details: dict = {
        "events_per_day": round(events_per_day, 2),
        "bytes_per_day":  round(bytes_per_day, 2),
        "z_events":       round(z_events, 2),
        "z_bytes":        round(z_bytes, 2),
        "z_patient_access": round(z_pat, 2),
        "z_failed_logins":  round(z_fail, 2),
    }

    if abs(z_events) > _DRIFT_THRESHOLD_Z:
        flags.append("abnormal_event_volume")
    if abs(z_bytes) > _DRIFT_THRESHOLD_Z:
        flags.append("abnormal_data_volume")
    if z_pat > _DRIFT_THRESHOLD_Z:
        flags.append("excessive_patient_access")
    if z_fail > _DRIFT_THRESHOLD_Z:
        flags.append("excessive_failed_logins")

    # New hours (off-pattern activity)
    new_hours = current_hours - set(baseline["typical_hours"])
    if new_hours:
        flags.append("new_active_hours")
        details["new_hours"] = sorted(new_hours)

    # New departments
    new_depts = current_depts - set(baseline["typical_departments"])
    if new_depts:
        flags.append("new_departments")
        details["new_departments"] = sorted(new_depts)

    # New IPs
    new_ips = current_ips - set(baseline["typical_ips"])
    if new_ips:
        flags.append("new_source_ips")
        details["new_ips"] = sorted(new_ips)

    # Composite deviation score (0-100)
    z_max   = max(abs(z_events), abs(z_bytes), z_pat, z_fail, 0)
    flag_bonus = min(30, len(flags) * 8)
    raw = min(100, round(z_max / _DRIFT_THRESHOLD_Z * 50 + flag_bonus))
    deviation_score = max(0, raw)

    return {
        "user_id":         user_id,
        "deviation_score": deviation_score,
        "flags":           flags,
        "details":         details,
    }


def score_all(
    events: list[dict],
    baselines: dict[str, dict],
    evaluation_days: int = 1,
) -> list[dict]:
    """Score all users in the most recent ``evaluation_days`` of the dataset.

    Returns a list of deviation dicts sorted by deviation_score descending.
    """
    if not events or not baselines:
        return []

    all_ts = [_parse_ts(e.get("timestamp", "")) for e in events]
    max_ts = max(all_ts)
    cutoff = max_ts - timedelta(days=evaluation_days)

    recent: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if _parse_ts(e.get("timestamp", "")) >= cutoff:
            recent[e.get("user_id", "unknown")].append(e)

    results: list[dict] = []
    for uid, baseline in baselines.items():
        user_events = recent.get(uid, [])
        scored = score_user(uid, user_events, baseline)
        scored["user_role"] = baseline.get("user_role", "")
        results.append(scored)

    results.sort(key=lambda x: x["deviation_score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Peer-group analysis
# ---------------------------------------------------------------------------

def build_peer_groups(baselines: dict[str, dict]) -> dict[str, dict]:
    """Build aggregated peer baselines grouped by user_role.

    Returns dict[role → peer_group_stats].
    """
    by_role: dict[str, list[dict]] = defaultdict(list)
    for b in baselines.values():
        role = b.get("user_role", "")
        if role:
            by_role[role].append(b)

    peer_groups: dict[str, dict] = {}
    for role, members in by_role.items():
        if len(members) < 2:
            continue
        peer_groups[role] = {
            "role":        role,
            "n_members":   len(members),
            "avg_events_per_day": _safe_mean([m["avg_events_per_day"] for m in members]),
            "std_events_per_day": _safe_stdev([m["avg_events_per_day"] for m in members]),
            "avg_bytes_per_day":  _safe_mean([m["avg_bytes_per_day"] for m in members]),
            "std_bytes_per_day":  _safe_stdev([m["avg_bytes_per_day"] for m in members]),
            "avg_patient_accesses_per_day": _safe_mean([m["avg_patient_accesses_per_day"] for m in members]),
            "std_patient_accesses_per_day": _safe_stdev([m["avg_patient_accesses_per_day"] for m in members]),
        }
    return peer_groups


def score_peer_deviation(
    user_id: str,
    baseline: dict,
    peer_group: dict,
) -> dict:
    """Compare a user's baseline against their peer group.

    Returns a dict with peer_deviation_score (0-100) and flags.
    """
    if not baseline or not peer_group:
        return {"user_id": user_id, "peer_deviation_score": 0, "peer_flags": []}

    z_events = _zscore(
        baseline["avg_events_per_day"],
        peer_group["avg_events_per_day"],
        peer_group["std_events_per_day"],
    )
    z_bytes = _zscore(
        baseline["avg_bytes_per_day"],
        peer_group["avg_bytes_per_day"],
        peer_group["std_bytes_per_day"],
    )
    z_pat = _zscore(
        baseline["avg_patient_accesses_per_day"],
        peer_group["avg_patient_accesses_per_day"],
        peer_group["std_patient_accesses_per_day"],
    )

    flags: list[str] = []
    if abs(z_events) > _PEER_THRESHOLD_Z:
        flags.append("peer_event_volume_outlier")
    if abs(z_bytes) > _PEER_THRESHOLD_Z:
        flags.append("peer_bytes_volume_outlier")
    if z_pat > _PEER_THRESHOLD_Z:
        flags.append("peer_patient_access_outlier")

    z_max = max(abs(z_events), abs(z_bytes), z_pat, 0)
    score = min(100, round(z_max / _PEER_THRESHOLD_Z * 40 + len(flags) * 10))

    return {
        "user_id":               user_id,
        "user_role":             baseline.get("user_role", ""),
        "peer_group_size":       peer_group["n_members"],
        "peer_deviation_score":  score,
        "peer_flags":            flags,
        "peer_details": {
            "z_events": round(z_events, 2),
            "z_bytes":  round(z_bytes, 2),
            "z_patient_access": round(z_pat, 2),
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CyberHealthGuard — Behavioral Baseline (CHG-034)",
    )
    parser.add_argument("--input",       required=True, help="Path to JSONL log file")
    parser.add_argument("--output",      default=None,  help="Output JSON path (default: artifacts/baselines.json)")
    parser.add_argument("--lookback",    type=int, default=_LOOKBACK_DAYS,
                        help=f"Lookback window in days (default {_LOOKBACK_DAYS})")
    parser.add_argument("--eval-days",   type=int, default=1,
                        help="Evaluation window in days for deviation scoring (default 1)")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"[behavioral_baseline] ERROR: {input_path}")
        return 1

    output_path = (
        Path(args.output).resolve() if args.output
        else Path("artifacts/baselines.json").resolve()
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    events = []
    with input_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    baselines    = build_baselines(events, args.lookback)
    peer_groups  = build_peer_groups(baselines)
    deviations   = score_all(events, baselines, args.eval_days)
    peer_scores  = [
        score_peer_deviation(uid, baselines[uid], peer_groups.get(baselines[uid]["user_role"], {}))
        for uid in baselines
        if baselines[uid].get("user_role") in peer_groups
    ]
    peer_scores.sort(key=lambda x: x["peer_deviation_score"], reverse=True)

    result = {
        "baselines":   baselines,
        "deviations":  deviations,
        "peer_groups": peer_groups,
        "peer_scores": peer_scores,
    }
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    flagged = sum(1 for d in deviations if d["flags"])
    top = deviations[:3] if deviations else []

    print(f"[behavioral_baseline] {len(events):,} events, {len(baselines)} baselines built")
    print(f"[behavioral_baseline] {len(deviations)} users scored — {flagged} flagged")
    for d in top:
        print(f"  {d['user_id']} ({d['user_role']}): score={d['deviation_score']} flags={d['flags']}")
    print(f"[behavioral_baseline] Output → {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
