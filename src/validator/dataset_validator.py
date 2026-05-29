"""Dataset Validator for CyberHealthGuard JSONL log files.

Validates schema, field types, value ranges, timestamp format
and detects duplicate event IDs.

Usage:
    python src/validator/dataset_validator.py --input data/logs/cyber_logs_*.json
    python src/validator/dataset_validator.py --input data/logs/cyber_logs_*.json --strict
    python src/validator/dataset_validator.py --input data/logs/cyber_logs_*.json --report artifacts/validation_report.json

Exit codes:
    0 → valid (or warnings only without --strict)
    1 → validation errors found
    2 → runtime error (bad args, unreadable files)
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# Schema definition
# ---------------------------------------------------------------------------

REQUIRED_FIELDS: Dict[str, Any] = {
    "event_id": str,
    "timestamp": str,
    "event_type": str,
    "category": str,
    "severity": int,
    "user_id": str,
    "user_role": str,
    "source_ip": str,
    "destination_ip": str,
    "device_id": str,
    "department": str,
    "action": str,
    "status": str,
    "bytes_transferred": (int, float),
    "is_anomaly": bool,
    "metadata": dict,
}

VALID_CATEGORIES = frozenset({
    "user_access",
    "patient_data_access",
    "network_activity",
    "system_event",
})

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# ---------------------------------------------------------------------------
# Validation logic
# ---------------------------------------------------------------------------

def _validate_event(
    event: Dict[str, Any],
    line_num: int,
    seen_ids: Set[str],
) -> Tuple[List[str], List[str]]:
    """Return (errors, warnings) for a single parsed event."""
    errors: List[str] = []
    warnings: List[str] = []

    for field_name, expected_type in REQUIRED_FIELDS.items():
        if field_name not in event:
            errors.append(f"line {line_num}: missing required field '{field_name}'")
            continue
        value = event[field_name]
        if not isinstance(value, expected_type):
            type_label = (
                expected_type.__name__
                if isinstance(expected_type, type)
                else "/".join(t.__name__ for t in expected_type)
            )
            errors.append(
                f"line {line_num}: '{field_name}' expected {type_label},"
                f" got {type(value).__name__}"
            )

    if isinstance(event.get("timestamp"), str):
        try:
            datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except ValueError:
            errors.append(
                f"line {line_num}: invalid ISO 8601 timestamp '{event['timestamp']}'"
            )

    category = event.get("category")
    if category is not None and category not in VALID_CATEGORIES:
        errors.append(f"line {line_num}: unknown category '{category}'")

    severity = event.get("severity")
    if isinstance(severity, int) and not (1 <= severity <= 5):
        errors.append(f"line {line_num}: severity {severity} out of range [1, 5]")

    bytes_val = event.get("bytes_transferred")
    if isinstance(bytes_val, (int, float)) and bytes_val < 0:
        errors.append(f"line {line_num}: bytes_transferred is negative ({bytes_val})")

    for ip_field in ("source_ip", "destination_ip"):
        val = event.get(ip_field, "")
        if isinstance(val, str) and not _IP_RE.match(val):
            warnings.append(
                f"line {line_num}: '{ip_field}' is not a valid IPv4 address: '{val}'"
            )

    eid = event.get("event_id")
    if eid:
        if eid in seen_ids:
            errors.append(f"line {line_num}: duplicate event_id '{eid}'")
        else:
            seen_ids.add(eid)

    return errors, warnings


def validate_file(path: Path) -> Dict[str, Any]:
    """Validate a JSONL file and return a structured report."""
    all_errors: List[str] = []
    all_warnings: List[str] = []
    seen_ids: Set[str] = set()
    total = 0
    parse_errors = 0

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"file": str(path), "error": str(exc), "total": 0, "valid": 0,
                "error_count": 1, "warning_count": 0, "errors": [str(exc)], "warnings": []}

    for line_num, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            all_errors.append(f"line {line_num}: JSON parse error — {exc}")
            parse_errors += 1
            continue
        errs, warns = _validate_event(event, line_num, seen_ids)
        all_errors.extend(errs)
        all_warnings.extend(warns)

    return {
        "file": str(path),
        "total": total,
        "valid": total - parse_errors,
        "error_count": len(all_errors),
        "warning_count": len(all_warnings),
        "errors": all_errors,
        "warnings": all_warnings,
    }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Valide les fichiers JSONL de logs CyberHealthGuard"
    )
    parser.add_argument("--input", type=Path, required=True, help="Fichier JSONL à valider")
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Exporter le rapport JSON vers ce chemin",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Échouer sur les avertissements en plus des erreurs",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input.exists():
        print(f"[validator] ❌ Fichier introuvable : {args.input}")
        return 2

    report = validate_file(args.input)

    if report.get("error") and report["total"] == 0:
        print(f"[validator] ❌ Erreur lecture : {report['error']}")
        return 2

    status_icon = "✅" if report["error_count"] == 0 else "❌"
    print(
        f"[validator] {status_icon} {report['file']} — "
        f"{report['total']} événements, "
        f"{report['error_count']} erreur(s), "
        f"{report['warning_count']} avertissement(s)."
    )

    if report["errors"]:
        print("\nErreurs :")
        for err in report["errors"][:20]:
            print(f"  {err}")
        overflow = len(report["errors"]) - 20
        if overflow > 0:
            print(f"  … et {overflow} erreur(s) supplémentaire(s).")

    if report["warnings"] and args.strict:
        print("\nAvertissements :")
        for warn in report["warnings"][:10]:
            print(f"  {warn}")

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"[validator] Rapport → {args.report}")

    has_errors = report["error_count"] > 0
    has_strict_issues = args.strict and report["warning_count"] > 0
    return 1 if (has_errors or has_strict_issues) else 0


if __name__ == "__main__":
    raise SystemExit(main())
