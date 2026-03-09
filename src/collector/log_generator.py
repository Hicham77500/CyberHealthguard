"""Synthetic cyber log generator for CyberHealthGuard."""
from __future__ import annotations

import argparse
import json
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

# -------------------- Static definitions --------------------

DEPARTMENTS = [
    "emergency",
    "cardiology",
    "oncology",
    "geriatrics",
    "pediatrics",
    "imaging",
    "lab_services",
    "pharmacy",
    "rehab",
    "administration",
]

FACILITIES = [
    "Paris-Central-Clinic",
    "Lyon-River-Hospital",
    "Marseille-Medical-Center",
    "Toulouse-Research-Hub",
]

APPLICATIONS = ["EHR", "RIS", "LIMS", "PACS", "Billing"]

USER_ROLE_DEPARTMENTS = {
    "physician": ["emergency", "cardiology", "oncology", "pediatrics"],
    "nurse": ["emergency", "geriatrics", "rehab", "pediatrics"],
    "it_admin": ["administration"],
    "lab_tech": ["lab_services"],
    "imaging_specialist": ["imaging"],
    "billing_specialist": ["pharmacy", "administration"],
    "receptionist": ["administration"],
}

EVENT_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "login_success": {"category": "user_access", "action": "user_login", "severity": (1, 2), "statuses": ("success",)},
    "login_failure": {"category": "user_access", "action": "user_login", "severity": (2, 4), "statuses": ("failure", "blocked")},
    "logout": {"category": "user_access", "action": "user_logout", "severity": (1, 1), "statuses": ("success",)},
    "password_reset_request": {"category": "user_access", "action": "password_reset", "severity": (1, 2), "statuses": ("pending", "success")},
    "read_patient_file": {"category": "patient_data_access", "action": "read_record", "severity": (1, 2), "statuses": ("success",)},
    "update_patient_file": {"category": "patient_data_access", "action": "update_record", "severity": (2, 3), "statuses": ("success", "failure")},
    "export_patient_file": {"category": "patient_data_access", "action": "export_record", "severity": (2, 4), "statuses": ("success", "failure")},
    "delete_patient_note": {"category": "patient_data_access", "action": "delete_record", "severity": (3, 4), "statuses": ("success", "failure")},
    "inbound_connection": {"category": "network_activity", "action": "inbound_flow", "severity": (1, 2), "statuses": ("allowed", "blocked")},
    "outbound_connection": {"category": "network_activity", "action": "outbound_flow", "severity": (1, 2), "statuses": ("allowed", "blocked")},
    "dns_query": {"category": "network_activity", "action": "dns_lookup", "severity": (1, 1), "statuses": ("resolved", "blocked")},
    "large_data_transfer": {"category": "network_activity", "action": "data_transfer", "severity": (2, 4), "statuses": ("allowed", "blocked")},
    "suspicious_ip_contact": {"category": "network_activity", "action": "threat_contact", "severity": (4, 5), "statuses": ("blocked", "alert")},
    "service_start": {"category": "system_event", "action": "service_state", "severity": (1, 2), "statuses": ("ok",)},
    "service_stop": {"category": "system_event", "action": "service_state", "severity": (1, 3), "statuses": ("ok", "unexpected")},
    "file_created": {"category": "system_event", "action": "filesystem", "severity": (1, 2), "statuses": ("ok",)},
    "file_deleted": {"category": "system_event", "action": "filesystem", "severity": (1, 3), "statuses": ("ok", "warning")},
    "privilege_escalation_attempt": {"category": "system_event", "action": "privilege_change", "severity": (4, 5), "statuses": ("blocked", "detected")},
    "antivirus_alert": {"category": "system_event", "action": "malware_scan", "severity": (3, 5), "statuses": ("alert", "quarantined")},
}

@dataclass
class SyntheticContext:
    rng: random.Random

    def __post_init__(self) -> None:
        self.users = self._build_users()
        self.patients = [f"PAT-{i:05d}" for i in range(1, 801)]
        self.devices = [f"DEV-{i:04d}" for i in range(1, 401)]

    def _build_users(self) -> List[Dict[str, str]]:
        users: List[Dict[str, str]] = []
        for role, departments in USER_ROLE_DEPARTMENTS.items():
            role_prefix = "".join(token[0] for token in role.split("_")).upper()
            for dept in departments:
                dept_prefix = dept[:3].upper()
                for idx in range(1, 6):
                    user_id = f"{role_prefix}-{dept_prefix}-{idx:02d}"
                    users.append({
                        "user_id": user_id,
                        "user_role": role,
                        "department": dept,
                    })
        return users

    def random_user(self) -> Dict[str, str]:
        return self.rng.choice(self.users)

    def random_patient(self) -> str:
        return self.rng.choice(self.patients)

    def random_device(self) -> str:
        return self.rng.choice(self.devices)


def random_ip(rng: random.Random, internal: bool = True) -> str:
    if internal:
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"{rng.randint(20, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def random_timestamp(rng: random.Random, days: int = 14) -> datetime:
    now = datetime.now(timezone.utc)
    delta_seconds = rng.uniform(0, days * 86400)
    return now - timedelta(seconds=delta_seconds)


def build_metadata(rng: random.Random, note: str, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    metadata = {
        "application": rng.choice(APPLICATIONS),
        "facility": rng.choice(FACILITIES),
        "notes": note,
    }
    if extra:
        metadata.update(extra)
    return metadata


class LogGenerator:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.context = SyntheticContext(rng)

    def generate_events(self, total_events: int, anomaly_ratio: float) -> List[Dict[str, Any]]:
        anomaly_types = [
            "mass_patient_file_access",
            "repeated_login_failure",
            "large_data_export",
            "off_hours_access",
            "suspicious_ip_contact",
            "privilege_escalation",
            "unusual_file_deletion",
            "role_inconsistent_activity",
        ]
        anomaly_count = min(total_events, max(len(anomaly_types), int(total_events * anomaly_ratio)))
        normal_count = total_events - anomaly_count
        events: List[Dict[str, Any]] = []

        for _ in range(normal_count):
            event_type = self.rng.choice(list(EVENT_DEFINITIONS.keys()))
            events.append(self._build_event(event_type, is_anomaly=False))

        for idx in range(anomaly_count):
            anomaly_label = anomaly_types[idx % len(anomaly_types)]
            events.append(self._build_anomaly(anomaly_label))

        events.sort(key=lambda evt: evt["timestamp"])
        for evt in events:
            evt["event_id"] = uuid.uuid4().hex
            evt["timestamp"] = evt["timestamp"].isoformat()
        return events

    def _base_event(self, event_type: str, *, severity_boost: int = 0, note: str = "routine activity") -> Dict[str, Any]:
        definition = EVENT_DEFINITIONS[event_type]
        user = self.context.random_user()
        timestamp = random_timestamp(self.rng)
        category = definition["category"]
        severity_range = definition["severity"]
        severity = min(5, max(1, self.rng.randint(severity_range[0], severity_range[1]) + severity_boost))
        patient_id = self.context.random_patient() if category == "patient_data_access" else None
        metadata = build_metadata(self.rng, note)

        return {
            "event_id": "",  # filled later
            "timestamp": timestamp,
            "event_type": event_type,
            "category": category,
            "severity": severity,
            "user_id": user["user_id"],
            "user_role": user["user_role"],
            "patient_id": patient_id,
            "source_ip": random_ip(self.rng, internal=True),
            "destination_ip": random_ip(self.rng, internal=False),
            "device_id": self.context.random_device(),
            "department": user["department"],
            "action": definition["action"],
            "status": self.rng.choice(definition["statuses"]),
            "bytes_transferred": int(self.rng.triangular(0, 2_000_000, 50_000)),
            "is_anomaly": False,
            "anomaly_type": None,
            "metadata": metadata,
        }

    def _build_event(self, event_type: str, *, is_anomaly: bool) -> Dict[str, Any]:
        note = "anomalous" if is_anomaly else "routine"
        event = self._base_event(event_type, note=note)
        if is_anomaly:
            event["is_anomaly"] = True
            event["severity"] = max(event["severity"], 4)
            event["anomaly_type"] = "generic"
        return event

    def _build_anomaly(self, anomaly_label: str) -> Dict[str, Any]:
        builder = getattr(self, f"_anomaly_{anomaly_label}", None)
        if not builder:
            return self._build_event(self.rng.choice(list(EVENT_DEFINITIONS.keys())), is_anomaly=True)
        return builder()

    def _anomaly_mass_patient_file_access(self) -> Dict[str, Any]:
        event = self._base_event("read_patient_file", severity_boost=2, note="Massive patient file access detected")
        event.update({
            "is_anomaly": True,
            "anomaly_type": "mass_patient_file_access",
            "metadata": build_metadata(self.rng, "Massive patient file access detected", {
                "records_accessed_last_hour": self.rng.randint(80, 200),
            }),
            "bytes_transferred": self.rng.randint(5_000_000, 15_000_000),
        })
        return event

    def _anomaly_repeated_login_failure(self) -> Dict[str, Any]:
        event = self._base_event("login_failure", severity_boost=1, note="Multiple consecutive login failures")
        event.update({
            "is_anomaly": True,
            "anomaly_type": "repeated_login_failure",
            "metadata": build_metadata(self.rng, "Multiple consecutive login failures", {
                "failed_attempts": self.rng.randint(8, 20),
                "lockout_triggered": True,
            }),
            "status": "blocked",
        })
        return event

    def _anomaly_large_data_export(self) -> Dict[str, Any]:
        event = self._base_event("export_patient_file", severity_boost=2, note="Large data export volume")
        event.update({
            "is_anomaly": True,
            "anomaly_type": "large_data_export",
            "bytes_transferred": self.rng.randint(100_000_000, 500_000_000),
            "metadata": build_metadata(self.rng, "Large data export volume", {
                "export_format": self.rng.choice(["csv", "pdf", "dicom"]),
                "record_count": self.rng.randint(1000, 10000),
            }),
        })
        return event

    def _anomaly_off_hours_access(self) -> Dict[str, Any]:
        event = self._base_event("read_patient_file", severity_boost=1, note="Access during restricted hours")
        base_ts = event["timestamp"]
        off_hour_timestamp = base_ts.replace(
            hour=self.rng.choice([1, 2, 3, 4]),
            minute=self.rng.randint(0, 59),
            second=self.rng.randint(0, 59),
            microsecond=self.rng.randint(0, 999999),
        )
        event["timestamp"] = off_hour_timestamp
        event.update({
            "is_anomaly": True,
            "anomaly_type": "off_hours_access",
            "metadata": build_metadata(self.rng, "Access during restricted hours", {
                "local_hour": off_hour_timestamp.hour,
                "usual_shift": "day",
            }),
        })
        return event

    def _anomaly_suspicious_ip_contact(self) -> Dict[str, Any]:
        event = self._base_event("suspicious_ip_contact", severity_boost=1, note="Contact with flagged IP")
        event.update({
            "is_anomaly": True,
            "anomaly_type": "suspicious_ip_contact",
            "destination_ip": random_ip(self.rng, internal=False),
            "metadata": build_metadata(self.rng, "Contact with flagged IP", {
                "threat_list_id": f"IOC-{self.rng.randint(1000,9999)}",
                "reputation_score": self.rng.randint(80, 100),
            }),
            "status": "alert",
        })
        return event

    def _anomaly_privilege_escalation(self) -> Dict[str, Any]:
        event = self._base_event("privilege_escalation_attempt", severity_boost=2, note="Privilege escalation attempt")
        event.update({
            "is_anomaly": True,
            "anomaly_type": "privilege_escalation",
            "metadata": build_metadata(self.rng, "Privilege escalation attempt", {
                "target_role": "it_admin",
                "method": self.rng.choice(["sudo_override", "token_injection"]),
            }),
            "status": "blocked",
        })
        return event

    def _anomaly_unusual_file_deletion(self) -> Dict[str, Any]:
        event = self._base_event("file_deleted", severity_boost=2, note="Unusual volume of deletions")
        event.update({
            "is_anomaly": True,
            "anomaly_type": "unusual_file_deletion",
            "metadata": build_metadata(self.rng, "Unusual volume of deletions", {
                "files_removed": self.rng.randint(50, 200),
                "watched_directory": "/secure/share/records",
            }),
            "status": "warning",
        })
        return event

    def _anomaly_role_inconsistent_activity(self) -> Dict[str, Any]:
        event = self._base_event("delete_patient_note", severity_boost=2, note="Role deviates from baseline")
        event.update({
            "is_anomaly": True,
            "anomaly_type": "role_inconsistent_activity",
            "user_role": "receptionist",
            "metadata": build_metadata(self.rng, "Role deviates from baseline", {
                "required_role": "physician",
            }),
        })
        return event


def write_events_to_file(events: List[Dict[str, Any]], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = output_dir / f"cyber_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with filename.open("w", encoding="utf-8") as fp:
        for event in events:
            json.dump(event, fp, ensure_ascii=True)
            fp.write("\n")
    return filename


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate synthetic cyber logs for CyberHealthGuard")
    parser.add_argument("--events", type=int, default=12000, help="Number of events to generate (>= 10000)")
    parser.add_argument("--anomaly-ratio", type=float, default=0.1, help="Fraction of events to tag as anomalies")
    parser.add_argument("--seed", type=int, default=None, help="Optional RNG seed for reproducibility")
    parser.add_argument("--output", type=Path, default=Path("data/logs"), help="Output directory for JSON logs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.events < 10000:
        raise ValueError("--events must be at least 10000 to satisfy dataset size requirements")
    if not 0 < args.anomaly_ratio < 1:
        raise ValueError("--anomaly-ratio must be between 0 and 1")

    rng = random.Random(args.seed)
    generator = LogGenerator(rng)
    events = generator.generate_events(args.events, args.anomaly_ratio)
    output_file = write_events_to_file(events, args.output)

    anomaly_total = sum(1 for event in events if event["is_anomaly"])
    print(f"Generated {len(events)} events ({anomaly_total} anomalies) -> {output_file}")


if __name__ == "__main__":
    main()
