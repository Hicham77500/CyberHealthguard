"""CHG-030 — Append-only Audit Trail with SHA-256 chained integrity.

Each audit entry is a JSON line written to ``artifacts/audit_trail.jsonl``.
The SHA-256 of each entry embeds the hash of the previous entry, forming
a tamper-evident chain (similar to a blockchain without the consensus layer).

Entry structure
---------------
{
  "seq":        42,
  "timestamp":  "2026-05-29T14:00:00+00:00",
  "event_type": "alert_generated | pipeline_run | user_action | incident_report",
  "actor":      "pipeline | <username>",
  "action":     "Free-text description of what happened",
  "object":     "File path, alert_id, run_id, or resource identifier",
  "metadata":   { ...any extra context... },
  "prev_hash":  "<sha256 of previous entry or '0'*64 for genesis>",
  "entry_hash": "<sha256 of this entry excluding entry_hash field>"
}

PGSSI-S mapping
---------------
The ``pgssi_control`` field maps each event type to the relevant
PGSSI-S v2 control reference (ANSSI healthcare IS security policy).

Usage
-----
    from src.compliance.audit_trail import AuditTrail
    trail = AuditTrail()
    trail.log(event_type="pipeline_run", actor="pipeline",
              action="Full pipeline executed", object="artifacts/")
    trail.verify()

CLI:
    python -m src.compliance.audit_trail log --event pipeline_run --actor pipeline --action "Run OK"
    python -m src.compliance.audit_trail verify
    python -m src.compliance.audit_trail export --output artifacts/audit_report.html
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TRAIL = Path("artifacts/audit_trail.jsonl")

_GENESIS_HASH = "0" * 64  # predecessor hash for the first entry

_EVENT_TYPES = frozenset({
    "alert_generated",
    "pipeline_run",
    "user_action",
    "incident_report",
    "validation_run",
    "model_training",
    "config_change",
    "access_attempt",
})

_PGSSI_S_MAP: dict[str, str] = {
    "alert_generated":  "PGSSI-S 12.4 — Surveillance et détection",
    "pipeline_run":     "PGSSI-S 12.1 — Journalisation des opérations",
    "user_action":      "PGSSI-S 9.1 — Contrôle d'accès et traçabilité",
    "incident_report":  "PGSSI-S 16.1 — Gestion des incidents de sécurité",
    "validation_run":   "PGSSI-S 12.2 — Contrôle de l'intégrité des données",
    "model_training":   "PGSSI-S 12.3 — Traçabilité des traitements automatisés",
    "config_change":    "PGSSI-S 12.5 — Gestion des changements",
    "access_attempt":   "PGSSI-S 9.3 — Authentification et traçabilité des accès",
}


# ---------------------------------------------------------------------------
# Entry helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_entry(entry: dict) -> str:
    """SHA-256 of the entry dict *without* the ``entry_hash`` key."""
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# AuditTrail
# ---------------------------------------------------------------------------

class AuditTrail:
    """Append-only audit log with SHA-256 chained integrity verification.

    Parameters
    ----------
    path:
        Path to the JSONL trail file. Created on first write.
    """

    def __init__(self, path: Path = _DEFAULT_TRAIL) -> None:
        self._path = Path(path).resolve()

    # ── Internal helpers ───────────────────────────────────────────────────

    def _read_entries(self) -> list[dict]:
        if not self._path.exists():
            return []
        entries = []
        with self._path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def _last_hash(self) -> tuple[int, str]:
        """Return (last_seq, last_entry_hash) or (0, GENESIS_HASH) if empty."""
        entries = self._read_entries()
        if not entries:
            return 0, _GENESIS_HASH
        last = entries[-1]
        return last.get("seq", len(entries)), last.get("entry_hash", _GENESIS_HASH)

    # ── Public API ─────────────────────────────────────────────────────────

    def log(
        self,
        event_type: str,
        actor: str,
        action: str,
        object_ref: str = "",
        metadata: Optional[dict] = None,
    ) -> dict:
        """Append a new signed entry to the audit trail.

        Parameters
        ----------
        event_type:
            Category of the event (must be in _EVENT_TYPES, or passed as-is).
        actor:
            Who performed the action (e.g. "pipeline", "user:alice").
        action:
            Human-readable description of what happened.
        object_ref:
            Resource identifier (file path, alert_id, run_id…).
        metadata:
            Any additional structured context.

        Returns
        -------
        dict
            The signed entry that was appended.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        last_seq, prev_hash = self._last_hash()

        entry: dict = {
            "seq":          last_seq + 1,
            "timestamp":    _now_iso(),
            "event_type":   event_type,
            "pgssi_control": _PGSSI_S_MAP.get(event_type, "PGSSI-S 12.1 — Journalisation"),
            "actor":        actor,
            "action":       action,
            "object":       object_ref,
            "metadata":     metadata or {},
            "prev_hash":    prev_hash,
            "entry_hash":   "",     # computed next
        }
        entry["entry_hash"] = _hash_entry(entry)

        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return entry

    def verify(self) -> tuple[bool, list[str]]:
        """Verify the integrity of the entire chain.

        Returns
        -------
        tuple[bool, list[str]]
            (all_ok, list_of_error_messages)
        """
        entries = self._read_entries()
        if not entries:
            return True, []

        errors: list[str] = []
        expected_prev = _GENESIS_HASH

        for entry in entries:
            seq = entry.get("seq", "?")

            # Check prev_hash linkage
            actual_prev = entry.get("prev_hash", "")
            if actual_prev != expected_prev:
                errors.append(
                    f"seq={seq}: prev_hash mismatch "
                    f"(expected {expected_prev[:12]}… got {actual_prev[:12]}…)"
                )

            # Recompute entry_hash
            stored_hash    = entry.get("entry_hash", "")
            recomputed     = _hash_entry(entry)
            if stored_hash != recomputed:
                errors.append(
                    f"seq={seq}: entry_hash tampered "
                    f"(stored {stored_hash[:12]}… recomputed {recomputed[:12]}…)"
                )

            expected_prev = stored_hash

        return len(errors) == 0, errors

    def list_entries(
        self,
        event_type: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """Return recent entries, optionally filtered by event_type."""
        entries = self._read_entries()
        if event_type:
            entries = [e for e in entries if e.get("event_type") == event_type]
        return entries[-limit:]

    def stats(self) -> dict:
        """Return summary statistics of the trail."""
        entries = self._read_entries()
        from collections import Counter
        counts = Counter(e.get("event_type", "unknown") for e in entries)
        ok, errors = self.verify()
        return {
            "total_entries":   len(entries),
            "chain_intact":    ok,
            "integrity_errors": len(errors),
            "by_event_type":   dict(counts),
            "trail_path":      str(self._path),
        }


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------

_EXPORT_CSS = """
body { font-family: Arial, sans-serif; margin: 40px; color: #1a1a2e; font-size: 13px; }
h1   { color: #1a1a2e; border-bottom: 2px solid #2980b9; padding-bottom: 8px; }
h2   { color: #2c3e50; margin-top: 28px; }
.ok  { color: #27ae60; font-weight: bold; }
.err { color: #c0392b; font-weight: bold; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
th    { background: #2c3e50; color: white; padding: 7px 9px; text-align: left; }
td    { padding: 7px 9px; border-bottom: 1px solid #eee; vertical-align: top; }
tr:nth-child(even) td { background: #f9f9f9; }
.hash { font-family: monospace; font-size: 10px; color: #888; }
.footer { margin-top: 40px; font-size: 11px; color: #888; border-top: 1px solid #ddd; padding-top: 10px; }
"""


def export_html(trail: AuditTrail, limit: int = 200) -> str:
    """Render the audit trail as a self-contained HTML page."""
    entries = trail.list_entries(limit=limit)
    ok, errors = trail.verify()
    s = trail.stats()

    integrity_html = (
        '<span class="ok">✅ Chaîne intègre</span>' if ok
        else f'<span class="err">❌ {len(errors)} erreur(s) d\'intégrité</span>'
    )

    rows = ""
    for e in reversed(entries):
        meta = json.dumps(e.get("metadata", {}), ensure_ascii=False)
        if len(meta) > 80:
            meta = meta[:77] + "…"
        rows += (
            f"<tr>"
            f"<td>{e.get('seq')}</td>"
            f"<td>{e.get('timestamp','')[:19].replace('T',' ')}</td>"
            f"<td>{e.get('event_type','')}</td>"
            f"<td>{e.get('actor','')}</td>"
            f"<td>{e.get('action','')}</td>"
            f"<td>{e.get('object','')}</td>"
            f"<td title='{e.get('pgssi_control','')}'>{e.get('pgssi_control','')[:40]}…</td>"
            f"<td class='hash'>{e.get('entry_hash','')[:16]}…</td>"
            f"</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Piste d'Audit — CyberHealthGuard</title>
<style>{_EXPORT_CSS}</style>
</head>
<body>
<h1>&#x1F512; Piste d'Audit de Sécurité</h1>
<p><strong>Fichier :</strong> {s['trail_path']}</p>
<p><strong>Total entrées :</strong> {s['total_entries']} &nbsp;|&nbsp;
   <strong>Intégrité :</strong> {integrity_html}</p>
<p><strong>Référentiel :</strong> PGSSI-S v2 (ANSSI) — NIS2 Art.23</p>

<h2>Journal des événements (dernières {limit} entrées)</h2>
<table>
<thead><tr>
<th>#</th><th>Horodatage</th><th>Type</th><th>Acteur</th>
<th>Action</th><th>Objet</th><th>Contrôle PGSSI-S</th><th>Hash</th>
</tr></thead>
<tbody>{rows if rows else '<tr><td colspan="8">Aucune entrée</td></tr>'}</tbody>
</table>

<div class="footer">
  Piste d'audit générée par CyberHealthGuard — Toute modification de ce fichier invalide la chaîne SHA-256.
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CyberHealthGuard — Audit Trail (append-only, SHA-256 chained)",
    )
    parser.add_argument("--trail", default=str(_DEFAULT_TRAIL),
                        help="Path to the JSONL audit trail file")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # log
    p_log = sub.add_parser("log", help="Append an entry to the trail")
    p_log.add_argument("--event",  required=True, help="Event type")
    p_log.add_argument("--actor",  required=True, help="Actor (pipeline|username)")
    p_log.add_argument("--action", required=True, help="Description of the action")
    p_log.add_argument("--object", default="",    help="Resource identifier")
    p_log.add_argument("--meta",   default="{}",  help="JSON metadata string")

    # verify
    sub.add_parser("verify", help="Verify the SHA-256 chain integrity")

    # export
    p_exp = sub.add_parser("export", help="Export the trail to HTML")
    p_exp.add_argument("--output", default="artifacts/audit_report.html")
    p_exp.add_argument("--limit",  type=int, default=200)

    # stats
    sub.add_parser("stats", help="Print trail statistics")

    args = parser.parse_args()
    trail = AuditTrail(Path(args.trail))

    if args.cmd == "log":
        try:
            meta = json.loads(args.meta)
        except json.JSONDecodeError:
            meta = {}
        entry = trail.log(
            event_type=args.event,
            actor=args.actor,
            action=args.action,
            object_ref=getattr(args, "object", ""),
            metadata=meta,
        )
        print(f"[audit_trail] Entry #{entry['seq']} logged — hash {entry['entry_hash'][:16]}…")
        return 0

    if args.cmd == "verify":
        ok, errors = trail.verify()
        if ok:
            print("[audit_trail] ✅ Chain intact — all hashes verified.")
        else:
            for err in errors:
                print(f"[audit_trail] ❌ {err}")
        return 0 if ok else 1

    if args.cmd == "export":
        out = Path(args.output).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(export_html(trail, limit=args.limit), encoding="utf-8")
        print(f"[audit_trail] HTML export → {out}")
        return 0

    if args.cmd == "stats":
        s = trail.stats()
        print(json.dumps(s, indent=2, ensure_ascii=False))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
